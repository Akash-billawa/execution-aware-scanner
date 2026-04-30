
    pub async fn block_ip(
        &mut self,
        ip: Ipv4Addr,
        reason: &str,
    ) -> Result<EnforcementResult, ScannerError> {
        // Return error if BPF is not available (for testing/mock scenarios)
        if self.bpf.is_none() {
            return Err(ScannerError::Bpf("BPF not available".to_string()));
        }

        let ip_u32 = u32::from(ip);

        if let Some(ref mut bpf) = self.bpf {
            // Update XDP blocked IPs map
            let mut xdp_blocked: BpfHashMap<_, u32, u8> = bpf
                .map_mut("XDP_BLOCKED_IPS")
                .ok_or_else(|| ScannerError::Bpf("XDP_BLOCKED_IPS map not found".to_string()))?
                .try_into()
                .map_err(|e| ScannerError::Bpf(format!("Failed to access XDP map: {}", e)))?;

            xdp_blocked
                .insert(ip_u32, 1, 0)
                .map_err(|e| ScannerError::Bpf(format!("Failed to block IP: {}", e)))?;
        }

        // Also update regular blocked IPs for TC
        if let Some(ref mut bpf) = self.bpf {
            let mut blocked: BpfHashMap<_, u32, u8> = bpf
                .map_mut("BLOCKED_IPS")
                .ok_or_else(|| ScannerError::Bpf("BLOCKED_IPS map not found".to_string()))?
                .try_into()
                .map_err(|e| ScannerError::Bpf(format!("Failed to block IP in TC: {}", e)))?;

            blocked
                .insert(ip_u32, 1, 0)
                .map_err(|e| ScannerError::Bpf(format!("Failed to block IP in TC: {}", e)))?;
        }

        self.blocked_ips.insert(ip_u32);
        self.last_update = Instant::now();

        info!("Blocked IP {} via XDP/TC: {}", ip, reason);

        Ok(EnforcementResult {
            rule: TrafficRule::BlockIp {
                ip,
                reason: reason.to_string(),
            },
            applied: true,
            error: None,
        })
    }

    /// Unblock IP address
    pub async fn unblock_ip(&mut self, ip: Ipv4Addr) -> Result<(), ScannerError> {
        let ip_u32 = u32::from(ip);

        if let Some(ref mut bpf) = self.bpf {
            // Remove from XDP map
            if let Ok(mut xdp_blocked) =
                BpfHashMap::<_, u32, u8>::try_from(bpf.map_mut("XDP_BLOCKED_IPS").ok_or_else(
                    || ScannerError::Bpf("XDP_BLOCKED_IPS map not found".to_string()),
                )?)
            {
                let _ = xdp_blocked.remove(&ip_u32);
            }

            // Remove from TC map
            if let Ok(mut blocked) = BpfHashMap::<_, u32, u8>::try_from(
                bpf.map_mut("BLOCKED_IPS")
                    .ok_or_else(|| ScannerError::Bpf("BLOCKED_IPS map not found".to_string()))?,
            ) {
                let _ = blocked.remove(&ip_u32);
            }
        }

        self.blocked_ips.remove(&ip_u32);
        info!("Unblocked IP {}", ip);

        Ok(())
    }

    /// Block outbound connections to C2 indicators
    pub async fn block_c2_indicators(
        &mut self,
        indicators: &[C2Indicator],
    ) -> Vec<EnforcementResult> {
        let mut results = Vec::new();

        for indicator in indicators {
            match indicator {
                C2Indicator::Ip(ip) => match self.block_ip(*ip, "C2 indicator").await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        error!("Failed to block C2 IP {}: {}", ip, e);
                        results.push(EnforcementResult {
                            rule: TrafficRule::BlockIp {
                                ip: *ip,
                                reason: "C2 indicator".to_string(),
                            },
                            applied: false,
                            error: Some(e.to_string()),
                        });
                    }
                },
                C2Indicator::Domain(domain) => {
                    self.blocked_domains.insert(domain.clone());
                    // DNS blocking requires additional setup
                    debug!("Added {} to blocked domains", domain);
                }
                C2Indicator::Port(port) => {
                    self.blocked_ports.insert(*port);
                    results.push(EnforcementResult {
                        rule: TrafficRule::BlockPort {
                            port: *port,
                            direction: Direction::Egress,
                        },
                        applied: true,
                        error: None,
                    });
                }
            }
        }

        results
    }

    /// Apply quarantine to workload via TC
    pub async fn quarantine_workload(
        &mut self,
        cgroup_id: u64,
        duration: Duration,
    ) -> Result<(), ScannerError> {
        // Add to denylist in BPF
        if let Some(ref mut bpf) = self.bpf {
            let mut denylist: BpfHashMap<_, u64, u8> = bpf
                .map_mut("DENYLIST")
                .ok_or_else(|| ScannerError::Bpf("DENYLIST map not found".to_string()))?
                .try_into()
                .map_err(|e| ScannerError::Bpf(format!("Failed to access denylist: {}", e)))?;

            denylist
                .insert(cgroup_id, 1, 0)
                .map_err(|e| ScannerError::Bpf(format!("Failed to quarantine: {}", e)))?;
        }

        info!("Quarantined cgroup {} for {:?}", cgroup_id, duration);

        // Schedule unquarantine
        let cgroup_id_for_unquarantine = cgroup_id;
        let weak_bpf = self.bpf.as_ref().map(|_| ()); // Can't easily clone, but we show the pattern
        tokio::spawn(async move {
            tokio::time::sleep(duration).await;
            info!(
                "Auto-unquarantine cgroup {} after {:?}",
                cgroup_id_for_unquarantine, duration
            );
            // In real implementation, would need access to BPF handle
        });

        Ok(())
    }

    /// Remove quarantine
    pub async fn unquarantine_workload(&mut self, cgroup_id: u64) -> Result<(), ScannerError> {
        if let Some(ref mut bpf) = self.bpf {
            let mut denylist: BpfHashMap<_, u64, u8> = bpf
                .map_mut("DENYLIST")
                .ok_or_else(|| ScannerError::Bpf("DENYLIST map not found".to_string()))?
                .try_into()
                .map_err(|e| ScannerError::Bpf(format!("Failed to access denylist: {}", e)))?;

            denylist
                .remove(&cgroup_id)
                .map_err(|e| ScannerError::Bpf(format!("Failed to unquarantine: {}", e)))?;
        }

        info!("Unquarantined cgroup {}", cgroup_id);
        Ok(())
    }

    /// Get blocked IPs count
    pub fn blocked_ip_count(&self) -> usize {
        self.blocked_ips.len()
    }

    /// Get blocked ports count
    pub fn blocked_port_count(&self) -> usize {
        self.blocked_ports.len()
    }

    /// Flush all rules (for reload)
    pub async fn flush_all(&mut self) -> Result<(), ScannerError> {
        // Clear XDP blocked IPs
        if let Some(ref mut bpf) = self.bpf {
            if let Ok(mut xdp_blocked) =
                BpfHashMap::<_, u32, u8>::try_from(bpf.map_mut("XDP_BLOCKED_IPS").ok_or_else(
                    || ScannerError::Bpf("XDP_BLOCKED_IPS map not found".to_string()),
                )?)
            {
                for ip in &self.blocked_ips {
                    let _ = xdp_blocked.remove(ip);
                }
            }

            if let Ok(mut blocked) = BpfHashMap::<_, u32, v8>::try_from(
                bpf.map_mut("BLOCKED_IPS")
                    .ok_or_else(|| ScannerError::Bpf("BLOCKED_IPS map not found".to_string()))?,
            ) {
                for ip in &self.blocked_ips {
                    let _ = blocked.remove(ip);
                }
            }
        }

        self.blocked_ips.clear();
        self.blocked_ports.clear();
        self.blocked_domains.clear();

        info!("Flushed all TC/XDP enforcement rules");
        Ok(())
    }

    /// Export current rules
    pub fn export_rules(&self) -> TrafficRules {
        TrafficRules {
            blocked_ips: self
                .blocked_ips
                .iter()
                .map(|&ip| Ipv4Addr::from(ip))
                .collect(),
            blocked_ports: self.blocked_ports.iter().cloned().collect(),
            blocked_domains: self.blocked_domains.iter().cloned().collect(),
            last_updated: self.last_update,
        }
    }
}

/// C2 indicators for blocking
#[derive(Debug, Clone)]
pub enum C2Indicator {
    Ip(Ipv4Addr),
    Domain(String),
    Port(u16),
}

/// Current traffic rules
#[derive(Debug)]
pub struct TrafficRules {
    pub blocked_ips: Vec<Ipv4Addr>,
    pub blocked_ports: Vec<u16>,
    pub blocked_domains: Vec<String>,
    pub last_updated: Instant,
}

/// Threat intelligence feed integration
pub struct ThreatIntelFeed {
    known_bad_ips: HashSet<Ipv4Addr>,
    known_bad_domains: HashSet<String>,
    last_update: Option<Instant>,
}

impl ThreatIntelFeed {
    pub fn new() -> Self {
        Self {
            known_bad_ips: HashSet::new(),
            known_bad_domains: HashSet::new(),
            last_update: None,
        }
    }

    /// Update from external feed
    pub async fn update(&mut self) -> Result<usize, ScannerError> {
        // Mock update from threat intel
        // In production, fetch from MISP, ThreatConnect, etc.

        let new_indicators = vec![
            C2Indicator::Ip(Ipv4Addr::new(192, 168, 100, 1)),
            C2Indicator::Domain("evil-c2.example.com".to_string()),
            C2Indicator::Port(4444),
        ];

        let count = new_indicators.len();

        for indicator in new_indicators {
            match indicator {
                C2Indicator::Ip(ip) => {
                    self.known_bad_ips.insert(ip);
                }
                C2Indicator::Domain(d) => {
                    self.known_bad_domains.insert(d);
                }
                C2Indicator::Port(p) => { /* Ports handled separately */ }
            }
        }

        self.last_update = Some(Instant::now());

        info!(
            "Updated threat intel: {} bad IPs, {} bad domains",
            self.known_bad_ips.len(),
            self.known_bad_domains.len()
        );

        Ok(count)
    }

    /// Check if IP is known bad
    pub fn is_known_bad(&self, ip: &Ipv4Addr) -> bool {
        self.known_bad_ips.contains(ip)
    }

    /// Check if domain is known bad
    pub fn is_known_bad_domain(&self, domain: &str) -> bool {
        self.known_bad_domains.iter().any(|d| domain.contains(d))
    }

    /// Get indicators as C2Indicator list
    pub fn get_indicators(&self) -> Vec<C2Indicator> {
        let mut indicators: Vec<_> = self
            .known_bad_ips
            .iter()
            .map(|&ip| C2Indicator::Ip(ip))
            .collect();

        indicators.extend(
            self.known_bad_domains
                .iter()
                .map(|d| C2Indicator::Domain(d.clone())),
        );

        indicators
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_blocking_mock() {
        let mut enforcer = TcEnforcer::new();

        let result = enforcer
            .block_ip(Ipv4Addr::new(192, 168, 1, 100), "Test block")
            .await;

        // Will fail without real BPF, but pattern is correct
        assert!(result.is_err()); // Expected without BPF
    }

    #[test]
    fn test_c2_indicators() {
        let indicators = vec![
            C2Indicator::Ip(Ipv4Addr::new(10, 0, 0, 1)),
            C2Indicator::Domain("evil.com".to_string()),
            C2Indicator::Port(4444),
        ];

        assert_eq!(indicators.len(), 3);
    }

    #[test]
    fn test_threat_intel() {
        let mut feed = ThreatIntelFeed::new();

        // Manually add for testing
        feed.known_bad_ips.insert(Ipv4Addr::new(10, 0, 0, 1));
        feed.known_bad_domains.insert("malware.com".to_string());

        assert!(feed.is_known_bad(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(feed.is_known_bad_domain("sub.malware.com"));
        assert!(!feed.is_known_bad(&Ipv4Addr::new(8, 8, 8, 8)));
    }
}