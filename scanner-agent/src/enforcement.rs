use crate::config::RemediatorConfig;
use crate::error::ScannerError;
use scanner_common::{Finding, Priority, RuntimeIdentity};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Enforcement actions that can be taken
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnforcementAction {
    /// No action - just log
    Notify = 0,
    /// Generate seccomp profile
    GenerateSeccomp = 1,
    /// Apply seccomp profile
    ApplySeccomp = 2,
    /// Block egress traffic
    BlockEgress = 3,
    /// Block ingress traffic
    BlockIngress = 4,
    /// Quarantine workload
    Quarantine = 5,
    /// Terminate workload
    Terminate = 6,
}

impl EnforcementAction {
    pub fn from_priority(priority: &Priority) -> Vec<Self> {
        match priority {
            Priority::Critical => vec![
                EnforcementAction::GenerateSeccomp,
                EnforcementAction::ApplySeccomp,
                EnforcementAction::BlockEgress,
            ],
            Priority::High => vec![
                EnforcementAction::GenerateSeccomp,
                EnforcementAction::Notify,
            ],
            Priority::Medium => vec![EnforcementAction::Notify],
            _ => vec![EnforcementAction::Notify],
        }
    }

    pub fn is_disruptive(&self) -> bool {
        matches!(
            self,
            EnforcementAction::Quarantine | EnforcementAction::Terminate
        )
    }
}

/// Enforcement rule for a workload
#[derive(Debug, Clone)]
pub struct EnforcementRule {
    pub workload_id: String,
    pub namespace: String,
    pub actions: Vec<EnforcementAction>,
    pub conditions: Vec<EnforcementCondition>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Conditions for enforcement
#[derive(Debug, Clone)]
pub enum EnforcementCondition {
    MinCvss(f32),
    MinEpss(f32),
    IsKev,
    RuntimeReachable,
    SuspiciousNetworkActivity,
    BlockedIpContacted(u32),
}

/// Enforcement status
#[derive(Debug, Clone)]
pub struct EnforcementStatus {
    pub rule_id: String,
    pub action: EnforcementAction,
    pub status: EnforcementStatusType,
    pub applied_at: Option<chrono::DateTime<chrono::Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EnforcementStatusType {
    Pending,
    Applying,
    Applied,
    Failed,
    RolledBack,
}

/// Enforcement controller
#[derive(Clone)]
pub struct EnforcementController {
    config: RemediatorConfig,
    rules: Arc<RwLock<HashMap<String, EnforcementRule>>>,
    statuses: Arc<RwLock<HashMap<String, Vec<EnforcementStatus>>>>,
    syscall_baselines: Arc<RwLock<BTreeMap<String, BTreeSet<String>>>>,
    blocked_ips: Arc<RwLock<BTreeSet<u32>>>,
}

impl EnforcementController {
    pub fn new(config: RemediatorConfig) -> Self {
        Self {
            config,
            rules: Arc::new(RwLock::new(HashMap::new())),
            statuses: Arc::new(RwLock::new(HashMap::new())),
            syscall_baselines: Arc::new(RwLock::new(BTreeMap::new())),
            blocked_ips: Arc::new(RwLock::new(BTreeSet::new())),
        }
    }

    /// Record observed syscalls for a workload
    pub async fn record_syscalls(&self, workload_id: &str, syscalls: BTreeSet<String>) {
        let mut baselines = self.syscall_baselines.write().await;
        let entry = baselines.entry(workload_id.to_string()).or_default();
        entry.extend(syscalls);
    }

    /// Get syscall baseline for workload
    pub async fn get_syscall_baseline(&self, workload_id: &str) -> Option<BTreeSet<String>> {
        let baselines = self.syscall_baselines.read().await;
        baselines.get(workload_id).cloned()
    }

    /// Generate seccomp profile from observed syscalls
    pub async fn generate_seccomp_profile(
        &self,
        workload_id: &str,
    ) -> Result<serde_json::Value, ScannerError> {
        let baselines = self.syscall_baselines.read().await;
        let syscalls = baselines
            .get(workload_id)
            .cloned()
            .unwrap_or_default();
        drop(baselines);

        if syscalls.is_empty() {
            warn!("No syscall baseline for {}, using default", workload_id);
        }

        // Essential syscalls that must always be allowed
        let mut allowed_syscalls: BTreeSet<String> = [
            "exit", "exit_group", "rt_sigreturn", "sigreturn",
            "brk", "mmap", "munmap", "mprotect",
            "arch_prctl", "set_tid_address",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        // Merge with observed syscalls
        allowed_syscalls.extend(syscalls);

        // Group syscalls by category
        let mut categories: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for syscall in &allowed_syscalls {
            let category = categorize_syscall(syscall);
            categories
                .entry(category)
                .or_default()
                .push(syscall.clone());
        }

        let profile = serde_json::json!({
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
            "syscalls": [{
                "names": allowed_syscalls.into_iter().collect::<Vec<_>>(),
                "action": "SCMP_ACT_ALLOW"
            }],
            "categories": categories,
            "metadata": {
                "generated_by": "execution-aware-scanner",
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "workload_id": workload_id,
                "syscall_count": allowed_syscalls.len(),
            }
        });

        info!(
            "Generated seccomp profile for {} with {} syscalls",
            workload_id,
            allowed_syscalls.len()
        );

        Ok(profile)
    }

    /// Apply seccomp profile to workload
    pub async fn apply_seccomp(
        &self,
        workload_id: &str,
        namespace: &str,
    ) -> Result<EnforcementStatus, ScannerError> {
        let rule_id = format!("seccomp-{}-{}", workload_id, chrono::Utc::now().timestamp());

        let status = EnforcementStatus {
            rule_id: rule_id.clone(),
            action: EnforcementAction::ApplySeccomp,
            status: EnforcementStatusType::Applying,
            applied_at: None,
            error: None,
        };

        // Store status
        let mut statuses = self.statuses.write().await;
        statuses
            .entry(workload_id.to_string())
            .or_default()
            .push(status.clone());
        drop(statuses);

        // Generate profile
        match self.generate_seccomp_profile(workload_id).await {
            Ok(profile) => {
                // Apply via Kubernetes (would need kube client)
                info!(
                    "Would apply seccomp profile to {}/{}",
                    namespace, workload_id
                );

                // Mock success
                let mut updated = status.clone();
                updated.status = EnforcementStatusType::Applied;
                updated.applied_at = Some(chrono::Utc::now());

                Ok(updated)
            }
            Err(e) => {
                let mut updated = status.clone();
                updated.status = EnforcementStatusType::Failed;
                updated.error = Some(e.to_string());
                Ok(updated)
            }
        }
    }

    /// Block IP address
    pub async fn block_ip(&self, ip: u32, reason: &str) -> Result<(), ScannerError> {
        let mut blocked = self.blocked_ips.write().await;
        blocked.insert(ip);

        info!("Blocked IP {}: {}", ip_to_string(ip), reason);

        // Push to eBPF map (would need BPF handle)
        // This is a placeholder for the actual eBPF map update
        Ok(())
    }

    /// Unblock IP address
    pub async fn unblock_ip(&self, ip: u32) -> Result<(), ScannerError> {
        let mut blocked = self.blocked_ips.write().await;
        blocked.remove(&ip);

        info!("Unblocked IP {}", ip_to_string(ip));
        Ok(())
    }

    /// Block egress for workload
    pub async fn block_egress(
        &self,
        workload_id: &str,
        namespace: &str,
        duration: Duration,
    ) -> Result<EnforcementStatus, ScannerError> {
        let rule_id = format!("egress-{}-{}", workload_id, chrono::Utc::now().timestamp());

        let status = EnforcementStatus {
            rule_id: rule_id.clone(),
            action: EnforcementAction::BlockEgress,
            status: EnforcementStatusType::Applying,
            applied_at: None,
            error: None,
        };

        info!(
            "Blocking egress for {}/{} for {:?}",
            namespace, workload_id, duration
        );

        // Apply via TC/XDP (mock)
        let mut updated = status.clone();
        updated.status = EnforcementStatusType::Applied;
        updated.applied_at = Some(chrono::Utc::now());

        Ok(updated)
    }

    /// Quarantine workload
    pub async fn quarantine_workload(
        &self,
        finding: &Finding,
        isolate_network: bool,
        isolate_storage: bool,
    ) -> Result<EnforcementStatus, ScannerError> {
        let rule_id = format!("quarantine-{}-{}", finding.identity.workload, chrono::Utc::now().timestamp());

        let status = EnforcementStatus {
            rule_id: rule_id.clone(),
            action: EnforcementAction::Quarantine,
            status: EnforcementStatusType::Applying,
            applied_at: None,
            error: None,
        };

        info!(
            "Quarantining {}/{}: network={}, storage={}",
            finding.identity.namespace,
            finding.identity.workload,
            isolate_network,
            isolate_storage
        );

        // Mock quarantine
        let mut updated = status.clone();
        updated.status = EnforcementStatusType::Applied;
        updated.applied_at = Some(chrono::Utc::now());

        Ok(updated)
    }

    /// Process a finding and apply appropriate enforcement
    pub async fn process_finding(&self, finding: &Finding) -> Vec<EnforcementStatus> {
        let actions = EnforcementAction::from_priority(&finding.priority);
        let mut results = Vec::new();

        for action in actions {
            // Check if action should be applied based on config
            match action {
                EnforcementAction::ApplySeccomp => {
                    if !self.config.auto_seccomp {
                        continue;
                    }
                }
                EnforcementAction::Quarantine => {
                    if !self.config.auto_quarantine {
                        continue;
                    }
                }
                _ => {}
            }

            let result = match action {
                EnforcementAction::GenerateSeccomp => {
                    match self.generate_seccomp_profile(&finding.identity.workload).await {
                        Ok(_) => EnforcementStatus {
                            rule_id: format!("gen-{}-{}", finding.id, action as u8),
                            action,
                            status: EnforcementStatusType::Applied,
                            applied_at: Some(chrono::Utc::now()),
                            error: None,
                        },
                        Err(e) => EnforcementStatus {
                            rule_id: format!("gen-{}-{}", finding.id, action as u8),
                            action,
                            status: EnforcementStatusType::Failed,
                            applied_at: None,
                            error: Some(e.to_string()),
                        },
                    }
                }
                EnforcementAction::ApplySeccomp => {
                    self.apply_seccomp(
                        &finding.identity.workload,
                        &finding.identity.namespace,
                    )
                    .await
                    .unwrap_or_else(|e| EnforcementStatus {
                        rule_id: format!("app-{}-{}", finding.id, action as u8),
                        action,
                        status: EnforcementStatusType::Failed,
                        applied_at: None,
                        error: Some(e.to_string()),
                    })
                }
                EnforcementAction::BlockEgress => {
                    self.block_egress(
                        &finding.identity.workload,
                        &finding.identity.namespace,
                        Duration::from_secs(3600),
                    )
                    .await
                    .unwrap_or_else(|e| EnforcementStatus {
                        rule_id: format!("blk-{}-{}", finding.id, action as u8),
                        action,
                        status: EnforcementStatusType::Failed,
                        applied_at: None,
                        error: Some(e.to_string()),
                    })
                }
                _ => EnforcementStatus {
                    rule_id: format!("notify-{}-{}", finding.id, action as u8),
                    action,
                    status: EnforcementStatusType::Applied,
                    applied_at: Some(chrono::Utc::now()),
                    error: None,
                },
            };

            results.push(result);
        }

        results
    }

    /// Get enforcement status for workload
    pub async fn get_status(&self, workload_id: &str) -> Vec<EnforcementStatus> {
        let statuses = self.statuses.read().await;
        statuses.get(workload_id).cloned().unwrap_or_default()
    }

    /// Get all active rules
    pub async fn get_active_rules(&self) -> Vec<EnforcementRule> {
        let rules = self.rules.read().await;
        rules.values().cloned().collect()
    }
}

fn categorize_syscall(syscall: &str) -> String {
    let categories: HashMap<&str, &[&str]> = [
        ("memory", &["mmap", "munmap", "mprotect", "brk", "sbrk"]),
        ("file", &["openat", "openat2", "read", "write", "close", "fstat", "lseek", "access"]),
        ("process", &["execve", "execveat", "clone", "fork", "vfork", "exit", "wait4", "getpid"]),
        ("network", &["socket", "connect", "bind", "listen", "accept", "sendto", "recvfrom", "setsockopt"]),
        ("signal", &["rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "kill", "tkill", "tgkill"]),
        ("time", &["clock_gettime", "gettimeofday", "nanosleep", "alarm", "timer_create"]),
    ]
    .iter()
    .cloned()
    .collect();

    for (category, syscalls) in categories {
        if syscalls.contains(&syscall) {
            return category.to_string();
        }
    }

    "other".to_string()
}

fn ip_to_string(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn create_test_config() -> RemediatorConfig {
        RemediatorConfig {
            enabled: true,
            address: "localhost:50051".to_string(),
            timeout_secs: 30,
            max_retries: 3,
            enforce_critical: true,
            enforce_high: false,
            auto_seccomp: true,
            auto_quarantine: false,
        }
    }

    #[tokio::test]
    async fn test_syscall_baseline_recording() {
        let controller = EnforcementController::new(create_test_config());
        
        let syscalls: BTreeSet<String> = [
            "openat", "read", "write", "mmap", "execve"
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        controller.record_syscalls("test-workload", syscalls.clone()).await;
        
        let baseline = controller.get_syscall_baseline("test-workload").await;
        assert_eq!(baseline, Some(syscalls));
    }

    #[tokio::test]
    async fn test_seccomp_generation() {
        let controller = EnforcementController::new(create_test_config());
        
        let syscalls: BTreeSet<String> = [
            "openat", "read", "write", "mmap", "execve"
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        controller.record_syscalls("test-workload", syscalls).await;
        
        let profile = controller.generate_seccomp_profile("test-workload").await.unwrap();
        assert!(profile.get("syscalls").is_some());
    }

    #[test]
    fn test_categorize_syscalls() {
        assert_eq!(categorize_syscall("mmap"), "memory");
        assert_eq!(categorize_syscall("openat"), "file");
        assert_eq!(categorize_syscall("execve"), "process");
        assert_eq!(categorize_syscall("connect"), "network");
        assert_eq!(categorize_syscall("rt_sigaction"), "signal");
        assert_eq!(categorize_syscall("unknown_syscall"), "other");
    }

    #[test]
    fn test_ip_conversion() {
        assert_eq!(ip_to_string(0x7F000001), "127.0.0.1");
        assert_eq!(ip_to_string(0xC0A80101), "192.168.1.1");
    }
}
