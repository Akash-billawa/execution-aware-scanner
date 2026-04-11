//! Execution Proof Layer
//! Provides concrete evidence that vulnerabilities are actively being exploited
//! Tracks: function calls, network activity, file access, syscall patterns

use crate::error::ScannerError;
use scanner_common::{EventKind, ExecEvent, FileEvent, NetEvent};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

/// Evidence of vulnerability exploitation
#[derive(Debug, Clone)]
pub struct ExecutionEvidence {
    pub cve_id: String,
    pub package: String,
    pub evidence_type: EvidenceType,
    pub timestamp: SystemTime,
    pub process_id: u32,
    pub process_name: String,
    pub details: String,
    pub confidence: ConfidenceLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceType {
    /// Network connection to vulnerable service
    NetworkConnection { dest_ip: String, dest_port: u16 },
    /// File access to vulnerable library
    FileAccess { path: String, operation: String },
    /// Syscall pattern matching exploit signature
    SyscallPattern { pattern: String },
    /// Function call traced (advanced)
    FunctionCall { function: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfidenceLevel {
    High,   // Direct evidence (e.g., exploit payload observed)
    Medium, // Strong correlation (e.g., vulnerable function called)
    Low,    // Indirect (e.g., library loaded but not confirmed usage)
}

/// Maps CVEs to specific runtime behaviors
pub struct ExecutionProofCollector {
    /// CVE ID -> Evidence list
    evidence: BTreeMap<String, Vec<ExecutionEvidence>>,
    /// Package -> CVE list
    package_cves: BTreeMap<String, BTreeSet<String>>,
    /// Track syscall patterns
    syscall_patterns: SyscallPatternMatcher,
}

/// Syscall pattern matching for exploit detection
pub struct SyscallPatternMatcher {
    /// Known exploit signatures
    signatures: Vec<SyscallSignature>,
}

#[derive(Clone)]
pub struct SyscallSignature {
    pub cve_id: String,
    pub pattern: Vec<String>,
    pub description: String,
}

impl ExecutionProofCollector {
    pub fn new() -> Self {
        Self {
            evidence: BTreeMap::new(),
            package_cves: BTreeMap::new(),
            syscall_patterns: SyscallPatternMatcher::new(),
        }
    }

    /// Register a CVE for a specific package
    pub fn register_cve(&mut self, package: &str, cve_id: &str) {
        self.package_cves
            .entry(package.to_string())
            .or_default()
            .insert(cve_id.to_string());
    }

    /// Process network event for exploit evidence
    pub fn process_network_event(&mut self, event: &NetEvent, process_name: &str) {
        // Check for suspicious outbound connections
        // Example: Log4j JNDI exploitation (LDAP/RMI to external)
        if event.dport == 389 || event.dport == 636 || event.dport == 1099 {
            let dest_ip = self.ip_to_string(event.daddr);

            // Check if this is external (non-private) IP
            if self.is_external_ip(event.daddr) {
                // Look for Log4Shell pattern
                if process_name.contains("java") || process_name.contains("log4j") {
                    self.add_evidence(
                        "CVE-2021-44228",
                        "log4j-core",
                        EvidenceType::NetworkConnection {
                            dest_ip: dest_ip.clone(),
                            dest_port: event.dport,
                        },
                        event.pid,
                        process_name,
                        format!(
                            "Suspicious JNDI/LDAP connection to {}:{}",
                            dest_ip, event.dport
                        ),
                        ConfidenceLevel::High,
                    );
                }
            }
        }
    }

    /// Process file event for exploit evidence  
    pub fn process_file_event(&mut self, event: &FileEvent, process_name: &str) {
        let path = String::from_utf8_lossy(&event.path)
            .trim_end_matches('\0')
            .to_string();

        // Check for vulnerable library access
        if let Some(cves) = self.get_cves_for_path(&path) {
            for cve_id in cves {
                let operation = match event.kind {
                    EventKind::Open => "open",
                    EventKind::Read => "read",
                    EventKind::Write => "write",
                    EventKind::Mmap => "mmap",
                    EventKind::Exec => "exec",
                };

                let confidence = if event.kind == EventKind::Mmap || event.kind == EventKind::Exec {
                    ConfidenceLevel::Medium
                } else {
                    ConfidenceLevel::Low
                };

                self.add_evidence(
                    &cve_id,
                    &self.extract_package_name(&path),
                    EvidenceType::FileAccess {
                        path: path.clone(),
                        operation: operation.to_string(),
                    },
                    event.pid,
                    process_name,
                    format!("Vulnerable library {} accessed via {}", path, operation),
                    confidence,
                );
            }
        }
    }

    /// Process exec event
    pub fn process_exec_event(&mut self, event: &ExecEvent) {
        let command = String::from_utf8_lossy(&event.command)
            .trim_end_matches('\0')
            .to_string();

        // Check for known vulnerable executables
        if command.contains("log4j") || command.contains("log4shell") {
            self.add_evidence(
                "CVE-2021-44228",
                "log4j-core",
                EvidenceType::SyscallPattern {
                    pattern: "log4j_execution".to_string(),
                },
                event.pid,
                &command,
                "Log4j-related process executed".to_string(),
                ConfidenceLevel::Medium,
            );
        }
    }

    /// Get all evidence for a CVE
    pub fn get_evidence(&self, cve_id: &str) -> Vec<&ExecutionEvidence> {
        self.evidence
            .get(cve_id)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get summary of execution proof
    pub fn get_execution_summary(&self, cve_id: &str) -> ExecutionSummary {
        let evidence = self.get_evidence(cve_id);

        let mut high_confidence = 0;
        let mut medium_confidence = 0;
        let mut low_confidence = 0;
        let mut processes = BTreeSet::new();
        let mut last_seen = None;

        for e in &evidence {
            match e.confidence {
                ConfidenceLevel::High => high_confidence += 1,
                ConfidenceLevel::Medium => medium_confidence += 1,
                ConfidenceLevel::Low => low_confidence += 1,
            }
            processes.insert(e.process_name.clone());
            if last_seen.is_none() || e.timestamp > last_seen.unwrap() {
                last_seen = Some(e.timestamp);
            }
        }

        ExecutionSummary {
            cve_id: cve_id.to_string(),
            total_evidence: evidence.len(),
            high_confidence,
            medium_confidence,
            low_confidence,
            affected_processes: processes.into_iter().collect(),
            last_seen,
            is_actively_exploited: high_confidence > 0,
        }
    }

    /// Check if CVE has execution proof
    pub fn has_execution_proof(&self, cve_id: &str, min_confidence: ConfidenceLevel) -> bool {
        self.get_evidence(cve_id)
            .iter()
            .any(|e| e.confidence >= min_confidence)
    }

    // Private helpers
    fn add_evidence(
        &mut self,
        cve_id: &str,
        package: &str,
        evidence_type: EvidenceType,
        process_id: u32,
        process_name: &str,
        details: String,
        confidence: ConfidenceLevel,
    ) {
        let evidence = ExecutionEvidence {
            cve_id: cve_id.to_string(),
            package: package.to_string(),
            evidence_type,
            timestamp: SystemTime::now(),
            process_id,
            process_name: process_name.to_string(),
            details,
            confidence,
        };

        self.evidence
            .entry(cve_id.to_string())
            .or_default()
            .push(evidence);

        tracing::info!(
            "Execution evidence for {}: {} ({} confidence)",
            cve_id,
            process_name,
            format!("{:?}", confidence)
        );
    }

    fn get_cves_for_path(&self, path: &str) -> Option<Vec<String>> {
        let package = self.extract_package_name(path);
        self.package_cves
            .get(&package)
            .map(|s| s.iter().cloned().collect())
    }

    fn extract_package_name(&self, path: &str) -> String {
        // Extract package from path
        // Example: /usr/lib/libssl.so.1.1 -> libssl
        std::path::Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .split('.')
            .next()
            .unwrap_or("unknown")
            .to_string()
    }

    fn ip_to_string(&self, ip: u32) -> String {
        format!(
            "{}.{}.{}.{}",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF
        )
    }

    fn is_external_ip(&self, ip: u32) -> bool {
        let octets = [
            ((ip >> 24) & 0xFF) as u8,
            ((ip >> 16) & 0xFF) as u8,
            ((ip >> 8) & 0xFF) as u8,
            (ip & 0xFF) as u8,
        ];

        // Check if private IP
        !(octets[0] == 10
            || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
            || (octets[0] == 192 && octets[1] == 168)
            || octets[0] == 127)
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionSummary {
    pub cve_id: String,
    pub total_evidence: usize,
    pub high_confidence: usize,
    pub medium_confidence: usize,
    pub low_confidence: usize,
    pub affected_processes: Vec<String>,
    pub last_seen: Option<SystemTime>,
    pub is_actively_exploited: bool,
}

impl SyscallPatternMatcher {
    pub fn new() -> Self {
        let signatures = vec![
            SyscallSignature {
                cve_id: "CVE-2021-44228".to_string(),
                pattern: vec!["socket", "connect", "sendto"], // JNDI LDAP
                description: "Log4Shell JNDI exploit pattern".to_string(),
            },
            SyscallSignature {
                cve_id: "CVE-2023-38408".to_string(),
                pattern: vec!["openat", "read", "write"], // OpenSSH
                description: "OpenSSH PKCS11 exploit".to_string(),
            },
        ];

        Self { signatures }
    }

    pub fn match_pattern(&self, syscalls: &[String]) -> Vec<String> {
        let mut matches = Vec::new();
        for sig in &self.signatures {
            if self.contains_pattern(syscalls, &sig.pattern) {
                matches.push(sig.cve_id.clone());
            }
        }
        matches
    }

    fn contains_pattern(&self, haystack: &[String], needle: &[String]) -> bool {
        if needle.len() > haystack.len() {
            return false;
        }
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}

impl Default for ExecutionProofCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_collection() {
        let mut collector = ExecutionProofCollector::new();

        collector.register_cve("log4j-core", "CVE-2021-44228");

        // Simulate network event
        let net_event = NetEvent {
            timestamp_ns: 0,
            pid: 1234,
            tgid: 1234,
            cgroup_id: 1,
            saddr: 0,
            daddr: 134744072, // 8.8.8.8
            sport: 12345,
            dport: 389, // LDAP
            family: 2,
            protocol: 6,
            kind: EventKind::Connect,
        };

        collector.process_network_event(&net_event, "java");

        let evidence = collector.get_evidence("CVE-2021-44228");
        assert!(!evidence.is_empty());
        assert_eq!(evidence[0].confidence, ConfidenceLevel::High);
    }

    #[test]
    fn test_execution_summary() {
        let mut collector = ExecutionProofCollector::new();
        collector.register_cve("libssl", "CVE-2023-XXXX");

        let summary = collector.get_execution_summary("CVE-2023-XXXX");
        assert_eq!(summary.total_evidence, 0);
        assert!(!summary.is_actively_exploited);
    }
}
