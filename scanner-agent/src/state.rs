use scanner_common::{c_string, EventKind, ExecEvent, FileEvent, NetEvent};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum signals per workload (prevents unbounded Vec growth)
const MAX_SIGNALS: usize = 1000;
/// Maximum entries per BTreeSet collection
const MAX_SET_ENTRIES: usize = 5000;
/// Maximum data transfer bytes (cap at 1 TB to prevent u64 overflow exploitation)
const MAX_DATA_BYTES: u64 = 1_099_511_627_776; // 1 TB

/// Signal types for runtime behavior weighting
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignalType {
    LibraryLoaded,       // mmap of shared library
    LargeDataTransfer,   // >1KB TCP send
    MaliciousIP,         // Connection to threat intel IP
    SensitiveFileAccess, // Access to sensitive paths
    MprotectExec,        // W+X memory (code injection)
    SuspiciousExec,      // Suspicious command patterns
}

/// Weighted signal for risk scoring
#[derive(Debug, Clone)]
pub struct RuntimeSignal {
    pub signal_type: SignalType,
    pub weight: f32,
    pub timestamp_ns: u64,
    pub details: String,
}

#[derive(Debug, Clone, Default)]
pub struct WorkloadState {
    pub observed_paths: BTreeSet<String>,
    pub observed_syscalls: BTreeSet<String>,
    pub commands: BTreeSet<String>,
    pub network_flows: BTreeSet<String>,
    pub loaded_libraries: BTreeSet<String>,
    pub signals: Vec<RuntimeSignal>,
    pub data_transferred_bytes: u64,
}

impl WorkloadState {
    /// Calculate total signal weight for risk scoring
    pub fn signal_weight(&self) -> f32 {
        self.signals.iter().map(|s| s.weight).sum()
    }

    /// Get signals that boost risk
    pub fn risk_boosting_signals(&self) -> Vec<&RuntimeSignal> {
        self.signals.iter().filter(|s| s.weight > 1.0).collect()
    }

    /// Get count of library loads
    pub fn library_load_count(&self) -> usize {
        self.loaded_libraries.len()
    }

    /// Push a signal with capacity enforcement (evicts oldest when full)
    fn push_signal(&mut self, signal: RuntimeSignal) {
        if self.signals.len() >= MAX_SIGNALS {
            self.signals.remove(0); // Remove oldest
        }
        self.signals.push(signal);
    }

    /// Insert into a BTreeSet with capacity enforcement
    fn capped_insert(set: &mut BTreeSet<String>, value: String) {
        if set.len() >= MAX_SET_ENTRIES && !set.contains(&value) {
            // At capacity and value is new — skip to prevent unbounded growth
            return;
        }
        set.insert(value);
    }
}

#[derive(Clone, Default)]
pub struct StateStore {
    by_cgroup: BTreeMap<u64, WorkloadState>,
}

impl StateStore {
    pub fn apply_exec(&mut self, event: &ExecEvent) {
        let entry = self.by_cgroup.entry(event.cgroup_id).or_default();
        let cmd = c_string(&event.command);
        WorkloadState::capped_insert(&mut entry.commands, cmd.clone());
        WorkloadState::capped_insert(&mut entry.observed_syscalls, "execve".to_string());

        // Check for suspicious command patterns
        if is_suspicious_command(&cmd) {
            entry.push_signal(RuntimeSignal {
                signal_type: SignalType::SuspiciousExec,
                weight: 1.5,
                timestamp_ns: event.timestamp_ns,
                details: format!("Suspicious command: {cmd}"),
            });
        }
    }

    pub fn apply_file(&mut self, event: &FileEvent) {
        let entry = self.by_cgroup.entry(event.cgroup_id).or_default();
        let path = c_string(&event.path);
        WorkloadState::capped_insert(&mut entry.observed_paths, path.clone());

        let syscall = match event.kind {
            EventKind::Mmap => "mmap",
            EventKind::Open => "openat",
            EventKind::Mprotect => "mprotect",
            _ => "unknown",
        };
        WorkloadState::capped_insert(&mut entry.observed_syscalls, syscall.to_string());

        // Track library loads
        if event.kind == EventKind::Mmap && is_shared_library(&path) {
            WorkloadState::capped_insert(&mut entry.loaded_libraries, path.clone());
            entry.push_signal(RuntimeSignal {
                signal_type: SignalType::LibraryLoaded,
                weight: 2.0,
                timestamp_ns: event.timestamp_ns,
                details: format!("Library loaded: {path}"),
            });
        }

        // Track sensitive file access
        if is_sensitive_path(&path) {
            entry.push_signal(RuntimeSignal {
                signal_type: SignalType::SensitiveFileAccess,
                weight: 1.0,
                timestamp_ns: event.timestamp_ns,
                details: format!("Sensitive file: {path}"),
            });
        }

        // Track mprotect for code injection detection
        if event.kind == EventKind::Mprotect {
            entry.push_signal(RuntimeSignal {
                signal_type: SignalType::MprotectExec,
                weight: 1.5,
                timestamp_ns: event.timestamp_ns,
                details: "Memory protection changed".to_string(),
            });
        }
    }

    pub fn apply_net(&mut self, event: &NetEvent) {
        let entry = self.by_cgroup.entry(event.cgroup_id).or_default();
        WorkloadState::capped_insert(
            &mut entry.network_flows,
            format!(
                "{}:{}->{}:{}",
                event.saddr, event.sport, event.daddr, event.dport
            ),
        );

        let syscall = match event.kind {
            EventKind::Connect => "connect",
            EventKind::Bind => "bind",
            EventKind::TcpSend => "tcp_sendmsg",
            EventKind::TcpRecv => "tcp_recvmsg",
            EventKind::UdpSend => "udp_sendmsg",
            EventKind::UdpRecv => "udp_recvmsg",
            _ => "unknown",
        };
        WorkloadState::capped_insert(&mut entry.observed_syscalls, syscall.to_string());

        // Track data transfer with saturating add to prevent overflow
        entry.data_transferred_bytes = entry
            .data_transferred_bytes
            .saturating_add(event.data_size as u64)
            .min(MAX_DATA_BYTES);

        // Large data transfer = potential exfiltration
        if event.data_size > 1024 {
            entry.push_signal(RuntimeSignal {
                signal_type: SignalType::LargeDataTransfer,
                weight: 1.5,
                timestamp_ns: event.timestamp_ns,
                details: format!(
                    "Large transfer: {} bytes to {}:{}",
                    event.data_size, event.daddr, event.dport
                ),
            });
        }
    }

    pub fn workload(&self, cgroup_id: u64) -> Option<&WorkloadState> {
        self.by_cgroup.get(&cgroup_id)
    }

    pub fn workloads(&self) -> &BTreeMap<u64, WorkloadState> {
        &self.by_cgroup
    }

    pub fn snapshot(&self) -> BTreeMap<u64, WorkloadState> {
        self.by_cgroup.clone()
    }

    pub fn clear(&mut self) {
        self.by_cgroup.clear();
    }
}

fn is_shared_library(path: &str) -> bool {
    path.ends_with(".so") || path.contains(".so.")
}

fn is_sensitive_path(path: &str) -> bool {
    let sensitive = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh",
        "/.dockerenv",
        "/.kube",
        "/var/run/secrets",
    ];
    sensitive.iter().any(|p| path.starts_with(p))
}

fn is_suspicious_command(cmd: &str) -> bool {
    let suspicious = ["nc", "ncat", "bash -i", "python", "perl", "ruby"];
    suspicious.iter().any(|s| cmd.contains(s))
}

// ── Finding Store (for REST API) ────────────────────────────────────────────

use chrono::{DateTime, Utc};
use scanner_common::Finding;

/// Maximum findings to keep in the ring buffer
const MAX_FINDINGS: usize = 10000;

/// Summary view of a finding for API responses
#[derive(Debug, Clone, serde::Serialize)]
pub struct FindingSummary {
    pub id: String,
    pub detected_at: DateTime<Utc>,
    pub cve: String,
    pub cvss: f32,
    pub epss: f32,
    pub kev: bool,
    pub priority: String,
    pub namespace: String,
    pub workload: String,
    pub pod_name: String,
    pub score: f32,
    pub recommendation: String,
    pub acknowledged: bool,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
}

impl From<&Finding> for FindingSummary {
    fn from(f: &Finding) -> Self {
        Self {
            id: f.id.clone(),
            detected_at: f.detected_at,
            cve: f.signal.cve.clone(),
            cvss: f.signal.cvss,
            epss: f.signal.epss,
            kev: f.signal.kev,
            priority: format!("{:?}", f.priority),
            namespace: f.identity.namespace.clone(),
            workload: f.identity.workload.clone(),
            pod_name: f.identity.pod_name.clone(),
            score: f.score,
            recommendation: f.recommendation.clone(),
            acknowledged: false,
            acknowledged_at: None,
            acknowledged_by: None,
        }
    }
}

/// Finding stats for API responses
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FindingStats {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
    pub acknowledged: usize,
}

/// In-memory finding store with ring buffer semantics
#[derive(Default)]
pub struct FindingStore {
    findings: Vec<FindingSummary>,
}

impl FindingStore {
    pub fn new() -> Self {
        Self {
            findings: Vec::with_capacity(MAX_FINDINGS.min(1000)),
        }
    }

    /// Insert a finding, evicting oldest if at capacity
    pub fn insert(&mut self, finding: &Finding) {
        if self.findings.len() >= MAX_FINDINGS {
            self.findings.remove(0);
        }
        self.findings.push(FindingSummary::from(finding));
    }

    /// Get all findings
    pub fn get_all(&self) -> &[FindingSummary] {
        &self.findings
    }

    /// Get a finding by ID
    pub fn get(&self, id: &str) -> Option<&FindingSummary> {
        self.findings.iter().find(|f| f.id == id)
    }

    /// Acknowledge a finding
    pub fn acknowledge(&mut self, id: &str, reason: Option<String>) -> Result<(), String> {
        let finding = self
            .findings
            .iter_mut()
            .find(|f| f.id == id)
            .ok_or_else(|| format!("Finding {id} not found"))?;
        finding.acknowledged = true;
        finding.acknowledged_at = Some(Utc::now());
        finding.acknowledged_by = reason;
        Ok(())
    }

    /// Get stats
    pub fn stats(&self) -> FindingStats {
        let mut stats = FindingStats::default();
        stats.total = self.findings.len();
        for f in &self.findings {
            match f.priority.as_str() {
                "Critical" => stats.critical += 1,
                "High" => stats.high += 1,
                "Medium" => stats.medium += 1,
                "Low" => stats.low += 1,
                _ => stats.informational += 1,
            }
            if f.acknowledged {
                stats.acknowledged += 1;
            }
        }
        stats
    }
}
