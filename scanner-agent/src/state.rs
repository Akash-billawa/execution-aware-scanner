use scanner_common::{c_string, EventKind, ExecEvent, FileEvent, NetEvent};
use std::collections::{BTreeMap, BTreeSet};

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
    pub loaded_libraries: BTreeSet<String>, // NEW: Track loaded libraries
    pub signals: Vec<RuntimeSignal>,        // NEW: Track signal weighting
    pub data_transferred_bytes: u64,        // NEW: Track total data transferred
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
}

#[derive(Clone, Default)]
pub struct StateStore {
    by_cgroup: BTreeMap<u64, WorkloadState>,
}

impl StateStore {
    pub fn apply_exec(&mut self, event: &ExecEvent) {
        let entry = self.by_cgroup.entry(event.cgroup_id).or_default();
        let cmd = c_string(&event.command);
        entry.commands.insert(cmd.clone());
        entry.observed_syscalls.insert("execve".to_string());

        // Check for suspicious command patterns
        if is_suspicious_command(&cmd) {
            entry.signals.push(RuntimeSignal {
                signal_type: SignalType::SuspiciousExec,
                weight: 1.5,
                timestamp_ns: event.timestamp_ns,
                details: format!("Suspicious command: {}", cmd),
            });
        }
    }

    pub fn apply_file(&mut self, event: &FileEvent) {
        let entry = self.by_cgroup.entry(event.cgroup_id).or_default();
        let path = c_string(&event.path);
        entry.observed_paths.insert(path.clone());

        let syscall = match event.kind {
            EventKind::Mmap => "mmap",
            EventKind::Open => "openat",
            EventKind::Mprotect => "mprotect",
            _ => "unknown",
        };
        entry.observed_syscalls.insert(syscall.to_string());

        // Track library loads
        if event.kind == EventKind::Mmap && is_shared_library(&path) {
            entry.loaded_libraries.insert(path.clone());
            entry.signals.push(RuntimeSignal {
                signal_type: SignalType::LibraryLoaded,
                weight: 2.0,
                timestamp_ns: event.timestamp_ns,
                details: format!("Library loaded: {}", path),
            });
        }

        // Track sensitive file access
        if is_sensitive_path(&path) {
            entry.signals.push(RuntimeSignal {
                signal_type: SignalType::SensitiveFileAccess,
                weight: 1.0,
                timestamp_ns: event.timestamp_ns,
                details: format!("Sensitive file: {}", path),
            });
        }

        // Track mprotect for code injection detection
        if event.kind == EventKind::Mprotect {
            entry.signals.push(RuntimeSignal {
                signal_type: SignalType::MprotectExec,
                weight: 1.5,
                timestamp_ns: event.timestamp_ns,
                details: "Memory protection changed".to_string(),
            });
        }
    }

    pub fn apply_net(&mut self, event: &NetEvent) {
        let entry = self.by_cgroup.entry(event.cgroup_id).or_default();
        entry.network_flows.insert(format!(
            "{}:{}->{}:{}",
            event.saddr, event.sport, event.daddr, event.dport
        ));

        let syscall = match event.kind {
            EventKind::Connect => "connect",
            EventKind::Bind => "bind",
            EventKind::TcpSend => "tcp_sendmsg",
            EventKind::TcpRecv => "tcp_recvmsg",
            EventKind::UdpSend => "udp_sendmsg",
            EventKind::UdpRecv => "udp_recvmsg",
            _ => "unknown",
        };
        entry.observed_syscalls.insert(syscall.to_string());

        // Track data transfer for behavioral analysis
        entry.data_transferred_bytes += event.data_size as u64;

        // Large data transfer = potential exfiltration
        if event.data_size > 1024 {
            entry.signals.push(RuntimeSignal {
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
