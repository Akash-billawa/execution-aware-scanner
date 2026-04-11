use scanner_common::{c_string, ExecEvent, FileEvent, NetEvent};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default)]
pub struct WorkloadState {
    pub observed_paths: BTreeSet<String>,
    pub observed_syscalls: BTreeSet<String>,
    pub commands: BTreeSet<String>,
    pub network_flows: BTreeSet<String>,
}

#[derive(Clone, Default)]
pub struct StateStore {
    by_cgroup: BTreeMap<u64, WorkloadState>,
}

impl StateStore {
    pub fn apply_exec(&mut self, event: &ExecEvent) {
        let entry = self.by_cgroup.entry(event.cgroup_id).or_default();
        entry.commands.insert(c_string(&event.command));
        entry.observed_syscalls.insert("execve".to_string());
    }

    pub fn apply_file(&mut self, event: &FileEvent) {
        let entry = self.by_cgroup.entry(event.cgroup_id).or_default();
        entry.observed_paths.insert(c_string(&event.path));
        let syscall = match event.kind {
            scanner_common::EventKind::Mmap => "mmap",
            scanner_common::EventKind::Open => "openat",
            _ => "unknown",
        };
        entry.observed_syscalls.insert(syscall.to_string());
    }

    pub fn apply_net(&mut self, event: &NetEvent) {
        let entry = self.by_cgroup.entry(event.cgroup_id).or_default();
        entry.network_flows.insert(format!(
            "{}:{}->{}:{}",
            event.saddr, event.sport, event.daddr, event.dport
        ));
        let syscall = match event.kind {
            scanner_common::EventKind::Connect => "connect",
            scanner_common::EventKind::Bind => "bind",
            _ => "unknown",
        };
        entry.observed_syscalls.insert(syscall.to_string());
    }

    pub fn workload(&self, cgroup_id: u64) -> Option<&WorkloadState> {
        self.by_cgroup.get(&cgroup_id)
    }

    pub fn workloads(&self) -> &BTreeMap<u64, WorkloadState> {
        &self.by_cgroup
    }

    /// Clears all tracked state (e.g., after processing a batch).
    pub fn clear(&mut self) {
        self.by_cgroup.clear();
    }
}
