//! Runtime event to CVE correlation mapper
//! Maps eBPF events (exec, file open, network) to actual vulnerable libraries

use crate::error::ScannerError;
use crate::runtime_correlation::library_matches_package;
use crate::vuln_detector::{VulnDetector, Vulnerability};
use scanner_common::{EventKind, ExecEvent, FileEvent, NetEvent};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Runtime process state tracked via eBPF
#[derive(Debug, Clone)]
pub struct ProcessState {
    pub pid: u32,
    pub command: String,
    pub binary_path: Option<String>,
    pub loaded_libs: BTreeSet<String>,
    pub network_connections: Vec<NetworkConn>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone)]
pub struct NetworkConn {
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
}

/// Maps eBPF runtime events to CVEs
pub struct RuntimeMapper {
    /// Process ID -> Process state
    processes: BTreeMap<u32, ProcessState>,
    /// Library path -> CVE list (cached)
    lib_vulns: BTreeMap<String, Vec<Vulnerability>>,
    /// Package -> known vulnerability list from image/SBOM scanning
    package_vulns: BTreeMap<String, Vec<Vulnerability>>,
    vuln_detector: VulnDetector,
}

impl RuntimeMapper {
    pub fn new() -> Self {
        Self {
            processes: BTreeMap::new(),
            lib_vulns: BTreeMap::new(),
            package_vulns: BTreeMap::new(),
            vuln_detector: VulnDetector::new(),
        }
    }

    /// Preload vulnerabilities discovered from an image or SBOM scan.
    pub fn set_vulnerabilities(&mut self, vulnerabilities: Vec<Vulnerability>) {
        self.package_vulns.clear();
        for vuln in vulnerabilities {
            self.package_vulns
                .entry(vuln.package.to_ascii_lowercase())
                .or_default()
                .push(vuln);
        }
        self.lib_vulns.clear();
    }

    /// Process exec event - new process started
    pub fn handle_exec(&mut self, event: &ExecEvent) {
        let command = String::from_utf8_lossy(&event.command)
            .trim_end_matches('\0')
            .to_string();

        let process = ProcessState {
            pid: event.pid,
            command: command.clone(),
            binary_path: None,
            loaded_libs: BTreeSet::new(),
            network_connections: Vec::new(),
            vulnerabilities: Vec::new(),
        };

        self.processes.insert(event.pid, process);
        tracing::info!("Process started: {} (pid={})", command, event.pid);
    }

    /// Process file event - library loaded or file opened
    pub async fn handle_file(&mut self, event: &FileEvent) -> Result<(), ScannerError> {
        let path = String::from_utf8_lossy(&event.path)
            .trim_end_matches('\0')
            .to_string();

        // Only process mmap events (shared libraries loaded)
        if event.kind != EventKind::Mmap {
            return Ok(());
        }

        // Check if this is a shared library
        if !self.is_shared_library(&path) {
            return Ok(());
        }

        // Update process state
        if let Some(process) = self.processes.get_mut(&event.pid) {
            process.loaded_libs.insert(path.clone());

            // End mutable borrow by letting it go out of scope

            // Check if library has known vulnerabilities
            let vulns = if !self.lib_vulns.contains_key(&path) {
                // Scan this specific library for CVEs
                match self.scan_library(&path).await {
                    Ok(vulns) => {
                        if !vulns.is_empty() {
                            tracing::info!(
                                "Library {} loaded by process {} has {} vulnerabilities",
                                path,
                                event.pid,
                                vulns.len()
                            );
                        }
                        self.lib_vulns.insert(path.clone(), vulns.clone());
                        vulns
                    }
                    Err(e) => {
                        tracing::warn!("Failed to scan library {}: {}", path, e);
                        Vec::new()
                    }
                }
            } else {
                // Use cached vulnerabilities
                self.lib_vulns.get(&path).unwrap().clone()
            };

            // Re-borrow mutably to update vulnerabilities
            if let Some(process) = self.processes.get_mut(&event.pid) {
                process.vulnerabilities.extend(vulns);
            }
        }

        Ok(())
    }

    /// Process network event - connection made
    pub fn handle_network(&mut self, event: &NetEvent) {
        // Only track external connections
        if event.dport == 443 || event.dport == 80 {
            let conn = NetworkConn {
                dest_ip: format!(
                    "{}.{}.{}.{}",
                    (event.daddr >> 24) & 0xFF,
                    (event.daddr >> 16) & 0xFF,
                    (event.daddr >> 8) & 0xFF,
                    event.daddr & 0xFF
                ),
                dest_port: event.dport,
                protocol: if event.protocol == 6 {
                    "TCP".to_string()
                } else {
                    "UDP".to_string()
                },
            };

            if let Some(process) = self.processes.get_mut(&event.pid) {
                process.network_connections.push(conn);
                tracing::debug!(
                    "Process {} made network connection to {}:{}",
                    process.command,
                    event.daddr,
                    event.dport
                );
            }
        }
    }

    /// Get active vulnerable processes
    pub fn get_vulnerable_processes(&self) -> Vec<&ProcessState> {
        self.processes
            .values()
            .filter(|p| !p.vulnerabilities.is_empty())
            .collect()
    }

    /// Get process by PID
    pub fn get_process(&self, pid: u32) -> Option<&ProcessState> {
        self.processes.get(&pid)
    }

    /// Get all tracked processes
    pub fn get_all_processes(&self) -> &BTreeMap<u32, ProcessState> {
        &self.processes
    }

    /// Clean up exited process
    pub fn remove_process(&mut self, pid: u32) {
        if let Some(process) = self.processes.remove(&pid) {
            tracing::info!("Process exited: {} (pid={})", process.command, pid);
        }
    }

    /// Check if path is a shared library
    fn is_shared_library(&self, path: &str) -> bool {
        path.ends_with(".so")
            || path.contains(".so.")
            || path.starts_with("/usr/lib")
            || path.starts_with("/lib")
    }

    /// Scan a library file for vulnerabilities
    async fn scan_library(&self, path: &str) -> Result<Vec<Vulnerability>, ScannerError> {
        let lib_name = Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .split('.')
            .next()
            .unwrap_or("unknown")
            .to_string();

        let vulns: Vec<Vulnerability> = self
            .package_vulns
            .values()
            .flatten()
            .filter(|vuln| library_matches_package(path, &vuln.package))
            .cloned()
            .collect();

        tracing::debug!(
            "Library {} loaded (path: {}), matched {} vulnerabilities",
            lib_name,
            path,
            vulns.len()
        );
        Ok(vulns)
    }
}

impl Default for RuntimeMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps runtime events to risk signals
pub struct RuntimeRiskMapper {
    mapper: RuntimeMapper,
}

impl RuntimeRiskMapper {
    pub fn new() -> Self {
        Self {
            mapper: RuntimeMapper::new(),
        }
    }

    /// Process batch of events and return vulnerable processes
    pub async fn process_events(
        &mut self,
        exec_events: &[ExecEvent],
        file_events: &[FileEvent],
        net_events: &[NetEvent],
    ) -> Result<Vec<ProcessRisk>, ScannerError> {
        // Process exec events
        for event in exec_events {
            self.mapper.handle_exec(event);
        }

        // Process file events (async for vulnerability scanning)
        for event in file_events {
            self.mapper.handle_file(event).await?;
        }

        // Process network events
        for event in net_events {
            self.mapper.handle_network(event);
        }

        // Build risk report
        let mut risks = Vec::new();
        for process in self.mapper.get_vulnerable_processes() {
            for vuln in &process.vulnerabilities {
                risks.push(ProcessRisk {
                    pid: process.pid,
                    command: process.command.clone(),
                    cve: vuln.cve.clone(),
                    severity: format!("{:?}", vuln.severity),
                    loaded_libs: process.loaded_libs.clone(),
                    network_exposed: !process.network_connections.is_empty(),
                });
            }
        }

        Ok(risks)
    }
}

#[derive(Debug, Clone)]
pub struct ProcessRisk {
    pub pid: u32,
    pub command: String,
    pub cve: String,
    pub severity: String,
    pub loaded_libs: BTreeSet<String>,
    pub network_exposed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_process_tracking() {
        let mut mapper = RuntimeMapper::new();

        // Simulate nginx starting
        let exec = ExecEvent {
            timestamp_ns: 0,
            pid: 1234,
            tgid: 1234,
            uid: 0,
            gid: 0,
            cgroup_id: 1,
            ppid: 1,
            command: [110, 103, 105, 110, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // "nginx"
            argv: [0u8; 256],
        };

        mapper.handle_exec(&exec);
        assert!(mapper.get_process(1234).is_some());
        assert_eq!(mapper.get_process(1234).unwrap().command, "nginx");

        // Simulate loading libssl
        let file = FileEvent {
            timestamp_ns: 0,
            pid: 1234,
            tgid: 1234,
            cgroup_id: 1,
            command: [110, 103, 105, 110, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            path: path_to_bytes("/usr/lib/libssl.so.1.1"),
            kind: EventKind::Mmap,
        };

        mapper.handle_file(&file).await.unwrap();
        let proc = mapper.get_process(1234).unwrap();
        assert!(proc.loaded_libs.contains("/usr/lib/libssl.so.1.1"));
    }

    #[tokio::test]
    async fn maps_loaded_library_to_preloaded_vulnerabilities() {
        let mut mapper = RuntimeMapper::new();
        mapper.set_vulnerabilities(vec![Vulnerability {
            package: "openssl".to_string(),
            version: "1.1.1".to_string(),
            cve: "CVE-2026-0001".to_string(),
            severity: crate::vuln_detector::Severity::High,
            cvss_score: 8.8,
            description: "test".to_string(),
            fixed_version: None,
        }]);

        let exec = ExecEvent {
            timestamp_ns: 0,
            pid: 1234,
            tgid: 1234,
            uid: 0,
            gid: 0,
            cgroup_id: 1,
            ppid: 1,
            command: [110, 103, 105, 110, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            argv: [0u8; 256],
        };
        mapper.handle_exec(&exec);

        let file = FileEvent {
            timestamp_ns: 0,
            pid: 1234,
            tgid: 1234,
            cgroup_id: 1,
            command: [110, 103, 105, 110, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            path: path_to_bytes("/usr/lib/libssl.so.1.1"),
            kind: EventKind::Mmap,
        };

        mapper.handle_file(&file).await.unwrap();
        let proc = mapper.get_process(1234).unwrap();
        assert_eq!(proc.vulnerabilities.len(), 1);
        assert_eq!(proc.vulnerabilities[0].cve, "CVE-2026-0001");
    }

    fn path_to_bytes(s: &str) -> [u8; 256] {
        let mut buf = [0u8; 256];
        let bytes = s.as_bytes();
        let len = bytes.len().min(256);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    }
}
