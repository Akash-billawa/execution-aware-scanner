//! Runtime Attack Path Graph
//! Builds attack chains from runtime signals: Process → Library → Network → CVE
//!
//! Example path:
//! node process
//!   ↓ mmap libssl.so (CVE-XXXX)
//!   ↓ ssl_write outbound TLS traffic
//!   ↓ tcp_send external IP
//!
//! Output: Attack Path: node → libssl (CVE) → TLS → outbound → HIGH RISK

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use scanner_common::{EventKind, Finding, NetEvent, RuntimeDisposition, SignalEvidence};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Vulnerability node data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnerabilityNode {
    pub cve_id: String,
    pub package: String,
    pub cvss: f32,
    pub epss: f32,
    pub kev: bool,
}

/// Node types in runtime attack graph
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuntimeNode {
    /// Process/container
    Process {
        pid: u32,
        name: String,
        cgroup_id: u64,
    },
    /// Loaded library
    Library {
        path: String,
        cve_ids: Vec<String>, // Associated CVEs
    },
    /// Network endpoint
    Network {
        ip: String,
        port: u16,
        protocol: String,
    },
    /// Detected vulnerability
    Vulnerability(VulnerabilityNode),
    /// Attack technique (for categorization)
    Technique {
        name: String,
        mitre_tactic: Option<String>,
    },
}

impl RuntimeNode {
    /// Get node ID for indexing
    pub fn node_id(&self) -> String {
        match self {
            RuntimeNode::Process { pid, name, .. } => format!("proc:{}:{}", pid, name),
            RuntimeNode::Library { path, .. } => format!("lib:{}", path),
            RuntimeNode::Network { ip, port, .. } => format!("net:{}:{}", ip, port),
            RuntimeNode::Vulnerability(v) => format!("vuln:{}", v.cve_id),
            RuntimeNode::Technique { name, .. } => format!("tech:{}", name),
        }
    }
}

/// Edge types representing interactions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuntimeEdge {
    /// Process loaded library
    LibraryLoaded { timestamp_ns: u64, confidence: f32 },
    /// Library has CVE
    Vulnerable { confidence: f32 },
    /// Process made network connection
    NetworkConnection {
        timestamp_ns: u64,
        bytes_sent: u64,
        confidence: f32,
    },
    /// Using vulnerable library over network
    ExploitationAttempt { confidence: f32, evidence: String },
    /// Technique used
    UsesTechnique { confidence: f32 },
}

/// Attack path detected from runtime signals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub path_id: String,
    pub nodes: Vec<RuntimeNode>,
    pub edges: Vec<(usize, usize, RuntimeEdge)>,
    pub confidence: f32,
    pub risk_score: f32,
    pub time_window_secs: u64,
    pub indicators: Vec<String>,
}

impl AttackPath {
    /// Serialize to compact JSON for output
    pub fn to_summary(&self) -> AttackPathSummary {
        AttackPathSummary {
            path_id: self.path_id.clone(),
            node_types: self.nodes.iter().map(|n| format!("{:?}", n)).collect(),
            node_count: self.nodes.len(),
            confidence: self.confidence,
            risk_score: self.risk_score,
            indicators: self.indicators.clone(),
        }
    }
}

/// Compact summary for JSON output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathSummary {
    pub path_id: String,
    pub node_types: Vec<String>,
    pub node_count: usize,
    pub confidence: f32,
    pub risk_score: f32,
    pub indicators: Vec<String>,
}

/// Runtime attack path builder
pub struct RuntimeAttackGraph {
    graph: DiGraph<RuntimeNode, RuntimeEdge>,
    node_indices: HashMap<String, NodeIndex>,
    /// Track process → libraries
    process_libraries: HashMap<u32, Vec<(String, u64)>>, // pid → [(lib_path, timestamp)]
    /// Track process → network connections
    process_connections: HashMap<u32, Vec<NetEvent>>,
    /// CVE to library mapping
    cve_to_library: HashMap<String, Vec<String>>,
    /// Time window for correlation
    correlation_window: Duration,
}

impl RuntimeAttackGraph {
    pub fn new(correlation_window_secs: u64) -> Self {
        Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
            process_libraries: HashMap::new(),
            process_connections: HashMap::new(),
            cve_to_library: HashMap::new(),
            correlation_window: Duration::from_secs(correlation_window_secs),
        }
    }

    /// Add or get node
    fn add_node(&mut self, node: RuntimeNode) -> NodeIndex {
        let id = node.node_id();
        if let Some(&idx) = self.node_indices.get(&id) {
            idx
        } else {
            let idx = self.graph.add_node(node);
            self.node_indices.insert(id, idx);
            idx
        }
    }

    /// Add edge
    fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: RuntimeEdge) {
        self.graph.add_edge(from, to, edge);
    }

    /// Process library load event
    pub fn process_library_load(
        &mut self,
        pid: u32,
        process_name: &str,
        cgroup_id: u64,
        lib_path: &str,
        timestamp_ns: u64,
    ) {
        let process_node = RuntimeNode::Process {
            pid,
            name: process_name.to_string(),
            cgroup_id,
        };
        let process_idx = self.add_node(process_node);

        let lib_node = RuntimeNode::Library {
            path: lib_path.to_string(),
            cve_ids: Vec::new(),
        };
        let lib_idx = self.add_node(lib_node);

        let edge = RuntimeEdge::LibraryLoaded {
            timestamp_ns,
            confidence: 1.0, // Direct observation
        };
        self.add_edge(process_idx, lib_idx, edge);

        // Track for later correlation
        self.process_libraries
            .entry(pid)
            .or_default()
            .push((lib_path.to_string(), timestamp_ns));
    }

    /// Process network event
    pub fn process_network_event(
        &mut self,
        pid: u32,
        process_name: &str,
        cgroup_id: u64,
        event: &NetEvent,
    ) {
        let process_node = RuntimeNode::Process {
            pid,
            name: process_name.to_string(),
            cgroup_id,
        };
        let process_idx = self.add_node(process_node);

        // Format IP address
        let daddr = format!(
            "{}.{}.{}.{}",
            (event.daddr >> 24) & 0xFF,
            (event.daddr >> 16) & 0xFF,
            (event.daddr >> 8) & 0xFF,
            event.daddr & 0xFF
        );

        let net_node = RuntimeNode::Network {
            ip: daddr.clone(),
            port: event.dport,
            protocol: match event.kind {
                EventKind::TcpSend | EventKind::TcpRecv => "TCP".to_string(),
                EventKind::UdpSend | EventKind::UdpRecv => "UDP".to_string(),
                _ => "UNKNOWN".to_string(),
            },
        };
        let net_idx = self.add_node(net_node);

        let edge = RuntimeEdge::NetworkConnection {
            timestamp_ns: event.timestamp_ns,
            bytes_sent: event.data_size as u64,
            confidence: if event.data_size > 1024 { 0.9 } else { 0.7 },
        };
        self.add_edge(process_idx, net_idx, edge);

        // Store for correlation
        self.process_connections
            .entry(pid)
            .or_default()
            .push(event.clone());
    }

    /// Associate CVE with library
    pub fn associate_cve_with_library(
        &mut self,
        cve_id: &str,
        package: &str,
        cvss: f32,
        epss: f32,
        kev: bool,
    ) {
        let vuln_node = RuntimeNode::Vulnerability(VulnerabilityNode {
            cve_id: cve_id.to_string(),
            package: package.to_string(),
            cvss,
            epss,
            kev,
        });
        let vuln_idx = self.add_node(vuln_node);

        // Find libraries that match this package
        for idx in self.graph.node_indices() {
            if let Some(RuntimeNode::Library { path, .. }) = self.graph.node_weight(idx) {
                if path.contains(package) || package.contains(path.split('/').last().unwrap_or(""))
                {
                    let edge = RuntimeEdge::Vulnerable { confidence: 0.95 };
                    self.add_edge(vuln_idx, idx, edge);
                }
            }
        }

        self.cve_to_library
            .entry(cve_id.to_string())
            .or_default()
            .push(package.to_string());
    }

    /// Build attack paths from findings
    pub fn build_attack_paths(&self, findings: &[Finding]) -> Vec<AttackPath> {
        let mut paths = Vec::new();

        for finding in findings {
            // Only build paths for active vulnerabilities
            if finding.signal.runtime != RuntimeDisposition::Reachable {
                continue;
            }

            let path = self.build_path_for_finding(finding);
            if !path.nodes.is_empty() {
                paths.push(path);
            }
        }

        // Sort by risk score
        paths.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());
        paths
    }

    /// Build attack path for a specific finding
    fn build_path_for_finding(&self, finding: &Finding) -> AttackPath {
        let cve_id = &finding.signal.cve;
        let package = &finding.signal.package;

        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut indicators = Vec::new();

        // Start with vulnerability
        let vuln_node = RuntimeNode::Vulnerability(VulnerabilityNode {
            cve_id: cve_id.clone(),
            package: package.clone(),
            cvss: finding.signal.cvss,
            epss: finding.signal.epss,
            kev: finding.signal.kev,
        });
        nodes.push(vuln_node);

        // Find library nodes with this CVE
        let vuln_idx = self.node_indices.get(&format!("vuln:{}", cve_id));

        if let Some(&vuln_idx) = vuln_idx {
            // Get libraries linked to this CVE
            let lib_neighbors: Vec<_> = self
                .graph
                .edges(vuln_idx)
                .filter_map(|e| {
                    if let RuntimeEdge::Vulnerable { .. } = e.weight() {
                        Some(e.target())
                    } else {
                        None
                    }
                })
                .collect();

            for lib_idx in lib_neighbors {
                if let Some(lib_node) = self.graph.node_weight(lib_idx) {
                    nodes.push(lib_node.clone());
                    edges.push((
                        0,
                        nodes.len() - 1,
                        RuntimeEdge::Vulnerable { confidence: 0.95 },
                    ));

                    indicators.push(format!("Vulnerable library: {:?}", lib_node));
                }
            }
        }

        // Calculate confidence and risk
        let confidence = if nodes.len() >= 4 {
            0.85
        } else if nodes.len() >= 3 {
            0.7
        } else {
            0.5
        };

        let risk_score = finding.score * (nodes.len() as f32 * 0.2).min(1.0);

        AttackPath {
            path_id: format!("path-{}", uuid::Uuid::new_v4()),
            nodes,
            edges,
            confidence,
            risk_score,
            time_window_secs: self.correlation_window.as_secs(),
            indicators,
        }
    }

    /// Get all detected attack paths as summaries
    pub fn get_attack_path_summaries(&self, findings: &[Finding]) -> Vec<AttackPathSummary> {
        self.build_attack_paths(findings)
            .iter()
            .map(|p| p.to_summary())
            .collect()
    }

    /// Export graph to dot format for visualization
    pub fn to_dot(&self) -> String {
        use petgraph::dot::{Config, Dot};
        format!(
            "{:?}",
            Dot::with_config(&self.graph, &[Config::EdgeNoLabel])
        )
    }
}

/// Integration with findings
pub fn attach_attack_paths_to_findings(findings: &mut [Finding], graph: &RuntimeAttackGraph) {
    let paths = graph.build_attack_paths(findings);

    // Map CVE ID to attack path
    let cve_to_path: HashMap<String, &AttackPath> = paths
        .iter()
        .filter_map(|p| {
            p.nodes.iter().find_map(|n| match n {
                RuntimeNode::Vulnerability(v) => Some((v.cve_id.clone(), p)),
                _ => None,
            })
        })
        .collect();

    for finding in findings.iter_mut() {
        if let Some(path) = cve_to_path.get(&finding.signal.cve) {
            // Add attack path indicators to explainability
            finding
                .explainability
                .signals
                .extend(path.indicators.iter().map(|i| SignalEvidence {
                    signal_type: "attack_path".to_string(),
                    timestamp_ns: 0,
                    details: i.clone(),
                    confidence: path.confidence,
                }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scanner_common::{Priority, RiskSignal, RuntimeIdentity};

    #[test]
    fn test_attack_path_construction() {
        let mut graph = RuntimeAttackGraph::new(300);

        // Simulate: nginx loads libssl.so, then makes HTTPS connection
        graph.process_library_load(1234, "nginx", 1, "/usr/lib/libssl.so", 1000);

        let net_event = NetEvent {
            timestamp_ns: 2000,
            pid: 1234,
            tgid: 1234,
            cgroup_id: 1,
            saddr: 0,
            daddr: 0x08080808, // 8.8.8.8
            sport: 443,
            dport: 443,
            family: 2,
            protocol: 6,
            kind: EventKind::TcpSend,
            data_size: 1024,
        };

        graph.process_network_event(1234, "nginx", 1, &net_event);

        // Associate CVE
        graph.associate_cve_with_library("CVE-2023-XXXX", "openssl", 9.8, 0.85, true);

        // Build path
        let finding = Finding {
            id: "test".to_string(),
            detected_at: chrono::Utc::now(),
            identity: RuntimeIdentity {
                node_name: "test".to_string(),
                namespace: "default".to_string(),
                pod_name: "test-pod".to_string(),
                container_name: "app".to_string(),
                image: "nginx:latest".to_string(),
                workload: "nginx".to_string(),
                labels: std::collections::BTreeMap::new(),
            },
            signal: RiskSignal {
                cve: "CVE-2023-XXXX".to_string(),
                cvss: 9.8,
                epss: 0.85,
                kev: true,
                runtime: RuntimeDisposition::Reachable,
                package: "openssl".to_string(),
                observed_paths: std::collections::BTreeSet::new(),
                signal_weight: 2.0,
            },
            score: 9.0,
            priority: Priority::Critical,
            recommendation: "Patch".to_string(),
            explainability: Default::default(),
        };

        let paths = graph.build_attack_paths(&[finding]);
        assert!(!paths.is_empty());
        assert!(paths[0].nodes.len() >= 2); // Vuln + Lib
    }
}
