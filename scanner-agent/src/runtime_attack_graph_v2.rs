//! Runtime Attack Path Graph v2
//! Enhanced with confidence model, ranking, de-duplication, and streaming support
//!
//! Key Improvements:
//! - Graph-aware confidence calculation
//! - Top-K path ranking
//! - Edge de-duplication (burst collapsing)
//! - Per-edge-type time windows
//! - Streaming incremental updates
//! - Path-level metrics
//! - Safety guards for enforcement
//!
//! Example:
//! node (nginx) → libssl.so (CVE-2023-XXXX) → tcp:443 (conf: 0.91, bytes: 84KB)

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use scanner_common::{EventKind, Finding, NetEvent, RuntimeDisposition, SignalEvidence};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Configuration for attack graph behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraphConfig {
    /// mmap → long window (300s)
    pub mmap_window_secs: u64,
    /// tcp/ssl → short window (30s)
    pub network_window_secs: u64,
    /// Minimum bytes to consider significant
    pub min_bytes_threshold: u64,
    /// Top K paths to report
    pub top_k: usize,
    /// Minimum confidence for enforcement
    pub min_enforcement_confidence: f32,
    /// Minimum path depth for enforcement
    pub min_enforcement_depth: usize,
    /// Enable edge de-duplication
    pub dedup_enabled: bool,
}

impl Default for AttackGraphConfig {
    fn default() -> Self {
        Self {
            mmap_window_secs: 300,
            network_window_secs: 30,
            min_bytes_threshold: 1024,
            top_k: 3,
            min_enforcement_confidence: 0.8,
            min_enforcement_depth: 3,
            dedup_enabled: true,
        }
    }
}

/// Node types in runtime attack graph
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuntimeNode {
    Process {
        pid: u32,
        name: String,
        cgroup_id: u64,
    },
    Library {
        path: String,
        cve_ids: Vec<String>,
    },
    Network {
        ip: String,
        port: u16,
        protocol: String,
    },
    Vulnerability(VulnerabilityNode),
    Technique {
        name: String,
        mitre_tactic: Option<String>,
    },
}

impl RuntimeNode {
    pub fn node_id(&self) -> String {
        match self {
            RuntimeNode::Process { pid, .. } => format!("proc:{pid}"),
            RuntimeNode::Library { path, .. } => format!("lib:{path}"),
            RuntimeNode::Network { ip, port, .. } => format!("net:{ip}:{port}"),
            RuntimeNode::Vulnerability(v) => format!("vuln:{}", v.cve_id),
            RuntimeNode::Technique { name, .. } => format!("tech:{name}"),
        }
    }

    /// Get node type as string
    pub fn node_type(&self) -> &'static str {
        match self {
            RuntimeNode::Process { .. } => "process",
            RuntimeNode::Library { .. } => "library",
            RuntimeNode::Network { .. } => "network",
            RuntimeNode::Vulnerability { .. } => "vulnerability",
            RuntimeNode::Technique { .. } => "technique",
        }
    }
}

/// Vulnerability node data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnerabilityNode {
    pub cve_id: String,
    pub package: String,
    pub cvss: f32,
    pub epss: f32,
    pub kev: bool,
}

/// Edge types with aggregated data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuntimeEdge {
    /// Process created/spawned
    ProcessCreated {
        timestamp_ns: u64,
        confidence: f32,
    },
    LibraryLoaded {
        timestamp_ns: u64,
        confidence: f32,
    },
    Vulnerable {
        confidence: f32,
    },
    NetworkConnection {
        timestamp_ns: u64,
        /// Aggregated bytes across multiple events
        total_bytes: u64,
        /// Event count (for burst detection)
        event_count: u32,
        confidence: f32,
    },
    ExploitationAttempt {
        confidence: f32,
        evidence: String,
    },
    UsesTechnique {
        confidence: f32,
    },
}

impl RuntimeEdge {
    /// Check if this edge represents burst activity
    pub fn is_burst(&self) -> bool {
        matches!(self, RuntimeEdge::NetworkConnection { event_count, .. } if *event_count > 1)
    }

    /// Get timestamp for temporal ordering
    pub fn timestamp_ns(&self) -> Option<u64> {
        match self {
            RuntimeEdge::ProcessCreated { timestamp_ns, .. } => Some(*timestamp_ns),
            RuntimeEdge::LibraryLoaded { timestamp_ns, .. } => Some(*timestamp_ns),
            RuntimeEdge::NetworkConnection { timestamp_ns, .. } => Some(*timestamp_ns),
            _ => None,
        }
    }
}

/// Attack path with confidence v2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub path_id: String,
    pub nodes: Vec<RuntimeNode>,
    pub edges: Vec<(usize, usize, RuntimeEdge)>,
    pub confidence: f32,
    pub risk_score: f32,
    pub time_window_secs: u64,
    pub indicators: Vec<String>,
    /// Path depth (node count)
    pub depth: usize,
    /// Signal types present in path
    pub signal_types: Vec<String>,
    /// Total data transferred
    pub total_bytes: u64,
    /// Rank based on confidence/risk
    pub rank: Option<usize>,
}

impl AttackPath {
    pub fn to_summary(&self) -> AttackPathSummary {
        AttackPathSummary {
            path_id: self.path_id.clone(),
            node_types: self
                .nodes
                .iter()
                .map(|n| n.node_type().to_string())
                .collect(),
            node_count: self.nodes.len(),
            depth: self.depth,
            confidence: self.confidence,
            risk_score: self.risk_score,
            total_bytes: self.total_bytes,
            signal_types: self.signal_types.clone(),
            indicators: self.indicators.clone(),
            rank: self.rank,
            is_burst: self.edges.iter().any(|(_, _, e)| e.is_burst()),
        }
    }

    /// Check if this path meets enforcement criteria
    pub fn meets_enforcement_criteria(&self, config: &AttackGraphConfig) -> bool {
        self.depth >= config.min_enforcement_depth
            && self.confidence >= config.min_enforcement_confidence
            && self.signal_types.len() >= 2 // Multiple signal types required
    }
}

/// Enhanced attack path summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathSummary {
    pub path_id: String,
    pub node_types: Vec<String>,
    pub node_count: usize,
    pub depth: usize,
    pub confidence: f32,
    pub risk_score: f32,
    pub total_bytes: u64,
    pub signal_types: Vec<String>,
    pub indicators: Vec<String>,
    pub rank: Option<usize>,
    pub is_burst: bool,
}

/// Metrics for attack paths
#[derive(Debug, Clone, Default)]
pub struct AttackPathMetrics {
    pub paths_total: u64,
    pub high_confidence_paths: u64, // conf >= 0.8
    pub avg_confidence: f32,
    pub paths_per_pid: HashMap<u32, u64>,
    pub burst_events_collapsed: u64,
}

/// Streaming update for incremental graph
#[derive(Debug, Clone)]
pub enum GraphUpdate {
    /// New edge added
    EdgeAdded {
        from: String,
        to: String,
        edge: RuntimeEdge,
    },
    /// Edge updated (aggregated)
    EdgeUpdated {
        from: String,
        to: String,
        delta_bytes: u64,
    },
    /// Confidence changed
    ConfidenceChanged { cve_id: String, old: f32, new: f32 },
    /// New path detected
    NewPath { path: AttackPath },
}

/// Enhanced runtime attack graph
pub struct RuntimeAttackGraph {
    graph: DiGraph<RuntimeNode, RuntimeEdge>,
    node_indices: HashMap<String, NodeIndex>,
    /// Track process → libraries
    process_libraries: HashMap<u32, Vec<(String, u64)>>,
    /// Track process → network connections (for dedup)
    process_connections: HashMap<u32, Vec<(NetEvent, u64)>>, // event + last_seen_timestamp
    /// CVE to library mapping
    cve_to_library: HashMap<String, Vec<String>>,
    /// Configuration
    config: AttackGraphConfig,
    /// Metrics
    metrics: AttackPathMetrics,
    /// Streaming updates
    update_queue: Vec<GraphUpdate>,
    /// Last update time for dedup windows
    last_network_update: HashMap<(u32, u16), u64>, // (pid, dport) -> timestamp
}

impl RuntimeAttackGraph {
    pub fn new(config: AttackGraphConfig) -> Self {
        Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
            process_libraries: HashMap::new(),
            process_connections: HashMap::new(),
            cve_to_library: HashMap::new(),
            config,
            metrics: AttackPathMetrics::default(),
            update_queue: Vec::new(),
            last_network_update: HashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(AttackGraphConfig::default())
    }

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

    /// Process library load with long time window
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
            confidence: 1.0,
        };
        self.graph.add_edge(process_idx, lib_idx, edge);

        self.process_libraries
            .entry(pid)
            .or_default()
            .push((lib_path.to_string(), timestamp_ns));

        self.update_queue.push(GraphUpdate::EdgeAdded {
            from: format!("proc:{pid}"),
            to: format!("lib:{lib_path}"),
            edge: RuntimeEdge::LibraryLoaded {
                timestamp_ns,
                confidence: 1.0,
            },
        });
    }

    /// Process network event with deduplication and burst collapsing
    pub fn process_network_event(
        &mut self,
        pid: u32,
        process_name: &str,
        cgroup_id: u64,
        event: &NetEvent,
    ) {
        // IP addresses from eBPF are in network byte order (big-endian)
        let daddr_h = u32::from_be(event.daddr);
        let daddr = format!(
            "{}.{}.{}.{}",
            (daddr_h >> 24) & 0xFF,
            (daddr_h >> 16) & 0xFF,
            (daddr_h >> 8) & 0xFF,
            daddr_h & 0xFF
        );

        // Check for deduplication (within short window)
        let dedup_key = (pid, event.dport);
        let current_time_ns = event.timestamp_ns;

        if self.config.dedup_enabled {
            if let Some(&last_time) = self.last_network_update.get(&dedup_key) {
                let window_ns =
                    Duration::from_secs(self.config.network_window_secs).as_nanos() as u64;
                if current_time_ns > last_time && current_time_ns - last_time < window_ns {
                    // Aggregate with existing edge
                    self.aggregate_network_event(pid, event);
                    self.metrics.burst_events_collapsed += 1;
                    return;
                }
            }
        }

        self.last_network_update.insert(dedup_key, current_time_ns);

        // Add new edge
        let process_node = RuntimeNode::Process {
            pid,
            name: process_name.to_string(),
            cgroup_id,
        };
        let process_idx = self.add_node(process_node);

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

        let confidence = if event.data_size as u64 > self.config.min_bytes_threshold {
            0.9
        } else {
            0.7
        };

        let edge = RuntimeEdge::NetworkConnection {
            timestamp_ns: event.timestamp_ns,
            total_bytes: event.data_size as u64,
            event_count: 1,
            confidence,
        };
        self.graph.add_edge(process_idx, net_idx, edge);

        // Correlate with libraries
        self.correlate_with_libraries(pid, net_idx, event, confidence);

        self.process_connections
            .entry(pid)
            .or_default()
            .push((*event, event.timestamp_ns));

        self.update_queue.push(GraphUpdate::EdgeAdded {
            from: format!("proc:{pid}"),
            to: format!("net:{}:{}", daddr, event.dport),
            edge: RuntimeEdge::NetworkConnection {
                timestamp_ns: event.timestamp_ns,
                total_bytes: event.data_size as u64,
                event_count: 1,
                confidence,
            },
        });
    }

    /// Aggregate network event with existing edge (burst collapsing)
    fn aggregate_network_event(&mut self, pid: u32, event: &NetEvent) {
        let process_idx = self.node_indices.get(&format!("proc:{pid}"));
        if process_idx.is_none() {
            return;
        }

        // IP addresses from eBPF are in network byte order (big-endian)
        let daddr_h = u32::from_be(event.daddr);
        let daddr = format!(
            "{}.{}.{}.{}",
            (daddr_h >> 24) & 0xFF,
            (daddr_h >> 16) & 0xFF,
            (daddr_h >> 8) & 0xFF,
            daddr_h & 0xFF
        );
        let net_idx = self
            .node_indices
            .get(&format!("net:{}:{}", daddr, event.dport));
        if net_idx.is_none() {
            return;
        }

        // Find and update existing edge
        let process_idx = *process_idx.unwrap();
        let net_idx = *net_idx.unwrap();

        // Update edge weight
        if let Some(edge_idx) = self.graph.find_edge(process_idx, net_idx) {
            if let Some(edge) = self.graph.edge_weight_mut(edge_idx) {
                if let RuntimeEdge::NetworkConnection {
                    total_bytes,
                    event_count,
                    confidence,
                    ..
                } = edge
                {
                    *total_bytes += event.data_size as u64;
                    *event_count += 1;
                    // Boost confidence with more events
                    *confidence = (*confidence + 0.05).min(0.95);

                    self.update_queue.push(GraphUpdate::EdgeUpdated {
                        from: format!("proc:{pid}"),
                        to: format!("net:{}:{}", daddr, event.dport),
                        delta_bytes: event.data_size as u64,
                    });
                }
            }
        }
    }

    /// Correlate network activity with loaded libraries
    fn correlate_with_libraries(
        &mut self,
        pid: u32,
        net_idx: NodeIndex,
        event: &NetEvent,
        confidence: f32,
    ) {
        let window_ns = Duration::from_secs(self.config.mmap_window_secs).as_nanos() as u64;
        let event_time = event.timestamp_ns;

        if let Some(libs) = self.process_libraries.get(&pid) {
            for (lib_path, load_time) in libs {
                // Check if within correlation window (long window for mmap)
                if event_time > *load_time && event_time - *load_time < window_ns {
                    let lib_id = format!("lib:{lib_path}");
                    if let Some(&lib_idx) = self.node_indices.get(&lib_id) {
                        let edge = RuntimeEdge::ExploitationAttempt {
                            confidence: confidence * 0.8, // Slightly lower confidence
                            evidence: format!(
                                "Library {} loaded {}s before network activity",
                                lib_path,
                                (event_time - load_time) / 1_000_000_000
                            ),
                        };
                        self.graph.add_edge(lib_idx, net_idx, edge);
                    }
                }
            }
        }
    }

    /// Calculate confidence v2 (graph-aware)
    fn calculate_path_confidence(
        &self,
        nodes: &[RuntimeNode],
        edges: &[(usize, usize, RuntimeEdge)],
        finding: &Finding,
    ) -> f32 {
        let mut confidence = 0.0_f32;

        // Base confidence
        confidence += 0.3;

        // Boost for path depth
        if nodes.len() >= 4 {
            confidence += 0.2;
        } else if nodes.len() >= 3 {
            confidence += 0.1;
        }

        // Boost for complete chain: mmap + network
        let has_mmap = edges
            .iter()
            .any(|(_, _, e)| matches!(e, RuntimeEdge::LibraryLoaded { .. }));
        let has_network = edges
            .iter()
            .any(|(_, _, e)| matches!(e, RuntimeEdge::NetworkConnection { .. }));
        if has_mmap && has_network {
            confidence += 0.2;
        }

        // Boost for KEV
        if finding.signal.kev {
            confidence += 0.15;
        }

        // Boost for high EPSS
        if finding.signal.epss >= 0.7 {
            confidence += 0.1;
        }

        // Penalize sparse signals
        if nodes.len() < 3 {
            confidence -= 0.2;
        }

        // Penalize if only weak signals
        let strong_signals = edges.iter().filter(|(_, _, e)| {
            matches!(e, RuntimeEdge::NetworkConnection { confidence, .. } if *confidence >= 0.9)
        }).count();
        if strong_signals == 0 && !edges.is_empty() {
            confidence -= 0.1;
        }

        confidence.clamp(0.0, 1.0)
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

        // Find matching libraries
        let lib_indices: Vec<_> = self.graph.node_indices().collect();
        for idx in lib_indices {
            if let Some(RuntimeNode::Library { path, .. }) = self.graph.node_weight(idx) {
                if library_matches_package(path, package) {
                    let edge = RuntimeEdge::Vulnerable { confidence: 0.95 };
                    self.graph.add_edge(vuln_idx, idx, edge);
                }
            }
        }

        self.cve_to_library
            .entry(cve_id.to_string())
            .or_default()
            .push(package.to_string());
    }

    /// Build attack paths with top-K ranking
    pub fn build_attack_paths(&mut self, findings: &[Finding]) -> Vec<AttackPath> {
        let mut paths: Vec<AttackPath> = findings
            .iter()
            .filter(|f| f.signal.runtime == RuntimeDisposition::Reachable)
            .map(|finding| self.build_path_for_finding(finding))
            .filter(|p| !p.nodes.is_empty())
            .collect();

        // Sort by confidence and risk
        paths.sort_by(|a, b| {
            let score_a = a.confidence * a.risk_score;
            let score_b = b.confidence * b.risk_score;
            score_b.total_cmp(&score_a)
        });

        // Assign ranks
        for (i, path) in paths.iter_mut().enumerate() {
            path.rank = Some(i + 1);
        }

        // Update metrics
        self.metrics.paths_total += paths.len() as u64;
        self.metrics.high_confidence_paths +=
            paths.iter().filter(|p| p.confidence >= 0.8).count() as u64;

        if !paths.is_empty() {
            let avg_conf = paths.iter().map(|p| p.confidence).sum::<f32>() / paths.len() as f32;
            self.metrics.avg_confidence = (self.metrics.avg_confidence + avg_conf) / 2.0;
        }

        // Return top K
        paths.into_iter().take(self.config.top_k).collect()
    }

    fn build_path_for_finding(&self, finding: &Finding) -> AttackPath {
        let cve_id = &finding.signal.cve;
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut indicators = Vec::new();
        let mut signal_types = Vec::new();
        let mut total_bytes = 0_u64;

        // Start with vulnerability
        let vuln_node = RuntimeNode::Vulnerability(VulnerabilityNode {
            cve_id: cve_id.clone(),
            package: finding.signal.package.clone(),
            cvss: finding.signal.cvss,
            epss: finding.signal.epss,
            kev: finding.signal.kev,
        });
        nodes.push(vuln_node);

        // Build path from vulnerability
        if let Some(&vuln_idx) = self.node_indices.get(&format!("vuln:{cve_id}")) {
            // Get vulnerable libraries
            for edge_ref in self.graph.edges(vuln_idx) {
                if let RuntimeEdge::Vulnerable { .. } = edge_ref.weight() {
                    let lib_idx = edge_ref.target();
                    if let Some(lib_node) = self.graph.node_weight(lib_idx) {
                        nodes.push(lib_node.clone());
                        edges.push((
                            0,
                            nodes.len() - 1,
                            RuntimeEdge::Vulnerable { confidence: 0.95 },
                        ));
                        indicators.push(format!("Vulnerable library: {}", lib_node.node_id()));
                        signal_types.push("vulnerability".to_string());

                        // Get processes using this library. Library loads are stored as process -> library.
                        for proc_edge in self.graph.edges_directed(lib_idx, Direction::Incoming) {
                            if let RuntimeEdge::LibraryLoaded {
                                timestamp_ns,
                                confidence,
                            } = proc_edge.weight()
                            {
                                let proc_idx = proc_edge.source();
                                if let Some(proc_node) = self.graph.node_weight(proc_idx) {
                                    if !nodes.iter().any(|n| n.node_id() == proc_node.node_id()) {
                                        nodes.push(proc_node.clone());
                                        edges.push((
                                            nodes.len() - 2,
                                            nodes.len() - 1,
                                            RuntimeEdge::LibraryLoaded {
                                                timestamp_ns: *timestamp_ns,
                                                confidence: *confidence,
                                            },
                                        ));
                                        signal_types.push("library_loaded".to_string());
                                    }

                                    // Get network connections
                                    for net_edge in self.graph.edges(proc_idx) {
                                        if let RuntimeEdge::NetworkConnection {
                                            timestamp_ns,
                                            total_bytes: bytes,
                                            confidence,
                                            event_count,
                                        } = net_edge.weight()
                                        {
                                            let net_idx = net_edge.target();
                                            if let Some(net_node) = self.graph.node_weight(net_idx)
                                            {
                                                nodes.push(net_node.clone());
                                                edges.push((
                                                    nodes.len() - 2,
                                                    nodes.len() - 1,
                                                    RuntimeEdge::NetworkConnection {
                                                        timestamp_ns: *timestamp_ns,
                                                        total_bytes: *bytes,
                                                        event_count: *event_count,
                                                        confidence: *confidence,
                                                    },
                                                ));
                                                total_bytes += *bytes;
                                                indicators.push(format!(
                                                    "Network: {} bytes to {}",
                                                    bytes,
                                                    net_node.node_id()
                                                ));
                                                signal_types.push("network".to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Calculate confidence v2 (graph-aware)
        let confidence = self.calculate_path_confidence(&nodes, &edges, finding);
        let risk_score = finding.score * (nodes.len() as f32 * 0.2).min(1.0);
        let depth = nodes.len();
        let unique_signal_types: Vec<_> = signal_types
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        AttackPath {
            path_id: format!("path-{}", uuid::Uuid::new_v4()),
            nodes,
            edges,
            confidence,
            risk_score,
            time_window_secs: self.config.mmap_window_secs,
            indicators,
            depth,
            signal_types: unique_signal_types,
            total_bytes,
            rank: None,
        }
    }

    /// Get path summaries with top-K
    pub fn get_top_k_paths(&mut self, findings: &[Finding]) -> Vec<AttackPathSummary> {
        self.build_attack_paths(findings)
            .into_iter()
            .map(|p| p.to_summary())
            .collect()
    }

    /// Get streaming updates
    pub fn drain_updates(&mut self) -> Vec<GraphUpdate> {
        std::mem::take(&mut self.update_queue)
    }

    /// Get metrics
    pub fn metrics(&self) -> &AttackPathMetrics {
        &self.metrics
    }

    /// Get paths that meet enforcement criteria
    pub fn get_enforceable_paths(&self, findings: &[Finding]) -> Vec<AttackPath> {
        findings
            .iter()
            .filter(|f| f.signal.runtime == RuntimeDisposition::Reachable)
            .map(|f| self.build_path_for_finding(f))
            .filter(|p| p.meets_enforcement_criteria(&self.config))
            .collect()
    }

    /// Export to dot format
    pub fn to_dot(&self) -> String {
        use petgraph::dot::{Config, Dot};
        format!(
            "{:?}",
            Dot::with_config(&self.graph, &[Config::EdgeNoLabel])
        )
    }

    /// Get all nodes in the graph
    pub fn nodes(&self) -> Vec<&RuntimeNode> {
        self.graph.node_weights().collect()
    }

    /// Get all edges in the graph
    pub fn edges(&self) -> Vec<(String, String, &RuntimeEdge)> {
        self.graph
            .edge_references()
            .map(|e| {
                let source = self
                    .graph
                    .node_weight(e.source())
                    .map(|n| n.node_id())
                    .unwrap_or_default();
                let target = self
                    .graph
                    .node_weight(e.target())
                    .map(|n| n.node_id())
                    .unwrap_or_default();
                (source, target, e.weight())
            })
            .collect()
    }

    /// Get all attack paths currently in the graph
    pub fn paths(&self) -> &[AttackPath] {
        // Attack paths are computed on-demand via build_attack_paths
        // This returns an empty slice since paths aren't stored
        // Call build_attack_paths() to get paths
        &[]
    }

    /// Get configuration
    pub fn config(&self) -> &AttackGraphConfig {
        &self.config
    }
}

fn library_matches_package(path: &str, package: &str) -> bool {
    let path_lc = path.to_ascii_lowercase();
    let package_lc = package.to_ascii_lowercase();
    let file_name = path_lc.rsplit('/').next().unwrap_or(&path_lc);
    let lib_stem = file_name
        .trim_start_matches("lib")
        .split(".so")
        .next()
        .unwrap_or(file_name);

    path_lc.contains(&package_lc)
        || package_lc.contains(file_name)
        || package_lc.contains(lib_stem)
        || (package_lc == "openssl" && lib_stem == "ssl")
        || (package_lc == "openssl" && lib_stem == "crypto")
}

/// Integration with findings
pub fn attach_attack_paths_to_findings(findings: &mut [Finding], graph: &mut RuntimeAttackGraph) {
    let paths = graph.build_attack_paths(findings);

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
            // Add attack path data to explainability
            finding
                .explainability
                .signals
                .extend(path.indicators.iter().map(|i| SignalEvidence {
                    signal_type: "attack_path".to_string(),
                    timestamp_ns: 0,
                    details: i.clone(),
                    confidence: path.confidence,
                }));

            // Update explainability with attack path context
            let path_summary = path.to_summary();
            finding.explainability.decision = format!(
                "{} + Attack Path (depth={}, confidence={}, rank={:?})",
                finding.explainability.decision,
                path_summary.depth,
                path_summary.confidence,
                path_summary.rank
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scanner_common::{Priority, RiskSignal, RuntimeIdentity};

    #[test]
    fn test_confidence_v2_calculation() {
        let config = AttackGraphConfig::default();
        let mut graph = RuntimeAttackGraph::new(config);

        // Simulate: nginx → libssl → network
        graph.process_library_load(1234, "nginx", 1, "/usr/lib/libssl.so", 1000);

        let net_event = NetEvent {
            timestamp_ns: 2000,
            pid: 1234,
            tgid: 1234,
            cgroup_id: 1,
            saddr: 0,
            daddr: 0x08080808,
            sport: 443,
            dport: 443,
            family: 2,
            protocol: 6,
            kind: EventKind::TcpSend,
            data_size: 1024,
        };

        graph.process_network_event(1234, "nginx", 1, &net_event);
        graph.associate_cve_with_library("CVE-2023-XXXX", "openssl", 9.8, 0.85, true);

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

        // Should have high confidence (mmap + network + KEV)
        assert!(
            paths[0].confidence >= 0.8,
            "Expected high confidence, got {}",
            paths[0].confidence
        );

        // Should have depth >= 3
        assert!(
            paths[0].depth >= 3,
            "Expected depth >= 3, got {}",
            paths[0].depth
        );

        // Should have rank
        assert!(paths[0].rank.is_some());
    }
}
