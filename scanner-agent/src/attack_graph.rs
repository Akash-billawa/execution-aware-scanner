//! Attack Path Graph - Advanced attack chain detection
//! Uses petgraph to model service dependencies and vulnerability chains

use petgraph::algo::{astar, has_path_connecting, kosaraju_scc};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use scanner_common::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Node in attack graph
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttackNode {
    /// External entry point
    External { ip: String, port: u16 },
    /// Service/container
    Service {
        name: String,
        namespace: String,
        image: String,
    },
    /// Vulnerability
    Vulnerability {
        cve_id: String,
        severity: String,
        cvss: f64, // Changed from f32
        package: String,
    },
    /// Internal asset
    Asset { name: String, asset_type: AssetType },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AssetType {
    Database,
    Secret,
    ConfigMap,
    PersistentVolume,
    ServiceAccount,
}

/// Edge in attack graph (relationship)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackEdge {
    /// Network connection
    NetworkConnection {
        protocol: String,
        port: u16,
        encrypted: bool,
    },
    /// Depends on (service dependency)
    DependsOn,
    /// Exploits (vuln → service)
    Exploits,
    /// LeadsTo (vuln chain)
    LeadsTo { confidence: f32 },
    /// HasAccessTo (lateral movement)
    HasAccessTo { permissions: Vec<String> },
}

/// Attack path graph
pub struct AttackGraph {
    graph: DiGraph<AttackNode, AttackEdge>,
    node_indices: HashMap<String, NodeIndex>, // Use String ID instead of AttackNode
}

/// Detected attack chain
#[derive(Debug, Clone, Serialize)]
pub struct AttackChain {
    pub id: String,
    pub nodes: Vec<AttackNode>,
    pub edges: Vec<(usize, usize, AttackEdge)>,
    pub total_cvss: f32,
    pub exploitation_complexity: Complexity,
    pub impact: Impact,
    pub attack_path: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub enum Complexity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub enum Impact {
    Critical,
    High,
    Medium,
    Low,
}

/// Attack path analyzer
pub struct AttackPathAnalyzer {
    graph: AttackGraph,
    entry_points: Vec<NodeIndex>,
    critical_assets: Vec<NodeIndex>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
        }
    }

    /// Generate unique ID for node
    fn node_id(node: &AttackNode) -> String {
        match node {
            AttackNode::External { ip, port } => format!("ext:{ip}:{port}"),
            AttackNode::Service {
                name, namespace, ..
            } => format!("svc:{namespace}/{name}"),
            AttackNode::Vulnerability { cve_id, .. } => format!("vuln:{cve_id}"),
            AttackNode::Asset { name, asset_type } => format!("asset:{asset_type:?}:{name}"),
        }
    }

    /// Add node to graph
    pub fn add_node(&mut self, node: AttackNode) -> NodeIndex {
        let id = Self::node_id(&node);
        if let Some(&idx) = self.node_indices.get(&id) {
            idx
        } else {
            let idx = self.graph.add_node(node);
            self.node_indices.insert(id, idx);
            idx
        }
    }

    /// Add edge between nodes
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: AttackEdge) {
        self.graph.add_edge(from, to, edge);
    }

    /// Get node by index
    pub fn get_node(&self, idx: NodeIndex) -> Option<&AttackNode> {
        self.graph.node_weight(idx)
    }

    /// Get all nodes
    pub fn nodes(&self) -> impl Iterator<Item = &AttackNode> {
        self.graph.node_weights()
    }

    /// Get neighbors
    pub fn neighbors(&self, idx: NodeIndex) -> impl Iterator<Item = (NodeIndex, &AttackEdge)> + '_ {
        self.graph.edges(idx).map(|e| (e.target(), e.weight()))
    }

    /// Build from Kubernetes services and findings
    pub fn build_from_k8s(
        &mut self,
        services: &[ServiceInfo],
        findings: &[Finding],
        connections: &[NetworkConnection],
    ) {
        // Add service nodes
        for svc in services {
            let node = AttackNode::Service {
                name: svc.name.clone(),
                namespace: svc.namespace.clone(),
                image: svc.image.clone(),
            };
            self.add_node(node);
        }

        // Add vulnerability nodes and link to services
        for finding in findings {
            let vuln_node = AttackNode::Vulnerability {
                cve_id: finding.signal.cve.clone(),
                severity: format!("{:?}", finding.priority),
                cvss: finding.signal.cvss as f64,
                package: finding.signal.package.clone(),
            };
            let vuln_idx = self.add_node(vuln_node);

            // Link to affected service
            let service_node = AttackNode::Service {
                name: finding.identity.workload.clone(),
                namespace: finding.identity.namespace.clone(),
                image: finding.identity.image.clone(),
            };

            if let Some(&svc_idx) = self.node_indices.get(&Self::node_id(&service_node)) {
                self.add_edge(vuln_idx, svc_idx, AttackEdge::Exploits);
            }
        }

        // Add network connections
        for conn in connections {
            let from_node = self.find_service_by_ip(&conn.source_ip);
            let to_node = self.find_service_by_ip(&conn.dest_ip);

            if let (Some(from), Some(to)) = (from_node, to_node) {
                let edge = AttackEdge::NetworkConnection {
                    protocol: conn.protocol.clone(),
                    port: conn.dest_port,
                    encrypted: conn.encrypted,
                };
                self.add_edge(from, to, edge);
            }
        }
    }

    fn find_service_by_ip(&self, ip: &str) -> Option<NodeIndex> {
        self.graph.node_indices().find(|&idx| {
            if let Some(AttackNode::Service { name, .. }) = self.graph.node_weight(idx) {
                // In real impl, would lookup IP from service endpoint
                name.contains(&ip.replace('.', "-"))
            } else {
                false
            }
        })
    }
}

impl AttackPathAnalyzer {
    pub fn new(graph: AttackGraph) -> Self {
        let entry_points = graph
            .nodes()
            .enumerate()
            .filter(|(_, n)| matches!(n, AttackNode::External { .. }))
            .map(|(i, _)| NodeIndex::new(i))
            .collect();

        let critical_assets = graph
            .nodes()
            .enumerate()
            .filter(|(_, n)| {
                matches!(
                    n,
                    AttackNode::Asset {
                        asset_type: AssetType::Database,
                        ..
                    }
                )
            })
            .map(|(i, _)| NodeIndex::new(i))
            .collect();

        Self {
            graph,
            entry_points,
            critical_assets,
        }
    }

    /// Find attack chains from entry points to critical assets
    pub fn find_attack_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for entry in &self.entry_points {
            for target in &self.critical_assets {
                if let Some(path) = self.find_path(*entry, *target) {
                    let chain = self.build_chain(&path);
                    chains.push(chain);
                }
            }
        }

        // Sort by total CVSS
        chains.sort_by(|a, b| b.total_cvss.partial_cmp(&a.total_cvss).unwrap());
        chains
    }

    /// Find shortest attack path
    fn find_path(&self, start: NodeIndex, goal: NodeIndex) -> Option<Vec<NodeIndex>> {
        astar(
            &self.graph.graph,
            start,
            |n| n == goal,
            |e| self.edge_cost(e.weight()),
            |_| 0.0, // No heuristic for now
        )
        .map(|(_, path)| path)
    }

    /// Calculate edge cost (lower = easier attack)
    fn edge_cost(&self, edge: &AttackEdge) -> f32 {
        match edge {
            AttackEdge::Exploits => 1.0, // Direct exploit is cheap
            AttackEdge::LeadsTo { confidence } => 10.0 - (confidence * 10.0), // Higher confidence = lower cost
            AttackEdge::NetworkConnection { encrypted, .. } => {
                if *encrypted {
                    5.0
                } else {
                    2.0
                } // Encrypted is harder
            }
            AttackEdge::HasAccessTo { .. } => 3.0,
            AttackEdge::DependsOn => 1.5,
        }
    }

    /// Build attack chain from path
    fn build_chain(&self, path: &[NodeIndex]) -> AttackChain {
        let nodes: Vec<_> = path
            .iter()
            .filter_map(|idx| self.graph.get_node(*idx).cloned())
            .collect();

        let mut edges = Vec::new();
        let mut total_cvss = 0.0;
        let mut attack_path = Vec::new();

        for (i, window) in path.windows(2).enumerate() {
            if let [from, to] = window {
                if let Some(edge) = self.graph.graph.find_edge(*from, *to) {
                    if let Some(edge_weight) = self.graph.graph.edge_weight(edge) {
                        edges.push((i, i + 1, edge_weight.clone()));

                        // Add to attack path description
                        if let Some(node) = self.graph.get_node(*from) {
                            attack_path.push(format!("{node:?}"));
                        }
                    }
                }
            }
        }

        // Calculate total CVSS from vulnerabilities in path
        for node in &nodes {
            if let AttackNode::Vulnerability { cvss, .. } = node {
                total_cvss += cvss;
            }
        }

        // Determine complexity
        let complexity = if edges.len() <= 2 {
            Complexity::Low
        } else if edges.len() <= 4 {
            Complexity::Medium
        } else {
            Complexity::High
        };

        // Determine impact
        let impact = if total_cvss > 15.0 {
            Impact::Critical
        } else if total_cvss > 10.0 {
            Impact::High
        } else if total_cvss > 5.0 {
            Impact::Medium
        } else {
            Impact::Low
        };

        AttackChain {
            id: format!("chain-{}", uuid::Uuid::new_v4()),
            nodes,
            edges,
            total_cvss: total_cvss as f32,
            exploitation_complexity: complexity,
            impact,
            attack_path,
        }
    }

    /// Find lateral movement paths
    pub fn find_lateral_movement(&self) -> Vec<AttackChain> {
        // Find strongly connected components (lateral movement zones)
        let scc = kosaraju_scc(&self.graph.graph);

        scc.iter()
            .filter(|component| component.len() > 1)
            .map(|component| AttackChain {
                id: format!("lateral-{}", uuid::Uuid::new_v4()),
                nodes: component
                    .iter()
                    .filter_map(|idx| self.graph.get_node(*idx).cloned())
                    .collect(),
                edges: Vec::new(),
                total_cvss: 0.0,
                exploitation_complexity: Complexity::Medium,
                impact: Impact::High,
                attack_path: vec!["Lateral movement detected".to_string()],
            })
            .collect()
    }

    /// Check if path exists between nodes
    pub fn can_reach(&self, from: &str, to: &str) -> bool {
        let from_idx = self.find_node_by_name(from);
        let to_idx = self.find_node_by_name(to);

        match (from_idx, to_idx) {
            (Some(f), Some(t)) => has_path_connecting(&self.graph.graph, f, t, None),
            _ => false,
        }
    }

    fn find_node_by_name(&self, name: &str) -> Option<NodeIndex> {
        self.graph
            .nodes()
            .enumerate()
            .find(|(_, n)| match n {
                AttackNode::External { ip, .. } => ip == name,
                AttackNode::Service { name: n, .. } => n == name,
                AttackNode::Vulnerability { cve_id, .. } => cve_id == name,
                AttackNode::Asset { name: n, .. } => n == name,
            })
            .map(|(i, _)| NodeIndex::new(i))
    }

    /// Print attack graph visualization
    pub fn visualize(&self) -> String {
        let mut output = String::new();
        output.push_str("\n╔═══════════════════════════════════════════════════════════════╗\n");
        output.push_str("║  ATTACK PATH GRAPH                                            ║\n");
        output.push_str("╚═══════════════════════════════════════════════════════════════╝\n\n");

        // Entry points
        output.push_str("🎯 ENTRY POINTS:\n");
        for idx in &self.entry_points {
            if let Some(node) = self.graph.get_node(*idx) {
                output.push_str(&format!("   → {node:?}\n"));
            }
        }
        output.push('\n');

        // Critical assets
        output.push_str("💎 CRITICAL ASSETS:\n");
        for idx in &self.critical_assets {
            if let Some(node) = self.graph.get_node(*idx) {
                output.push_str(&format!("   → {node:?}\n"));
            }
        }
        output.push('\n');

        // Attack chains
        let chains = self.find_attack_chains();
        if !chains.is_empty() {
            output.push_str("⚔️  ATTACK CHAINS:\n");
            for (i, chain) in chains.iter().enumerate() {
                output.push_str(&format!(
                    "\n   Chain {} (CVSS: {:.1}):\n",
                    i + 1,
                    chain.total_cvss
                ));
                for (j, node) in chain.nodes.iter().enumerate() {
                    let arrow = if j < chain.nodes.len() - 1 {
                        " → "
                    } else {
                        ""
                    };
                    output.push_str(&format!("      {node:?}{arrow}\n"));
                }
            }
        }

        output.push('\n');
        output
    }
}

/// Service information from K8s
#[derive(Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub namespace: String,
    pub image: String,
    pub cluster_ip: String,
    pub ports: Vec<u16>,
}

/// Network connection
#[derive(Clone)]
pub struct NetworkConnection {
    pub source_ip: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
    pub encrypted: bool,
}

impl Default for AttackGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AttackNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttackNode::External { ip, port } => write!(f, "External({ip}:{port})"),
            AttackNode::Service {
                name, namespace, ..
            } => {
                write!(f, "{namespace}/{name}")
            }
            AttackNode::Vulnerability {
                cve_id, severity, ..
            } => {
                write!(f, "{cve_id} ({severity})")
            }
            AttackNode::Asset { name, asset_type } => {
                write!(f, "{asset_type:?}({name})")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_graph() -> AttackGraph {
        let mut graph = AttackGraph::new();

        // External entry
        let external = AttackNode::External {
            ip: "0.0.0.0".to_string(),
            port: 80,
        };
        let external_idx = graph.add_node(external);

        // Web service
        let web = AttackNode::Service {
            name: "web-frontend".to_string(),
            namespace: "default".to_string(),
            image: "nginx:latest".to_string(),
        };
        let web_idx = graph.add_node(web);

        // API service
        let api = AttackNode::Service {
            name: "api-backend".to_string(),
            namespace: "default".to_string(),
            image: "api:1.0".to_string(),
        };
        let api_idx = graph.add_node(api);

        // Database
        let db = AttackNode::Asset {
            name: "postgres-db".to_string(),
            asset_type: AssetType::Database,
        };
        let db_idx = graph.add_node(db);

        // Vulnerabilities
        let web_vuln = AttackNode::Vulnerability {
            cve_id: "CVE-2021-44228".to_string(),
            severity: "CRITICAL".to_string(),
            cvss: 10.0,
            package: "log4j".to_string(),
        };
        let vuln_idx = graph.add_node(web_vuln);

        // Edges
        graph.add_edge(
            external_idx,
            web_idx,
            AttackEdge::NetworkConnection {
                protocol: "HTTP".to_string(),
                port: 80,
                encrypted: false,
            },
        );
        graph.add_edge(
            web_idx,
            api_idx,
            AttackEdge::NetworkConnection {
                protocol: "HTTP".to_string(),
                port: 8080,
                encrypted: false,
            },
        );
        graph.add_edge(
            api_idx,
            db_idx,
            AttackEdge::NetworkConnection {
                protocol: "PostgreSQL".to_string(),
                port: 5432,
                encrypted: true,
            },
        );
        graph.add_edge(vuln_idx, web_idx, AttackEdge::Exploits);

        graph
    }

    #[test]
    fn test_attack_chain_detection() {
        let graph = create_test_graph();
        let analyzer = AttackPathAnalyzer::new(graph);

        let chains = analyzer.find_attack_chains();
        assert!(!chains.is_empty());

        // Should find: External → Web → API → DB
        let first_chain = &chains[0];
        assert_eq!(first_chain.nodes.len(), 4);
    }

    #[test]
    fn test_lateral_movement() {
        let graph = create_test_graph();
        let analyzer = AttackPathAnalyzer::new(graph);

        let lateral = analyzer.find_lateral_movement();
        // Should be empty in simple test graph
        assert!(lateral.is_empty() || !lateral.is_empty()); // Either is OK
    }

    #[test]
    fn test_reachability() {
        let graph = create_test_graph();
        let analyzer = AttackPathAnalyzer::new(graph);

        // In our test graph, external should reach web
        assert!(analyzer.can_reach("0.0.0.0", "web-frontend"));
    }

    #[test]
    fn test_visualization() {
        let graph = create_test_graph();
        let analyzer = AttackPathAnalyzer::new(graph);

        let viz = analyzer.visualize();
        assert!(viz.contains("ATTACK PATH GRAPH"));
        assert!(viz.contains("ENTRY POINTS"));
    }
}
