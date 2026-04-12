//! Visualization module for attack path graph export
//!
//! Supports:
//! - JSON export for D3.js visualization
//! - DOT format for Graphviz
//! - Grafana node-graph plugin format
//!
//! Example output:
//! {
//!   "nodes": [
//!     {"id": "proc:1234:nginx", "type": "process", "label": "nginx (PID 1234)"},
//!     {"id": "lib:/usr/lib/libssl.so", "type": "library", "label": "libssl.so"},
//!     {"id": "vuln:CVE-2023-XXXX", "type": "cve", "label": "CVE-2023-XXXX (CVSS 9.8)"}
//!   ],
//!   "edges": [
//!     {"from": "proc:1234:nginx", "to": "lib:/usr/lib/libssl.so", "type": "mmap"},
//!     {"from": "lib:/usr/lib/libssl.so", "to": "vuln:CVE-2023-XXXX", "type": "vulnerable"}
//!   ]
//! }

use crate::runtime_attack_graph_v2::{AttackPath, RuntimeAttackGraph, RuntimeEdge, RuntimeNode};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// Graph format for export
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphFormat {
    Json,
    Dot,
    Grafana,
}

impl std::str::FromStr for GraphFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(GraphFormat::Json),
            "dot" => Ok(GraphFormat::Dot),
            "grafana" => Ok(GraphFormat::Grafana),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }
}

/// Export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    pub format: GraphFormat,
    pub include_metrics: bool,
    pub include_paths: bool,
    pub max_nodes: Option<usize>,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            format: GraphFormat::Json,
            include_metrics: true,
            include_paths: true,
            max_nodes: None,
        }
    }
}

/// Generic graph export structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphExport {
    pub metadata: GraphMetadata,
    pub nodes: Vec<ExportNode>,
    pub edges: Vec<ExportEdge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<ExportedPath>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<GraphMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphMetadata {
    pub exported_at: String,
    pub total_nodes: usize,
    pub total_edges: usize,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportNode {
    pub id: String,
    pub node_type: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub style: Option<NodeStyle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStyle {
    pub color: String,
    pub size: u32,
    pub icon: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEdge {
    pub from: String,
    pub to: String,
    pub edge_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub style: Option<EdgeStyle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeStyle {
    pub width: f32,
    pub color: String,
    pub style: String, // solid, dashed, dotted
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedPath {
    pub path_id: String,
    pub nodes: Vec<String>,
    pub confidence: f32,
    pub risk_score: f32,
    pub depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphMetrics {
    pub total_paths: u64,
    pub high_confidence_paths: u64,
    pub avg_confidence: f32,
}

/// Visualization exporter
pub struct GraphExporter;

impl GraphExporter {
    /// Export attack graph to JSON format
    pub fn export_json(
        graph: &RuntimeAttackGraph,
        paths: &[AttackPath],
        config: &ExportConfig,
    ) -> String {
        let export = Self::build_export(graph, paths, config);
        serde_json::to_string_pretty(&export).unwrap_or_default()
    }

    /// Export to DOT format for Graphviz
    pub fn export_dot(graph: &RuntimeAttackGraph, paths: &[AttackPath]) -> String {
        let mut dot = String::new();
        dot.push_str("digraph AttackGraph {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box, style=\"rounded,filled\", fontname=\"Arial\"];\n\n");

        // Add nodes with colors based on type
        for node in Self::extract_nodes_from_graph(graph) {
            let color = match node.node_type.as_str() {
                "process" => "lightblue",
                "library" => "lightgreen",
                "vulnerability" => "salmon",
                "network" => "lightyellow",
                _ => "white",
            };

            dot.push_str(&format!(
                "  \"{}\" [label=\"{}\", fillcolor={}];\n",
                node.id, node.label, color
            ));
        }

        dot.push_str("\n");

        // Add edges
        for edge in Self::extract_edges_from_graph(graph) {
            let style = if edge.edge_type == "exploitation" {
                " [color=red, penwidth=2]"
            } else {
                ""
            };

            dot.push_str(&format!(
                "  \"{}\" -> \"{}\"{};\n",
                edge.from, edge.to, style
            ));
        }

        // Highlight critical paths
        for path in paths.iter().filter(|p| p.confidence >= 0.8) {
            dot.push_str(&format!(
                "\n  // Path: {} (confidence: {:.2})\n",
                path.path_id, path.confidence
            ));
        }

        dot.push_str("}\n");
        dot
    }

    /// Extract nodes from graph (public version)
    pub fn extract_nodes(graph: &RuntimeAttackGraph) -> Vec<ExportNode> {
        Self::extract_nodes_from_graph(graph)
    }

    /// Extract edges from graph (public version)
    pub fn extract_edges(graph: &RuntimeAttackGraph) -> Vec<ExportEdge> {
        Self::extract_edges_from_graph(graph)
    }

    /// Export to Grafana node graph format
    pub fn export_grafana(graph: &RuntimeAttackGraph, paths: &[AttackPath]) -> String {
        let mut nodes: Vec<serde_json::Value> = Vec::new();
        let mut edges: Vec<serde_json::Value> = Vec::new();

        // Grafana format expects specific fields
        for node in Self::extract_nodes(graph) {
            nodes.push(serde_json::json!({
                "id": node.id,
                "title": node.label,
                "mainStat": node.node_type,
                "color": Self::node_color(&node.node_type),
                "icon": Self::node_icon(&node.node_type),
            }));
        }

        for edge in Self::extract_edges(graph) {
            edges.push(serde_json::json!({
                "source": edge.from,
                "target": edge.to,
                "mainStat": edge.edge_type,
            }));
        }

        let output = serde_json::json!({
            "nodes": nodes,
            "edges": edges,
        });

        serde_json::to_string_pretty(&output).unwrap_or_default()
    }

    /// Build generic export structure
    fn build_export(
        _graph: &RuntimeAttackGraph,
        paths: &[AttackPath],
        config: &ExportConfig,
    ) -> GraphExport {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut node_ids = std::collections::HashSet::new();
        let mut edge_pairs = std::collections::HashSet::new();

        // Build from attack paths
        for path in paths {
            // Add nodes
            for (i, node) in path.nodes.iter().enumerate() {
                let node_id = node.node_id();

                if !node_ids.contains(&node_id) {
                    node_ids.insert(node_id.clone());

                    let (node_type, label, color, icon) = match node {
                        RuntimeNode::Process { pid, name, .. } => (
                            "process",
                            format!("{} (PID {})", name, pid),
                            "#3498db",
                            "process",
                        ),
                        RuntimeNode::Library { path, .. } => {
                            let name = path.split('/').last().unwrap_or(path);
                            ("library", name.to_string(), "#2ecc71", "library")
                        }
                        RuntimeNode::Network { ip, port, .. } => (
                            "network",
                            format!("{}:{}", ip, port),
                            "#f39c12",
                            "globe",
                        ),
                        RuntimeNode::Vulnerability(v) => (
                            "vulnerability",
                            format!("{} (CVSS {:.1})", v.cve_id, v.cvss),
                            "#e74c3c",
                            "alert",
                        ),
                        RuntimeNode::Technique { name, .. } => (
                            "technique",
                            name.clone(),
                            "#9b59b6",
                            "gear",
                        ),
                    };

                    nodes.push(ExportNode {
                        id: node_id.clone(),
                        node_type: node_type.to_string(),
                        label,
                        properties: None,
                        style: Some(NodeStyle {
                            color: color.to_string(),
                            size: if i == 0 { 40 } else { 30 },
                            icon: icon.to_string(),
                        }),
                    });
                }
            }

            // Add edges
            for (from_idx, to_idx, edge) in &path.edges {
                if let (Some(from_node), Some(to_node)) =
                    (path.nodes.get(*from_idx), path.nodes.get(*to_idx))
                {
                    let from_id = from_node.node_id();
                    let to_id = to_node.node_id();
                    let edge_key = (from_id.clone(), to_id.clone());

                    if !edge_pairs.contains(&edge_key) {
                        edge_pairs.insert(edge_key);

                    let (edge_type, label, width, color): (&str, String, f32, &str) = match edge {
                        RuntimeEdge::LibraryLoaded { .. } => {
                            ("mmap", "loaded".to_string(), 1.0, "#95a5a6")
                        }
                        RuntimeEdge::Vulnerable { confidence } => {
                            ("vulnerable", "vulnerable".to_string(), *confidence, "#e74c3c")
                        }
                        RuntimeEdge::NetworkConnection { total_bytes, .. } => (
                            "network",
                            format!("{} bytes", total_bytes),
                            1.5,
                            "#3498db",
                        ),
                        RuntimeEdge::ExploitationAttempt { evidence, .. } => {
                            ("exploitation", evidence.clone(), 2.0, "#e74c3c")
                        }
                        RuntimeEdge::UsesTechnique { .. } => {
                            ("technique", "uses".to_string(), 1.0, "#9b59b6")
                        }
                    };

                        edges.push(ExportEdge {
                            from: from_id,
                            to: to_id,
                            edge_type: edge_type.to_string(),
                            label: Some(label.to_string()),
                            properties: None,
                            style: Some(EdgeStyle {
                                width,
                                color: color.to_string(),
                                style: "solid".to_string(),
                            }),
                        });
                    }
                }
            }
        }

        // Build exported paths
        let exported_paths = if config.include_paths {
            Some(
                paths
                    .iter()
                    .map(|p| ExportedPath {
                        path_id: p.path_id.clone(),
                        nodes: p.nodes.iter().map(|n| n.node_id()).collect(),
                        confidence: p.confidence,
                        risk_score: p.risk_score,
                        depth: p.depth,
                    })
                    .collect(),
            )
        } else {
            None
        };

        // Build metrics
        let metrics = if config.include_metrics {
            let high_conf = paths.iter().filter(|p| p.confidence >= 0.8).count() as u64;
            let avg_conf = if paths.is_empty() {
                0.0
            } else {
                paths.iter().map(|p| p.confidence).sum::<f32>() / paths.len() as f32
            };

            Some(GraphMetrics {
                total_paths: paths.len() as u64,
                high_confidence_paths: high_conf,
                avg_confidence: avg_conf,
            })
        } else {
            None
        };

        GraphExport {
            metadata: GraphMetadata {
                exported_at: Utc::now().to_rfc3339(),
                total_nodes: nodes.len(),
                total_edges: edges.len(),
                version: "2.0".to_string(),
            },
            nodes,
            edges,
            paths: exported_paths,
            metrics,
        }
    }

    /// Extract nodes from graph
    fn extract_nodes_from_graph(graph: &RuntimeAttackGraph) -> Vec<ExportNode> {
        let mut export_nodes = Vec::new();

        for node in graph.nodes() {
            let node_id = node.node_id();
            let node_type = node.node_type().to_string();

            let label = match node {
                RuntimeNode::Process { pid, name, .. } => {
                    format!("{} (PID {})", name, pid)
                }
                RuntimeNode::Library { path, cve_ids } => {
                    let name = path.split('/').last().unwrap_or(path);
                    let cve_str = if cve_ids.is_empty() {
                        "".to_string()
                    } else {
                        format!(" [{}]", cve_ids.join(", "))
                    };
                    format!("{}{}", name, cve_str)
                }
                RuntimeNode::Network { ip, port, protocol } => {
                    format!("{} {}:{}", protocol, ip, port)
                }
                RuntimeNode::Vulnerability(v) => {
                    format!("{} (CVSS {:.1})", v.cve_id, v.cvss)
                }
                RuntimeNode::Technique { name, .. } => {
                    name.clone()
                }
            };

            export_nodes.push(ExportNode {
                id: node_id,
                node_type,
                label,
                properties: None,
                style: None,
            });
        }

        export_nodes
    }

    /// Extract edges from graph
    fn extract_edges_from_graph(graph: &RuntimeAttackGraph) -> Vec<ExportEdge> {
        let mut export_edges = Vec::new();

        for (from, to, edge) in graph.edges() {
            let (edge_type, label): (&str, String) = match edge {
                RuntimeEdge::LibraryLoaded { .. } => ("mmap", "loaded".to_string()),
                RuntimeEdge::Vulnerable { .. } => ("vulnerable", "vulnerable".to_string()),
                RuntimeEdge::NetworkConnection { total_bytes, .. } => {
                    ("network", format!("{} bytes", total_bytes))
                }
                RuntimeEdge::ExploitationAttempt { evidence, .. } => {
                    ("exploitation", evidence.clone())
                }
                RuntimeEdge::UsesTechnique { .. } => ("technique", "uses".to_string()),
            };

            export_edges.push(ExportEdge {
                from,
                to,
                edge_type: edge_type.to_string(),
                label: Some(label),
                properties: None,
                style: None,
            });
        }

        export_edges
    }

    /// Get node color for Grafana
    fn node_color(node_type: &str) -> &'static str {
        match node_type {
            "process" => "blue",
            "library" => "green",
            "vulnerability" => "red",
            "network" => "yellow",
            _ => "gray",
        }
    }

    /// Get node icon for Grafana
    fn node_icon(node_type: &str) -> &'static str {
        match node_type {
            "process" => "process",
            "library" => "library",
            "vulnerability" => "alert",
            "network" => "globe",
            _ => "circle",
        }
    }

    /// Export to file
    pub async fn export_to_file(
        graph: &RuntimeAttackGraph,
        paths: &[AttackPath],
        output_path: &str,
        config: &ExportConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = match config.format {
            GraphFormat::Json => Self::export_json(graph, paths, config),
            GraphFormat::Dot => Self::export_dot(graph, paths),
            GraphFormat::Grafana => Self::export_grafana(graph, paths),
        };

        tokio::fs::write(output_path, content).await?;
        info!(path = output_path, format = ?config.format, "Graph exported successfully");

        Ok(())
    }
}

/// Example D3.js visualization HTML template
pub fn d3_template() -> &'static str {
    "<!DOCTYPE html>
<html>
<head>
    <title>Attack Path Visualization</title>
    <script src='https://d3js.org/d3.v7.min.js'></script>
    <style>
        body { margin: 0; font-family: Arial, sans-serif; }
        #graph { width: 100vw; height: 100vh; }
        .node { cursor: pointer; }
        .link { stroke: #999; stroke-opacity: 0.6; }
        text { font-size: 12px; pointer-events: none; }
    </style>
</head>
<body>
    <div id='graph'></div>
    <script>
        d3.json('graph.json').then(function(data) {
            const width = window.innerWidth;
            const height = window.innerHeight;
            const svg = d3.select('#graph').append('svg')
                .attr('width', width).attr('height', height);
            const simulation = d3.forceSimulation(data.nodes)
                .force('link', d3.forceLink(data.edges).id(d => d.id).distance(100))
                .force('charge', d3.forceManyBody().strength(-300))
                .force('center', d3.forceCenter(width / 2, height / 2));
            const link = svg.append('g').selectAll('line')
                .data(data.edges).enter().append('line')
                .attr('class', 'link').attr('stroke-width', 1);
            const node = svg.append('g').selectAll('circle')
                .data(data.nodes).enter().append('circle')
                .attr('class', 'node').attr('r', 15).attr('fill', '#69b3a2');
            const label = svg.append('g').selectAll('text')
                .data(data.nodes).enter().append('text')
                .text(d => d.label).attr('dx', 20).attr('dy', 4);
            simulation.on('tick', () => {
                link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
                node.attr('cx', d => d.x).attr('cy', d => d.y);
                label.attr('x', d => d.x).attr('y', d => d.y);
            });
        });
    </script>
</body>
</html>"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_format_parsing() {
        assert!(matches!("json".parse::<GraphFormat>().unwrap(), GraphFormat::Json));
        assert!(matches!("dot".parse::<GraphFormat>().unwrap(), GraphFormat::Dot));
        assert!("invalid".parse::<GraphFormat>().is_err());
    }
}
