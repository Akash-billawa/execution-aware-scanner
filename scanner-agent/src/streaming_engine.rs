//! Real-time Streaming Engine
//! Continuously updates attack paths as signals arrive with event bus architecture
//!
//! Architecture:
//! eBPF Events → Event Bus (mpsc channel) → Streaming Engine → Attack Graph Updates → Output
//!
//! Features:
//! - Trigger-based alerts (confidence thresholds)
//! - Burst collapsing (deduplication)
//! - JSON streaming output
//! - Event bus for decoupled processing

use crate::runtime_attack_graph_v2::{AttackPath, GraphUpdate, RuntimeAttackGraph};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration, Instant};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Configuration for streaming mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingConfig {
    /// Output interval in milliseconds
    pub output_interval_ms: u64,
    /// Confidence threshold for alerts (0.0-1.0)
    pub alert_threshold: f32,
    /// Risk escalation threshold
    pub risk_escalation_threshold: f32,
    /// Channel buffer size
    pub channel_buffer_size: usize,
    /// Enable JSON output to stdout
    pub stream_json: bool,
    /// Top K paths to emit
    pub top_k: usize,
    /// Export graph snapshots
    pub export_graph: bool,
    /// Graph export interval in seconds
    pub graph_export_interval_secs: u64,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            output_interval_ms: 1000,
            alert_threshold: 0.8,
            risk_escalation_threshold: 0.7,
            channel_buffer_size: 1000,
            stream_json: true,
            top_k: 3,
            export_graph: true,
            graph_export_interval_secs: 60,
        }
    }
}

/// Event types flowing through the event bus
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// New eBPF event from kernel
    BpfEvent {
        timestamp_ns: u64,
        kind: String,
        details: String,
    },
    /// Attack graph update
    GraphUpdate(GraphUpdate),
    /// New path detected
    PathDetected(AttackPath),
    /// Confidence changed
    ConfidenceChanged { path_id: String, old: f32, new: f32 },
    /// Risk escalation
    RiskEscalated { path_id: String, risk_delta: f32 },
    /// Shutdown signal
    Shutdown,
}

/// Streaming output format (JSON)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StreamingOutput {
    /// Path updated with new confidence
    #[serde(rename = "PathUpdated")]
    PathUpdated {
        path_id: String,
        confidence: f32,
        delta: String,
        trigger: String,
        timestamp: i64,
        risk_score: f32,
    },
    /// New path detected
    #[serde(rename = "PathDetected")]
    PathDetected {
        path_id: String,
        confidence: f32,
        nodes: Vec<String>,
        trigger: String,
        timestamp: i64,
        risk_score: f32,
    },
    /// Alert triggered
    #[serde(rename = "Alert")]
    Alert {
        severity: AlertSeverity,
        path_id: String,
        message: String,
        confidence: f32,
        timestamp: i64,
        indicators: Vec<String>,
    },
    /// Graph snapshot exported
    #[serde(rename = "GraphExported")]
    GraphExported {
        path: String,
        node_count: usize,
        edge_count: usize,
        timestamp: i64,
    },
    /// Stats update
    #[serde(rename = "Stats")]
    Stats {
        total_paths: u64,
        high_confidence_paths: u64,
        avg_confidence: f32,
        events_processed: u64,
        timestamp: i64,
    },
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// State tracking for streaming engine
struct StreamingState {
    /// Known paths and their confidence
    path_confidence: HashMap<String, f32>,
    /// Known paths and their risk
    path_risk: HashMap<String, f32>,
    /// Events processed count
    events_processed: u64,
    /// Last alert timestamp per path
    last_alert: HashMap<String, Instant>,
    /// Cooldown between alerts
    alert_cooldown: Duration,
}

impl StreamingState {
    fn new() -> Self {
        Self {
            path_confidence: HashMap::new(),
            path_risk: HashMap::new(),
            events_processed: 0,
            last_alert: HashMap::new(),
            alert_cooldown: Duration::from_secs(30),
        }
    }

    /// Check if we should alert on this confidence change
    fn should_alert(&mut self, path_id: &str, new_confidence: f32) -> bool {
        let old_confidence = self.path_confidence.get(path_id).copied().unwrap_or(0.0);

        // Only alert if crossing threshold
        let should_alert = old_confidence < 0.8 && new_confidence >= 0.8;

        // Check cooldown
        if should_alert {
            if let Some(&last_time) = self.last_alert.get(path_id) {
                if Instant::now().duration_since(last_time) < self.alert_cooldown {
                    return false;
                }
            }
            self.last_alert.insert(path_id.to_string(), Instant::now());
        }

        self.path_confidence
            .insert(path_id.to_string(), new_confidence);
        should_alert
    }

    /// Check for risk escalation
    fn check_escalation(&mut self, path_id: &str, new_risk: f32) -> Option<f32> {
        let old_risk = self.path_risk.get(path_id).copied().unwrap_or(0.0);
        let delta = new_risk - old_risk;

        self.path_risk.insert(path_id.to_string(), new_risk);

        // Report if risk increased significantly
        if delta > 0.2 {
            Some(delta)
        } else {
            None
        }
    }
}

/// Real-time streaming engine
pub struct StreamingEngine {
    /// Event bus sender
    event_tx: mpsc::Sender<StreamEvent>,
    /// Shared attack graph
    attack_graph: Arc<RwLock<RuntimeAttackGraph>>,
    /// Configuration
    config: StreamingConfig,
    /// State
    state: Arc<RwLock<StreamingState>>,
    /// Webhook manager for alerts
    webhook_manager: Option<Arc<crate::webhook_sender::WebhookManager>>,
    /// Scanner ID
    scanner_id: String,
}

impl StreamingEngine {
    /// Create new streaming engine with event bus
    pub fn new(
        attack_graph: Arc<RwLock<RuntimeAttackGraph>>,
        config: StreamingConfig,
    ) -> (Self, mpsc::Receiver<StreamEvent>) {
        let (event_tx, event_rx) = mpsc::channel(config.channel_buffer_size);

        let engine = Self {
            event_tx,
            attack_graph,
            config,
            state: Arc::new(RwLock::new(StreamingState::new())),
            webhook_manager: None,
            scanner_id: format!("scanner-{}", Uuid::new_v4()),
        };

        (engine, event_rx)
    }

    /// Create streaming engine with webhook support
    pub fn with_webhooks(
        attack_graph: Arc<RwLock<RuntimeAttackGraph>>,
        config: StreamingConfig,
        webhook_manager: Arc<crate::webhook_sender::WebhookManager>,
    ) -> (Self, mpsc::Receiver<StreamEvent>) {
        let (event_tx, event_rx) = mpsc::channel(config.channel_buffer_size);

        let engine = Self {
            event_tx,
            attack_graph,
            config,
            state: Arc::new(RwLock::new(StreamingState::new())),
            webhook_manager: Some(webhook_manager),
            scanner_id: format!("scanner-{}", Uuid::new_v4()),
        };

        (engine, event_rx)
    }

    /// Get event sender for external components
    pub fn sender(&self) -> mpsc::Sender<StreamEvent> {
        self.event_tx.clone()
    }

    /// Start the streaming engine
    pub async fn run(&self, mut event_rx: mpsc::Receiver<StreamEvent>) {
        info!("Starting real-time streaming engine");
        info!("Alert threshold: {:.2}", self.config.alert_threshold);
        info!("Output interval: {}ms", self.config.output_interval_ms);

        let mut output_ticker = interval(Duration::from_millis(self.config.output_interval_ms));

        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    if let StreamEvent::Shutdown = event {
                        info!("Streaming engine shutting down");
                        break;
                    }
                    self.process_event(event).await;
                }
                _ = output_ticker.tick() => {
                    self.emit_stats().await;
                }
            }
        }
    }

    /// Process incoming event
    async fn process_event(&self, event: StreamEvent) {
        let mut state = self.state.write().await;
        state.events_processed += 1;

        match event {
            StreamEvent::GraphUpdate(update) => {
                self.handle_graph_update(update).await;
            }
            StreamEvent::PathDetected(path) => {
                self.handle_path_detected(path, &mut state).await;
            }
            StreamEvent::ConfidenceChanged { path_id, old, new } => {
                self.handle_confidence_change(&path_id, old, new, &mut state)
                    .await;
            }
            StreamEvent::RiskEscalated {
                path_id,
                risk_delta,
            } => {
                self.handle_risk_escalation(&path_id, risk_delta).await;
            }
            StreamEvent::BpfEvent {
                timestamp_ns,
                kind,
                details,
            } => {
                debug!(
                    timestamp = timestamp_ns,
                    kind = kind,
                    details = details,
                    "BPF event received"
                );
            }
            StreamEvent::Shutdown => {}
        }
    }

    /// Handle graph update
    async fn handle_graph_update(&self, update: GraphUpdate) {
        match &update {
            GraphUpdate::EdgeAdded { from, to, edge } => {
                debug!(from = from, to = to, "Edge added to attack graph");

                if self.config.stream_json {
                    // Example live flow output
                    if from.starts_with("proc:") && to.starts_with("lib:") {
                        println!("[STREAM] mmap → {}", to.strip_prefix("lib:").unwrap_or(to));
                    } else if from.starts_with("proc:") && to.starts_with("net:") {
                        println!("[STREAM] Network connection detected: {}", to);
                    }
                }
            }
            GraphUpdate::EdgeUpdated {
                from,
                to,
                delta_bytes,
            } => {
                debug!(
                    from = from,
                    to = to,
                    delta = delta_bytes,
                    "Edge updated (burst collapsing)"
                );

                if self.config.stream_json && *delta_bytes > 1024 {
                    println!("[STREAM] Data transfer: +{} bytes", delta_bytes);
                }
            }
            GraphUpdate::ConfidenceChanged { cve_id, old, new } => {
                debug!(cve = cve_id, old = old, new = new, "Confidence updated");
            }
            GraphUpdate::NewPath { path } => {
                debug!(
                    path_id = path.path_id,
                    confidence = path.confidence,
                    "New attack path detected"
                );
            }
        }
    }

    /// Handle new path detected
    async fn handle_path_detected(&self, path: AttackPath, state: &mut StreamingState) {
        let path_summary = path.to_summary();
        let node_names: Vec<String> = path.nodes.iter().map(|n| n.node_id()).collect();

        // Build trigger string
        let trigger = path.signal_types.join(" + ");

        // Update state
        state
            .path_confidence
            .insert(path.path_id.clone(), path.confidence);
        state
            .path_risk
            .insert(path.path_id.clone(), path.risk_score);

        // Emit PathDetected
        if self.config.stream_json {
            let output = StreamingOutput::PathDetected {
                path_id: path.path_id.clone(),
                confidence: path.confidence,
                nodes: node_names,
                trigger: trigger.clone(),
                timestamp: Utc::now().timestamp(),
                risk_score: path.risk_score,
            };
            println!("{}", serde_json::to_string(&output).unwrap());
        }

        // Check for alert
        if path.confidence >= self.config.alert_threshold {
            let severity = if path.confidence >= 0.9 {
                AlertSeverity::Critical
            } else if path.confidence >= 0.8 {
                AlertSeverity::High
            } else {
                AlertSeverity::Medium
            };

            let output = StreamingOutput::Alert {
                severity: severity.clone(),
                path_id: path.path_id.clone(),
                message: format!(
                    "HIGH RISK PATH ACTIVATED: {} (confidence: {:.2})",
                    path_summary.node_types.join(" → "),
                    path.confidence
                ),
                confidence: path.confidence,
                timestamp: Utc::now().timestamp(),
                indicators: path.indicators.clone(),
            };

            if self.config.stream_json {
                println!("{}", serde_json::to_string(&output).unwrap());
            }

            info!(
                path_id = path.path_id,
                confidence = path.confidence,
                "HIGH RISK PATH ACTIVATED"
            );

            // Send webhook alert
            if let Some(ref manager) = self.webhook_manager {
                use crate::webhook_sender::create_alert_payload;
                let payload = create_alert_payload(&path, None, &self.scanner_id);
                manager.send_alert(&path.path_id, &payload).await;
            }
        }
    }

    /// Handle confidence change
    async fn handle_confidence_change(
        &self,
        path_id: &str,
        old: f32,
        new: f32,
        state: &mut StreamingState,
    ) {
        let delta = new - old;
        let delta_str = format!("{:+.2}", delta);

        // Emit PathUpdated
        if self.config.stream_json {
            let output = StreamingOutput::PathUpdated {
                path_id: path_id.to_string(),
                confidence: new,
                delta: delta_str,
                trigger: "signal accumulation".to_string(),
                timestamp: Utc::now().timestamp(),
                risk_score: 0.0,
            };
            println!("{}", serde_json::to_string(&output).unwrap());

            // Live confidence update
            if delta.abs() > 0.1 {
                println!("[UPDATE] Path confidence {:.2} → {:.2}", old, new);
            }
        }

        // Check for threshold crossing
        if state.should_alert(path_id, new) {
            let severity = if new >= 0.9 {
                AlertSeverity::Critical
            } else {
                AlertSeverity::High
            };

            let output = StreamingOutput::Alert {
                severity,
                path_id: path_id.to_string(),
                message: format!("CONFIDENCE THRESHOLD CROSSED: {:.2} → {:.2}", old, new),
                confidence: new,
                timestamp: Utc::now().timestamp(),
                indicators: vec!["confidence_threshold_crossed".to_string()],
            };

            if self.config.stream_json {
                println!("{}", serde_json::to_string(&output).unwrap());
            }

            info!(
                path_id = path_id,
                old = old,
                new = new,
                "🚨 CONFIDENCE THRESHOLD CROSSED"
            );
        }
    }

    /// Handle risk escalation
    async fn handle_risk_escalation(&self, path_id: &str, risk_delta: f32) {
        warn!(
            path_id = path_id,
            delta = risk_delta,
            "RISK ESCALATION DETECTED"
        );

        if self.config.stream_json {
            println!(
                "[ALERT] Risk escalation for {}: +{:.2}",
                path_id, risk_delta
            );
        }
    }

    /// Emit periodic stats
    async fn emit_stats(&self) {
        let graph = self.attack_graph.read().await;
        let metrics = graph.metrics();

        let output = StreamingOutput::Stats {
            total_paths: metrics.paths_total,
            high_confidence_paths: metrics.high_confidence_paths,
            avg_confidence: metrics.avg_confidence,
            events_processed: self.state.read().await.events_processed,
            timestamp: Utc::now().timestamp(),
        };

        if self.config.stream_json {
            println!("{}", serde_json::to_string(&output).unwrap());
        }

        debug!(
            paths = metrics.paths_total,
            high_confidence = metrics.high_confidence_paths,
            avg_confidence = metrics.avg_confidence,
            "Streaming stats"
        );
    }

    /// Export graph to JSON for visualization
    pub async fn export_graph(
        &self,
        output_path: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let graph = self.attack_graph.read().await;
        let snapshot = GraphSnapshot::from_graph(&graph);

        let json = serde_json::to_string_pretty(&snapshot)?;
        tokio::fs::write(output_path, json).await?;

        info!(path = output_path, "Graph snapshot exported");

        if self.config.stream_json {
            let output = StreamingOutput::GraphExported {
                path: output_path.to_string(),
                node_count: snapshot.nodes.len(),
                edge_count: snapshot.edges.len(),
                timestamp: Utc::now().timestamp(),
            };
            println!("{}", serde_json::to_string(&output).unwrap());
        }

        Ok(())
    }
}

/// Graph snapshot for visualization export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub metadata: GraphMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub node_type: String,
    pub label: String,
    pub properties: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub edge_type: String,
    pub properties: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphMetadata {
    pub exported_at: i64,
    pub total_nodes: usize,
    pub total_edges: usize,
}

impl GraphSnapshot {
    pub fn from_graph(graph: &RuntimeAttackGraph) -> Self {
        // This would need to expose graph internals
        // For now, return empty placeholder
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            metadata: GraphMetadata {
                exported_at: Utc::now().timestamp(),
                total_nodes: 0,
                total_edges: 0,
            },
        }
    }
}

/// Helper to run streaming mode from main
pub async fn run_streaming_mode(
    attack_graph: Arc<RwLock<RuntimeAttackGraph>>,
    config: StreamingConfig,
) {
    let (engine, event_rx) = StreamingEngine::new(attack_graph, config.clone());

    // Spawn graph export task if enabled
    if config.export_graph {
        let engine_clone = StreamingEngine {
            event_tx: engine.sender(),
            attack_graph: engine.attack_graph.clone(),
            config: config.clone(),
            state: engine.state.clone(),
            webhook_manager: None,
            scanner_id: "scanner".to_string(),
        };

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(config.graph_export_interval_secs));
            let mut counter = 0;

            loop {
                ticker.tick().await;
                counter += 1;
                let path = format!("graph-snapshot-{}.json", counter);
                if let Err(e) = engine_clone.export_graph(&path).await {
                    warn!(error = %e, "Failed to export graph");
                }
            }
        });
    }

    // Run the streaming engine
    engine.run(event_rx).await;
}

/// Helper to run streaming mode with webhook support
pub async fn run_streaming_mode_with_webhooks(
    attack_graph: Arc<RwLock<RuntimeAttackGraph>>,
    config: StreamingConfig,
    webhook_manager: Arc<crate::webhook_sender::WebhookManager>,
) {
    let (engine, event_rx) =
        StreamingEngine::with_webhooks(attack_graph, config.clone(), webhook_manager);

    // Spawn graph export task if enabled
    if config.export_graph {
        let engine_clone = StreamingEngine {
            event_tx: engine.sender(),
            attack_graph: engine.attack_graph.clone(),
            config: config.clone(),
            state: engine.state.clone(),
            webhook_manager: engine.webhook_manager.clone(),
            scanner_id: engine.scanner_id.clone(),
        };

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(config.graph_export_interval_secs));
            let mut counter = 0;

            loop {
                ticker.tick().await;
                counter += 1;
                let path = format!("graph-snapshot-{}.json", counter);
                if let Err(e) = engine_clone.export_graph(&path).await {
                    warn!(error = %e, "Failed to export graph");
                }
            }
        });
    }

    // Run the streaming engine
    engine.run(event_rx).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streaming_output_serialization() {
        let output = StreamingOutput::PathUpdated {
            path_id: "path-123".to_string(),
            confidence: 0.88,
            delta: "+0.12".to_string(),
            trigger: "ssl_write + tcp_send".to_string(),
            timestamp: 1710000000,
            risk_score: 8.5,
        };

        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("PathUpdated"));
        assert!(json.contains("path-123"));
        assert!(json.contains("0.88"));
    }

    #[test]
    fn test_streaming_state() {
        let mut state = StreamingState::new();

        // Should alert when crossing threshold
        assert!(state.should_alert("path-1", 0.85));

        // Should not alert for same path within cooldown
        assert!(!state.should_alert("path-1", 0.90));

        // Different path should alert
        assert!(state.should_alert("path-2", 0.85));
    }
}
