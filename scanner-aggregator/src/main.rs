//! Central Aggregator Service
//! Collects attack paths from all nodes and builds global attack graph

use axum::{
    extract::{Json, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

/// Global attack path from cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterPath {
    pub cluster_id: String,
    pub node_name: String,
    pub path_id: String,
    pub path_summary: PathSummary,
    pub timestamp: i64,
    pub pod_name: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSummary {
    pub node_types: Vec<String>,
    pub node_count: usize,
    pub confidence: f32,
    pub risk_score: f32,
    pub indicators: Vec<String>,
}

/// Global correlation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalCorrelation {
    pub correlation_id: String,
    pub pattern_type: PatternType,
    pub affected_clusters: Vec<String>,
    pub affected_nodes: Vec<String>,
    pub total_instances: usize,
    pub first_seen: i64,
    pub last_seen: i64,
    pub confidence: f32,
    pub risk_score: f32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    /// Same vulnerability across multiple nodes
    DistributedVulnerability,
    /// Lateral movement pattern
    LateralMovement,
    /// Coordinated attack
    CoordinatedAttack,
    /// Supply chain compromise
    SupplyChainCompromise,
    /// Data exfiltration
    DataExfiltration,
}

/// Federation peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationPeer {
    pub peer_id: String,
    pub endpoint: String,
    pub api_key: Option<String>,
    pub last_sync: Option<i64>,
    pub status: PeerStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PeerStatus {
    Active,
    Inactive,
    Syncing,
    Error,
}

/// Federation sync payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationSync {
    pub source_peer: String,
    pub paths: Vec<ClusterPath>,
    pub correlations: Vec<GlobalCorrelation>,
    pub timestamp: i64,
}

/// Aggregator state
pub struct AggregatorState {
    /// All paths from all clusters
    paths: RwLock<HashMap<String, ClusterPath>>,
    /// Global correlations
    correlations: RwLock<Vec<GlobalCorrelation>>,
    /// Cluster health
    cluster_heartbeat: RwLock<HashMap<String, i64>>,
    /// Federation peers
    federation_peers: RwLock<HashMap<String, FederationPeer>>,
}

impl AggregatorState {
    pub fn new() -> Self {
        Self {
            paths: RwLock::new(HashMap::new()),
            correlations: RwLock::new(Vec::new()),
            cluster_heartbeat: RwLock::new(HashMap::new()),
            federation_peers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a federation peer
    pub async fn register_peer(&self, peer: FederationPeer) {
        let mut peers = self.federation_peers.write().await;
        peers.insert(peer.peer_id.clone(), peer);
    }

    /// Get all federation peers
    pub async fn get_peers(&self) -> Vec<FederationPeer> {
        let peers = self.federation_peers.read().await;
        peers.values().cloned().collect()
    }

    /// Receive federation sync from a peer
    pub async fn receive_federation_sync(&self, sync: FederationSync) {
        info!(
            peer = %sync.source_peer,
            paths = sync.paths.len(),
            correlations = sync.correlations.len(),
            "Received federation sync"
        );

        // Merge paths from peer
        let mut paths = self.paths.write().await;
        for path in sync.paths {
            let key = format!("{}:{}", path.cluster_id, path.path_id);
            paths.insert(key, path);
        }

        // Merge correlations (dedup by correlation_id)
        let mut correlations = self.correlations.write().await;
        for corr in sync.correlations {
            if !correlations.iter().any(|c| c.correlation_id == corr.correlation_id) {
                correlations.push(corr);
            }
        }

        // Update peer last sync time
        let mut peers = self.federation_peers.write().await;
        if let Some(peer) = peers.get_mut(&sync.source_peer) {
            peer.last_sync = Some(chrono::Utc::now().timestamp());
            peer.status = PeerStatus::Active;
        }
    }

    /// Prepare federation sync payload for outgoing sync
    pub async fn prepare_federation_sync(&self, peer_id: &str) -> FederationSync {
        let paths = self.paths.read().await;
        let correlations = self.correlations.read().await;

        FederationSync {
            source_peer: peer_id.to_string(),
            paths: paths.values().cloned().collect(),
            correlations: correlations.clone(),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Add path from a cluster node
    pub async fn add_path(&self, path: ClusterPath) {
        let key = format!("{}:{}", path.cluster_id, path.path_id);
        let mut paths = self.paths.write().await;
        paths.insert(key.clone(), path.clone());

        // Update heartbeat
        let mut heartbeats = self.cluster_heartbeat.write().await;
        heartbeats.insert(path.cluster_id.clone(), chrono::Utc::now().timestamp());

        info!(
            cluster = %path.cluster_id,
            node = %path.node_name,
            path_id = %path.path_id,
            confidence = path.path_summary.confidence,
            "Path received from cluster"
        );

        // Trigger correlation analysis
        drop(paths);
        self.analyze_correlations().await;
    }

    /// Find global patterns
    async fn analyze_correlations(&self) {
        let paths = self.paths.read().await;
        let mut new_correlations = Vec::new();

        // Group by CVE/vulnerability
        let mut vuln_groups: HashMap<String, Vec<&ClusterPath>> = HashMap::new();
        for (_, path) in paths.iter() {
            // Extract CVE from indicators
            for indicator in &path.path_summary.indicators {
                if indicator.contains("CVE-") {
                    let cve = extract_cve(indicator);
                    vuln_groups
                        .entry(cve)
                        .or_default()
                        .push(path);
                }
            }
        }

        // Find distributed vulnerabilities
        for (cve, instances) in vuln_groups.iter() {
            if instances.len() > 1 {
                let clusters: std::collections::HashSet<_> =
                    instances.iter().map(|p| p.cluster_id.clone()).collect();
                let nodes: Vec<_> = instances.iter().map(|p| p.node_name.clone()).collect();

                if clusters.len() > 1 {
                    let correlation = GlobalCorrelation {
                        correlation_id: format!("corr-{}", uuid::Uuid::new_v4()),
                        pattern_type: PatternType::DistributedVulnerability,
                        affected_clusters: clusters.into_iter().collect(),
                        affected_nodes: nodes,
                        total_instances: instances.len(),
                        first_seen: instances.iter().map(|p| p.timestamp).min().unwrap_or(0),
                        last_seen: instances.iter().map(|p| p.timestamp).max().unwrap_or(0),
                        confidence: instances.iter().map(|p| p.path_summary.confidence).sum::<f32>()
                            / instances.len() as f32,
                        risk_score: instances.iter().map(|p| p.path_summary.risk_score).sum::<f32>()
                            / instances.len() as f32,
                        description: format!(
                            "{} affected by {} across {} clusters",
                            instances.len(),
                            cve,
                            clusters.len()
                        ),
                    };

                    new_correlations.push(correlation);

                    warn!(
                        cve = %cve,
                        instances = instances.len(),
                        clusters = clusters.len(),
                        "DISTRIBUTED VULNERABILITY DETECTED"
                    );
                }
            }
        }

        // Store new correlations
        if !new_correlations.is_empty() {
            let mut correlations = self.correlations.write().await;
            *correlations = new_correlations;
        }
    }

    /// Get global stats
    pub async fn get_stats(&self) -> GlobalStats {
        let paths = self.paths.read().await;
        let correlations = self.correlations.read().await;
        let heartbeats = self.cluster_heartbeat.read().await;

        let unique_clusters = paths
            .values()
            .map(|p| p.cluster_id.clone())
            .collect::<std::collections::HashSet<_>>()
            .len();

        let avg_confidence = if paths.is_empty() {
            0.0
        } else {
            paths.values().map(|p| p.path_summary.confidence).sum::<f32>() / paths.len() as f32
        };

        GlobalStats {
            total_paths: paths.len() as u64,
            unique_clusters: unique_clusters as u32,
            active_correlations: correlations.len(),
            avg_confidence,
            healthy_clusters: heartbeats.len() as u32,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GlobalStats {
    pub total_paths: u64,
    pub unique_clusters: u32,
    pub active_correlations: usize,
    pub avg_confidence: f32,
    pub healthy_clusters: u32,
}

fn extract_cve(indicator: &str) -> String {
    // Simple CVE extraction
    if let Some(start) = indicator.find("CVE-") {
        let end = indicator[start..]
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .map(|i| start + i)
            .unwrap_or(indicator.len());
        indicator[start..end].to_string()
    } else {
        "UNKNOWN".to_string()
    }
}

/// API: Receive path from scanner
async fn receive_path(
    State(state): State<Arc<AggregatorState>>,
    Json(path): Json<ClusterPath>,
) -> StatusCode {
    state.add_path(path).await;
    StatusCode::CREATED
}

/// API: Get global correlations
async fn get_correlations(
    State(state): State<Arc<AggregatorState>>,
) -> Json<Vec<GlobalCorrelation>> {
    let correlations = state.correlations.read().await;
    Json(correlations.clone())
}

/// API: Get global stats
async fn get_stats(State(state): State<Arc<AggregatorState>>) -> Json<GlobalStats> {
    Json(state.get_stats().await)
}

/// API: Register federation peer
async fn register_peer(
    State(state): State<Arc<AggregatorState>>,
    Json(peer): Json<FederationPeer>,
) -> StatusCode {
    state.register_peer(peer).await;
    StatusCode::CREATED
}

/// API: Get federation peers
async fn get_peers(
    State(state): State<Arc<AggregatorState>>,
) -> Json<Vec<FederationPeer>> {
    Json(state.get_peers().await)
}

/// API: Receive federation sync
async fn receive_federation_sync(
    State(state): State<Arc<AggregatorState>>,
    Json(sync): Json<FederationSync>,
) -> StatusCode {
    state.receive_federation_sync(sync).await;
    StatusCode::OK
}

/// API: Health check
async fn health() -> &'static str {
    "OK"
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = Arc::new(AggregatorState::new());

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/paths", post(receive_path))
        .route("/api/correlations", get(get_correlations))
        .route("/api/stats", get(get_stats))
        .route("/api/federation/peers", get(get_peers).post(register_peer))
        .route("/api/federation/sync", post(receive_federation_sync))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = "0.0.0.0:8080";
    info!("Central Aggregator starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
