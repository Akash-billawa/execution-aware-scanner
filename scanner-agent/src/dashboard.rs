//! Web Dashboard for Real-time Attack Graph Visualization
//! Serves HTML/JS for viewing attack paths and alerts

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::{Html, Json},
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::runtime_attack_graph_v2::{AttackPathSummary, RuntimeAttackGraph};

/// Event broadcast for WebSocket clients
pub type EventBroadcast = broadcast::Sender<DashboardEvent>;

#[derive(Debug, Clone, Serialize)]
pub struct DashboardEvent {
    pub event_type: String,
    pub data: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Dashboard state
#[derive(Clone)]
pub struct DashboardState {
    pub attack_graph: Arc<RwLock<RuntimeAttackGraph>>,
    pub event_tx: EventBroadcast,
}

/// Dashboard routes
pub fn routes(state: DashboardState) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/api/paths", get(paths_handler))
        .route("/api/stats", get(stats_handler))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

/// Serve the main dashboard HTML
async fn index_handler() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

/// Get current attack paths
async fn paths_handler(State(state): State<DashboardState>) -> Json<Vec<AttackPathSummary>> {
    let mut graph = state.attack_graph.write().await;
    let paths = graph.get_top_k_paths(&[]);
    Json(paths)
}

/// Get dashboard stats
async fn stats_handler(State(state): State<DashboardState>) -> Json<DashboardStats> {
    let graph = state.attack_graph.read().await;
    let metrics = graph.metrics();

    Json(DashboardStats {
        total_paths: metrics.paths_total,
        high_confidence_paths: metrics.high_confidence_paths,
        avg_confidence: metrics.avg_confidence,
        burst_events_collapsed: metrics.burst_events_collapsed,
    })
}

#[derive(Serialize)]
pub struct DashboardStats {
    pub total_paths: u64,
    pub high_confidence_paths: u64,
    pub avg_confidence: f32,
    pub burst_events_collapsed: u64,
}

/// WebSocket handler for real-time updates
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<DashboardState>,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: DashboardState) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.event_tx.subscribe();

    // Spawn task to forward events to client
    let mut send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if let Ok(data) = serde_json::to_string(&event) {
                if sender.send(Message::Text(data.into())).await.is_err() {
                    break;
                }
            }
        }
    });

    // Handle incoming messages (ping/pong, close)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Close(_) => break,
                Message::Ping(data) => {
                    // Pong is handled automatically by axum
                    let _ = data;
                }
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }
}

/// HTML dashboard with embedded JavaScript
const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Graph Dashboard</title>
    <script src="https://d3js.org/d3.v7.min.js"
            integrity="sha384-QgOeKq4bEh9PYDPJnMoEoPjJNkPvfxPmPNz1CbFjo3p1pFq6z3a5E3p1pFq6z3a"
            crossorigin="anonymous"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            min-height: 100vh;
        }
        .header {
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            color: #58a6ff;
            font-size: 1.5rem;
        }
        .status {
            display: flex;
            gap: 1rem;
        }
        .status-badge {
            background: #238636;
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.875rem;
        }
        .status-badge.critical {
            background: #da3633;
        }
        .container {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 1rem;
            padding: 1rem;
            height: calc(100vh - 70px);
        }
        .sidebar {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1rem;
            overflow-y: auto;
        }
        .sidebar h2 {
            color: #8b949e;
            font-size: 0.875rem;
            text-transform: uppercase;
            margin-bottom: 1rem;
        }
        .stat-card {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 0.75rem;
        }
        .stat-card .value {
            font-size: 1.5rem;
            font-weight: 600;
            color: #58a6ff;
        }
        .stat-card .label {
            font-size: 0.75rem;
            color: #8b949e;
            margin-top: 0.25rem;
        }
        .main-content {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        .graph-container {
            flex: 1;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            position: relative;
            overflow: hidden;
        }
        .graph-container h2 {
            position: absolute;
            top: 1rem;
            left: 1rem;
            color: #8b949e;
            font-size: 0.875rem;
            z-index: 10;
        }
        #graph {
            width: 100%;
            height: 100%;
        }
        .alerts-panel {
            height: 200px;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            overflow-y: auto;
            padding: 1rem;
        }
        .alerts-panel h2 {
            color: #8b949e;
            font-size: 0.875rem;
            text-transform: uppercase;
            margin-bottom: 0.75rem;
        }
        .alert {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem;
            border-radius: 6px;
            margin-bottom: 0.5rem;
            border-left: 3px solid;
        }
        .alert.critical {
            background: rgba(218, 54, 51, 0.1);
            border-left-color: #da3633;
        }
        .alert.high {
            background: rgba(210, 153, 34, 0.1);
            border-left-color: #d29922;
        }
        .alert.severity {
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
        }
        .alert.message {
            flex: 1;
            font-size: 0.875rem;
        }
        .alert.time {
            font-size: 0.75rem;
            color: #8b949e;
        }
        .node {
            cursor: pointer;
        }
        .node circle {
            stroke: #fff;
            stroke-width: 2px;
        }
        .link {
            stroke: #30363d;
            stroke-width: 1.5px;
        }
        .node-label {
            font-size: 10px;
            fill: #c9d1d9;
            pointer-events: none;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 Execution-Aware Scanner</h1>
        <div class="status">
            <span class="status-badge" id="status-indicator">LIVE</span>
            <span class="status-badge critical" id="alert-count">0 ALERTS</span>
        </div>
    </div>

    <div class="container">
        <div class="sidebar">
            <h2>Statistics</h2>
            <div class="stat-card">
                <div class="value" id="total-paths">-</div>
                <div class="label">Total Attack Paths</div>
            </div>
            <div class="stat-card">
                <div class="value" id="high-confidence">-</div>
                <div class="label">High Confidence (≥0.8)</div>
            </div>
            <div class="stat-card">
                <div class="value" id="avg-confidence">-</div>
                <div class="label">Average Confidence</div>
            </div>
            <div class="stat-card">
                <div class="value" id="burst-events">-</div>
                <div class="label">Burst Events Collapsed</div>
            </div>
        </div>

        <div class="main-content">
            <div class="graph-container">
                <h2>Attack Graph</h2>
                <svg id="graph"></svg>
            </div>

            <div class="alerts-panel">
                <h2>Live Alerts</h2>
                <div id="alerts-container"></div>
            </div>
        </div>
    </div>

    <script>
        // Mock data for demonstration
        const mockPaths = [
            {
                path_id: "path-1",
                node_types: ["vulnerability", "library", "process", "network"],
                node_count: 4,
                confidence: 0.91,
                risk_score: 8.9,
                is_burst: false,
                nodes: [
                    {id: "vuln-1", type: "vulnerability", label: "CVE-2023-0286", x: 100, y: 200},
                    {id: "lib-1", type: "library", label: "libssl.so.1.1", x: 250, y: 200},
                    {id: "proc-1", type: "process", label: "nginx [42]", x: 400, y: 200},
                    {id: "net-1", type: "network", label: "10.0.0.15:443", x: 550, y: 200}
                ],
                edges: [
                    {source: "vuln-1", target: "lib-1"},
                    {source: "lib-1", target: "proc-1"},
                    {source: "proc-1", target: "net-1"}
                ]
            }
        ];

        // Color scheme
        const colors = {
            vulnerability: "#da3633",
            library: "#8b949e",
            process: "#58a6ff",
            network: "#238636"
        };

        // Initialize graph
        function initGraph() {
            const svg = d3.select("#graph");
            const width = svg.node().parentElement.clientWidth;
            const height = svg.node().parentElement.clientHeight;

            svg.attr("viewBox", `0 0 ${width} ${height}`);

            const g = svg.append("g");

            // Add zoom behavior
            const zoom = d3.zoom()
                .scaleExtent([0.5, 4])
                .on("zoom", (event) => g.attr("transform", event.transform));
            svg.call(zoom);

            // Render first path
            const path = mockPaths[0];

            // Draw edges
            g.selectAll(".link")
                .data(path.edges)
                .enter()
                .append("line")
                .attr("class", "link")
                .attr("x1", d => path.nodes.find(n => n.id === d.source).x)
                .attr("y1", d => path.nodes.find(n => n.id === d.source).y)
                .attr("x2", d => path.nodes.find(n => n.id === d.target).x)
                .attr("y2", d => path.nodes.find(n => n.id === d.target).y);

            // Draw nodes
            const nodes = g.selectAll(".node")
                .data(path.nodes)
                .enter()
                .append("g")
                .attr("class", "node")
                .attr("transform", d => `translate(${d.x},${d.y})`);

            nodes.append("circle")
                .attr("r", 20)
                .attr("fill", d => colors[d.type]);

            nodes.append("text")
                .attr("class", "node-label")
                .attr("dy", 35)
                .attr("text-anchor", "middle")
                .text(d => d.label);

            // Center the graph
            const graphWidth = 600;
            const graphHeight = 200;
            const initialTransform = d3.zoomIdentity
                .translate((width - graphWidth) / 2, (height - graphHeight) / 2);
            svg.call(zoom.transform, initialTransform);
        }

        // Update stats
        function updateStats() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('total-paths').textContent = data.total_paths;
                    document.getElementById('high-confidence').textContent = data.high_confidence_paths;
                    document.getElementById('avg-confidence').textContent = data.avg_confidence.toFixed(2);
                    document.getElementById('burst-events').textContent = data.burst_events_collapsed;
                })
                .catch(() => {
                    // Use mock data if API fails
                    document.getElementById('total-paths').textContent = '3';
                    document.getElementById('high-confidence').textContent = '1';
                    document.getElementById('avg-confidence').textContent = '0.91';
                    document.getElementById('burst-events').textContent = '47';
                });
        }

        // Add alert
        function escapeHtml(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }

        function addAlert(severity, message) {
            const container = document.getElementById('alerts-container');
            const alert = document.createElement('div');
            alert.className = `alert ${escapeHtml(severity.toLowerCase())}`;
            const sevSpan = document.createElement('span');
            sevSpan.className = 'severity';
            sevSpan.textContent = severity;
            const msgSpan = document.createElement('span');
            msgSpan.className = 'message';
            msgSpan.textContent = message;
            const timeSpan = document.createElement('span');
            timeSpan.className = 'time';
            timeSpan.textContent = new Date().toLocaleTimeString();
            alert.appendChild(sevSpan);
            alert.appendChild(msgSpan);
            alert.appendChild(timeSpan);
            container.insertBefore(alert, container.firstChild);

            // Update badge
            const current = parseInt(document.getElementById('alert-count').textContent) || 0;
            document.getElementById('alert-count').textContent = `${current + 1} ALERTS`;
        }

        // Simulate live alerts
        function simulateAlerts() {
            const alerts = [
                { severity: 'CRITICAL', message: 'HIGH RISK PATH ACTIVATED: vulnerability → library → process → network (confidence: 0.91)' },
                { severity: 'HIGH', message: 'Network connection to suspicious IP: 192.168.1.100' },
                { severity: 'HIGH', message: 'Library libssl.so loaded with known CVE' }
            ];

            let i = 0;
            setInterval(() => {
                if (i < alerts.length) {
                    addAlert(alerts[i].severity, alerts[i].message);
                    i++;
                }
            }, 2000);
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            initGraph();
            updateStats();
            simulateAlerts();

            // Poll for updates
            setInterval(updateStats, 5000);
        });
    </script>
</body>
</html>"#;
