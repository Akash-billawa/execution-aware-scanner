//! Webhook and SIEM Integration Module
//!
//! Sends alerts to external systems via webhooks:
//! - Generic webhook endpoints
//! - Elastic (HTTP input)
//! - Splunk (HEC)
//! - Slack
//!
//! Features:
//! - Rate limiting and deduplication
//! - Retry with exponential backoff
//! - Alert policies
//! - Multiple output formats

use crate::runtime_attack_graph_v2::AttackPath;
use chrono::Utc;
use reqwest::Client;
use scanner_common::{Finding, Priority};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Configuration for webhook integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,
    /// Webhook type
    pub webhook_type: WebhookType,
    /// Authentication
    pub auth: WebhookAuth,
    /// Rate limit (events per minute)
    pub rate_limit: u32,
    /// Minimum severity to send
    pub min_severity: SeverityFilter,
    /// Alert mode
    pub alert_mode: AlertMode,
    /// Timeout seconds
    pub timeout_secs: u64,
    /// Retry attempts
    pub retry_attempts: u32,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            webhook_type: WebhookType::Generic,
            auth: WebhookAuth::None,
            rate_limit: 60,
            min_severity: SeverityFilter::High,
            alert_mode: AlertMode::OnAlertOnly,
            timeout_secs: 30,
            retry_attempts: 3,
        }
    }
}

/// Webhook destination type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookType {
    Generic,
    Elastic,
    Splunk,
    Slack,
    Teams,
    Datadog,
    Custom(String),
}

/// Authentication methods
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebhookAuth {
    None,
    Bearer { token: String },
    Basic { username: String, password: String },
    ApiKey { header: String, key: String },
}

/// Severity filter
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum SeverityFilter {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SeverityFilter {
    fn rank(&self) -> u8 {
        match self {
            SeverityFilter::Info => 0,
            SeverityFilter::Low => 1,
            SeverityFilter::Medium => 2,
            SeverityFilter::High => 3,
            SeverityFilter::Critical => 4,
        }
    }
}

impl PartialOrd for SeverityFilter {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SeverityFilter {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl From<&Priority> for SeverityFilter {
    fn from(p: &Priority) -> Self {
        match p {
            Priority::Critical => SeverityFilter::Critical,
            Priority::High => SeverityFilter::High,
            Priority::Medium => SeverityFilter::Medium,
            Priority::Low => SeverityFilter::Low,
            Priority::Informational => SeverityFilter::Low,
        }
    }
}

/// Alert mode
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertMode {
    OnAlertOnly,  // Only when confidence crosses threshold
    OnUpdate,     // On any path update
    OnEveryEvent, // Debug mode - every event
}

/// Unified alert payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPayload {
    /// Event type
    pub event_type: String,
    /// Severity level
    pub severity: String,
    /// Confidence score
    pub confidence: f32,
    /// Risk score
    pub risk_score: f32,
    /// CVE identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    /// Process name
    pub process: String,
    /// Attack path chain
    pub attack_path: Vec<String>,
    /// Signal types
    pub signals: Vec<String>,
    /// Timestamp
    pub timestamp: i64,
    /// Scanner metadata
    pub metadata: AlertMetadata,
    /// Additional context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertMetadata {
    pub scanner_version: String,
    pub scanner_id: String,
    pub node_name: String,
    pub namespace: String,
    pub pod_name: String,
}

/// Rate limiting and deduplication state
struct RateLimiter {
    /// Last sent time per path_id
    last_sent: HashMap<String, Instant>,
    /// Cooldown duration
    cooldown: Duration,
    /// Event counter for rate limiting
    event_count: HashMap<String, u32>,
    /// Rate limit window
    rate_window: Duration,
}

impl RateLimiter {
    fn new(cooldown_secs: u64) -> Self {
        Self {
            last_sent: HashMap::new(),
            cooldown: Duration::from_secs(cooldown_secs),
            event_count: HashMap::new(),
            rate_window: Duration::from_secs(60),
        }
    }

    /// Check if we can send alert for this path
    fn should_send(&mut self, path_id: &str) -> bool {
        let now = Instant::now();

        if let Some(&last_time) = self.last_sent.get(path_id) {
            if now.duration_since(last_time) < self.cooldown {
                return false;
            }
        }

        self.last_sent.insert(path_id.to_string(), now);
        true
    }

    /// Check rate limit
    fn check_rate_limit(&mut self, webhook_id: &str, limit: u32) -> bool {
        let count = self.event_count.entry(webhook_id.to_string()).or_insert(0);
        *count += 1;
        *count <= limit
    }

    /// Reset rate counters
    fn reset_counters(&mut self) {
        self.event_count.clear();
    }
}

/// Webhook sender with retry logic
pub struct WebhookSender {
    client: Client,
    config: WebhookConfig,
    rate_limiter: Arc<RwLock<RateLimiter>>,
    webhook_id: String,
}

impl WebhookSender {
    pub fn new(config: WebhookConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to build HTTP client");

        let webhook_id = format!("{:?}_{}", config.webhook_type, config.url);

        Self {
            client,
            config,
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(60))),
            webhook_id,
        }
    }

    /// Send alert payload
    pub async fn send_alert(
        &self,
        payload: &AlertPayload,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check severity filter
        let severity: SeverityFilter = match payload.severity.as_str() {
            "CRITICAL" => SeverityFilter::Critical,
            "HIGH" => SeverityFilter::High,
            "MEDIUM" => SeverityFilter::Medium,
            "LOW" => SeverityFilter::Low,
            _ => SeverityFilter::Info,
        };

        if severity < self.config.min_severity {
            debug!("Alert severity below threshold, skipping");
            return Ok(());
        }

        // Check rate limit
        let mut limiter = self.rate_limiter.write().await;
        if !limiter.check_rate_limit(&self.webhook_id, self.config.rate_limit) {
            warn!("Rate limit exceeded for webhook: {}", self.config.url);
            return Ok(());
        }
        drop(limiter);

        // Format payload for target
        let formatted_payload = self.format_payload(payload);

        // Send with retry
        self.send_with_retry(&formatted_payload).await
    }

    /// Format payload for target webhook type
    fn format_payload(&self, payload: &AlertPayload) -> serde_json::Value {
        match self.config.webhook_type {
            WebhookType::Generic => serde_json::to_value(payload).unwrap_or_default(),
            WebhookType::Elastic => self.format_elastic(payload),
            WebhookType::Splunk => self.format_splunk(payload),
            WebhookType::Slack => self.format_slack(payload),
            WebhookType::Teams => self.format_teams(payload),
            WebhookType::Datadog => self.format_datadog(payload),
            WebhookType::Custom(_) => serde_json::to_value(payload).unwrap_or_default(),
        }
    }

    /// Format for Elastic
    fn format_elastic(&self, payload: &AlertPayload) -> serde_json::Value {
        serde_json::json!({
            "@timestamp": chrono::Utc::now().to_rfc3339(),
            "event": {
                "category": "threat",
                "type": "attack_path",
                "severity": payload.severity.to_lowercase(),
                "confidence": payload.confidence,
            },
            "threat": {
                "cve": payload.cve,
                "risk_score": payload.risk_score,
                "attack_path": payload.attack_path,
                "signals": payload.signals,
            },
            "process": {
                "name": payload.process,
            },
            "scanner": {
                "version": payload.metadata.scanner_version,
                "id": payload.metadata.scanner_id,
                "node": payload.metadata.node_name,
            }
        })
    }

    /// Format for Splunk HEC
    fn format_splunk(&self, payload: &AlertPayload) -> serde_json::Value {
        serde_json::json!({
            "time": Utc::now().timestamp(),
            "event": payload,
            "sourcetype": "vulnerability_scanner",
            "index": "security",
        })
    }

    /// Format for Slack
    fn format_slack(&self, payload: &AlertPayload) -> serde_json::Value {
        let emoji = match payload.severity.as_str() {
            "CRITICAL" => "🚨",
            "HIGH" => "⚠️",
            "MEDIUM" => "⚡",
            _ => "ℹ️",
        };

        let color = match payload.severity.as_str() {
            "CRITICAL" => "#FF0000",
            "HIGH" => "#FF8800",
            "MEDIUM" => "#FFCC00",
            _ => "#00CC00",
        };

        let path_str = payload.attack_path.join(" → ");
        let signals_str = payload.signals.join(" + ");

        serde_json::json!({
            "text": format!("{} {} CVE ACTIVE", emoji, payload.severity),
            "attachments": [{
                "color": color,
                "fields": [
                    {
                        "title": "CVE",
                        "value": payload.cve.as_deref().unwrap_or("N/A"),
                        "short": true
                    },
                    {
                        "title": "Confidence",
                        "value": format!("{:.2}", payload.confidence),
                        "short": true
                    },
                    {
                        "title": "Risk Score",
                        "value": format!("{:.1}", payload.risk_score),
                        "short": true
                    },
                    {
                        "title": "Process",
                        "value": &payload.process,
                        "short": true
                    },
                    {
                        "title": "Attack Path",
                        "value": path_str,
                        "short": false
                    },
                    {
                        "title": "Signals",
                        "value": signals_str,
                        "short": false
                    }
                ],
                "footer": format!("Scanner {} on {}", payload.metadata.scanner_id, payload.metadata.node_name),
                "ts": payload.timestamp
            }]
        })
    }

    /// Format for Teams
    fn format_teams(&self, payload: &AlertPayload) -> serde_json::Value {
        serde_json::json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": match payload.severity.as_str() {
                "CRITICAL" => "FF0000",
                "HIGH" => "FF8800",
                _ => "00CC00",
            },
            "summary": format!("{} CVE Alert", payload.severity),
            "sections": [{
                "activityTitle": format!("🚨 {} CVE Detected", payload.severity),
                "facts": [
                    {"name": "CVE:", "value": payload.cve.as_deref().unwrap_or("N/A")},
                    {"name": "Confidence:", "value": format!("{:.2}", payload.confidence)},
                    {"name": "Risk Score:", "value": format!("{:.1}", payload.risk_score)},
                    {"name": "Process:", "value": &payload.process},
                    {"name": "Path:", "value": payload.attack_path.join(" → ")},
                    {"name": "Signals:", "value": payload.signals.join(", ")},
                ]
            }]
        })
    }

    /// Format for Datadog
    fn format_datadog(&self, payload: &AlertPayload) -> serde_json::Value {
        serde_json::json!({
            "title": format!("{} CVE Alert: {}", payload.severity, payload.cve.as_deref().unwrap_or("Unknown")),
            "text": format!("Attack path detected: {}", payload.attack_path.join(" → ")),
            "alert_type": match payload.severity.as_str() {
                "CRITICAL" | "HIGH" => "error",
                "MEDIUM" => "warning",
                _ => "info",
            },
            "tags": [
                format!("cve:{}", payload.cve.as_deref().unwrap_or("unknown")),
                format!("severity:{}", payload.severity.to_lowercase()),
                format!("process:{}", payload.process),
                format!("scanner:{}", payload.metadata.scanner_id),
            ],
            "timestamp": payload.timestamp,
        })
    }

    /// Send with exponential backoff retry
    async fn send_with_retry(
        &self,
        payload: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut attempts = 0;
        let mut delay = Duration::from_secs(1);

        loop {
            match self.send_once(payload).await {
                Ok(_) => {
                    info!("Webhook sent successfully to {}", self.config.url);
                    return Ok(());
                }
                Err(e) => {
                    attempts += 1;
                    if attempts >= self.config.retry_attempts {
                        error!("Webhook failed after {} attempts: {}", attempts, e);
                        return Err(e);
                    }
                    warn!(
                        "Webhook attempt {} failed, retrying in {:?}...",
                        attempts, delay
                    );
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
            }
        }
    }

    /// Send single request
    async fn send_once(
        &self,
        payload: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut request = self.client.post(&self.config.url).json(payload);

        // Add authentication
        match &self.config.auth {
            WebhookAuth::None => {}
            WebhookAuth::Bearer { token } => {
                request = request.bearer_auth(token);
            }
            WebhookAuth::Basic { username, password } => {
                request = request.basic_auth(username, Some(password));
            }
            WebhookAuth::ApiKey { header, key } => {
                request = request.header(header, key);
            }
        }

        let response = request.send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("HTTP {}: {}", response.status(), response.text().await?).into())
        }
    }
}

/// Manager for multiple webhooks
pub struct WebhookManager {
    senders: Vec<WebhookSender>,
    dedup_cache: Arc<RwLock<HashMap<String, Instant>>>,
    dedup_ttl: Duration,
}

impl WebhookManager {
    pub fn new() -> Self {
        Self {
            senders: Vec::new(),
            dedup_cache: Arc::new(RwLock::new(HashMap::new())),
            dedup_ttl: Duration::from_secs(60),
        }
    }

    /// Add webhook
    pub fn add_webhook(&mut self, config: WebhookConfig) {
        self.senders.push(WebhookSender::new(config));
    }

    /// Check if alert is duplicate
    pub async fn is_duplicate(&self, path_id: &str) -> bool {
        let cache = self.dedup_cache.read().await;
        if let Some(&last_time) = cache.get(path_id) {
            if Instant::now().duration_since(last_time) < self.dedup_ttl {
                return true;
            }
        }
        false
    }

    /// Mark alert as sent
    pub async fn mark_sent(&self, path_id: &str) {
        let mut cache = self.dedup_cache.write().await;
        cache.insert(path_id.to_string(), Instant::now());

        // Cleanup old entries
        let now = Instant::now();
        cache.retain(|_, v| now.duration_since(*v) < self.dedup_ttl);
    }

    /// Send alert to all configured webhooks
    pub async fn broadcast(&self, payload: &AlertPayload) {
        for sender in &self.senders {
            if let Err(e) = sender.send_alert(payload).await {
                error!("Failed to send webhook: {}", e);
            }
        }
    }

    /// Send alert with deduplication
    pub async fn send_alert(&self, path_id: &str, payload: &AlertPayload) {
        if self.is_duplicate(path_id).await {
            debug!("Deduplicating alert for {}", path_id);
            return;
        }

        self.mark_sent(path_id).await;
        self.broadcast(payload).await;
    }
}

/// Create alert payload from attack path and finding
pub fn create_alert_payload(
    path: &AttackPath,
    finding: Option<&Finding>,
    scanner_id: &str,
) -> AlertPayload {
    let node_names: Vec<String> = path.nodes.iter().map(|n| n.node_id()).collect();

    let severity = if path.confidence >= 0.9 {
        "CRITICAL"
    } else if path.confidence >= 0.8 {
        "HIGH"
    } else if path.confidence >= 0.6 {
        "MEDIUM"
    } else {
        "LOW"
    };

    let process = path
        .nodes
        .iter()
        .find_map(|n| match n {
            crate::runtime_attack_graph_v2::RuntimeNode::Process { name, .. } => Some(name.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "unknown".to_string());

    AlertPayload {
        event_type: "ATTACK_PATH_ALERT".to_string(),
        severity: severity.to_string(),
        confidence: path.confidence,
        risk_score: path.risk_score,
        cve: finding.map(|f| f.signal.cve.clone()),
        process,
        attack_path: node_names,
        signals: path.signal_types.clone(),
        timestamp: Utc::now().timestamp(),
        metadata: AlertMetadata {
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            scanner_id: scanner_id.to_string(),
            node_name: finding
                .map(|f| f.identity.node_name.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            namespace: finding
                .map(|f| f.identity.namespace.clone())
                .unwrap_or_default(),
            pod_name: finding
                .map(|f| f.identity.pod_name.clone())
                .unwrap_or_default(),
        },
        context: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_filter_ordering() {
        assert!(SeverityFilter::Critical > SeverityFilter::High);
        assert!(SeverityFilter::High > SeverityFilter::Medium);
        assert!(SeverityFilter::Medium > SeverityFilter::Low);
    }

    #[test]
    fn test_slack_formatting() {
        let config = WebhookConfig {
            webhook_type: WebhookType::Slack,
            ..Default::default()
        };

        let sender = WebhookSender::new(config);
        let payload = AlertPayload {
            event_type: "TEST".to_string(),
            severity: "CRITICAL".to_string(),
            confidence: 0.88,
            risk_score: 8.5,
            cve: Some("CVE-2023-XXXX".to_string()),
            process: "nginx".to_string(),
            attack_path: vec!["proc:1234:nginx".to_string(), "lib:ssl".to_string()],
            signals: vec!["mmap".to_string(), "tcp_send".to_string()],
            timestamp: 1710000000,
            metadata: AlertMetadata {
                scanner_version: "1.0".to_string(),
                scanner_id: "test".to_string(),
                node_name: "node-a".to_string(),
                namespace: "default".to_string(),
                pod_name: "test-pod".to_string(),
            },
            context: None,
        };

        let slack_json = sender.format_slack(&payload);
        let json_str = serde_json::to_string(&slack_json).unwrap();

        assert!(json_str.contains("🚨"));
        assert!(json_str.contains("CRITICAL"));
        assert!(json_str.contains("CVE-2023-XXXX"));
    }
}
