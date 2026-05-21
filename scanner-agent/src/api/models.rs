//! API request/response models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Pagination ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

impl PaginationParams {
    pub fn offset(&self) -> usize {
        let page = self.page.unwrap_or(1).max(1);
        let per_page = self.per_page.unwrap_or(50).min(200);
        ((page - 1) * per_page) as usize
    }

    pub fn limit(&self) -> usize {
        self.per_page.unwrap_or(50).min(200) as usize
    }
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub total: usize,
    pub page: u32,
    pub per_page: u32,
}

// ── Findings ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct FindingsFilter {
    pub priority: Option<String>,
    pub namespace: Option<String>,
    pub workload: Option<String>,
    pub cve: Option<String>,
    pub since: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub pagination: PaginationParams,
}

#[derive(Debug, Serialize)]
pub struct FindingSummary {
    pub id: String,
    pub detected_at: DateTime<Utc>,
    pub cve: String,
    pub cvss: f32,
    pub epss: f32,
    pub kev: bool,
    pub priority: String,
    pub namespace: String,
    pub workload: String,
    pub pod_name: String,
    pub score: f32,
    pub recommendation: String,
    pub acknowledged: bool,
}

#[derive(Debug, Serialize)]
pub struct FindingDetail {
    pub id: String,
    pub detected_at: DateTime<Utc>,
    pub cve: String,
    pub cvss: f32,
    pub epss: f32,
    pub kev: bool,
    pub priority: String,
    pub namespace: String,
    pub workload: String,
    pub pod_name: String,
    pub container: String,
    pub image: String,
    pub score: f32,
    pub recommendation: String,
    pub explainability: ExplainabilitySummary,
    pub acknowledged: bool,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExplainabilitySummary {
    pub decision: String,
    pub confidence: f32,
    pub cvss_component: f32,
    pub epss_component: f32,
    pub kev_component: f32,
    pub runtime_component: f32,
    pub signal_boost: f32,
}

#[derive(Debug, Deserialize)]
pub struct AcknowledgeRequest {
    pub reason: Option<String>,
}

// ── Policies ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PolicySummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub rules_count: usize,
    pub last_loaded: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct PolicyDetail {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub rules: Vec<PolicyRule>,
    pub source_path: String,
    pub last_loaded: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub action: String,
    pub conditions: String,
}

#[derive(Debug, Serialize)]
pub struct PolicyReloadResult {
    pub reloaded: usize,
    pub errors: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

// ── Webhooks ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateWebhookRequest {
    pub name: String,
    pub url: String,
    pub webhook_type: String,
    pub auth: Option<WebhookAuthConfig>,
    pub min_severity: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct WebhookAuthConfig {
    pub auth_type: String,
    pub token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebhookInfo {
    pub id: String,
    pub name: String,
    pub url: String,
    pub webhook_type: String,
    pub enabled: bool,
    pub min_severity: String,
    pub last_sent: Option<DateTime<Utc>>,
    pub send_count: u64,
    pub error_count: u64,
}

// ── Scans ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TriggerScanRequest {
    pub namespace: Option<String>,
    pub workload: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

// ── System Stats ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SystemStats {
    pub uptime_seconds: u64,
    pub events_processed: u64,
    pub findings_total: u64,
    pub workloads_active: u64,
    pub attack_paths_active: u64,
    pub enforcement_actions: u64,
    pub webhook_deliveries: u64,
    pub intel_last_refresh: Option<DateTime<Utc>>,
    pub kev_count: u64,
    pub epss_count: u64,
    pub version: String,
}

// ── Error Response ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

impl ErrorResponse {
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
            timestamp: Utc::now(),
        }
    }
}
