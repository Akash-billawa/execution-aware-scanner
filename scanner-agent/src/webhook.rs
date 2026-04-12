use crate::error::ScannerError;
use scanner_common::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Webhook configuration
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    /// Webhook endpoint URL
    pub url: String,
    /// Authentication token (optional)
    pub token: Option<String>,
    /// Request timeout
    pub timeout_secs: u64,
    /// Maximum retries
    pub max_retries: u32,
    /// Batch size (0 = no batching)
    pub batch_size: usize,
    /// Batch timeout
    pub batch_timeout_secs: u64,
    /// Filter by minimum priority
    pub min_priority: String,
    /// Include metadata
    pub include_metadata: bool,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8080/webhook".to_string(),
            token: None,
            timeout_secs: 30,
            max_retries: 3,
            batch_size: 10,
            batch_timeout_secs: 5,
            min_priority: "Medium".to_string(),
            include_metadata: true,
        }
    }
}

/// Webhook payload structure
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub version: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub finding: Finding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<WebhookMetadata>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookMetadata {
    pub agent_version: String,
    pub node_name: String,
    pub scanner_id: String,
    pub source_ip: String,
}

/// Webhook exporter
#[derive(Clone)]
pub struct WebhookExporter {
    client: reqwest::Client,
    config: WebhookConfig,
    scanner_id: String,
    node_name: String,
}

/// Export result
#[derive(Debug)]
pub struct ExportResult {
    pub success: bool,
    pub retry_count: u32,
    pub duration: Duration,
    pub error: Option<String>,
}

impl WebhookExporter {
    pub fn new(config: WebhookConfig, scanner_id: String, node_name: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .pool_max_idle_per_host(10)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            config,
            scanner_id,
            node_name,
        }
    }

    /// Export a single finding
    pub async fn export_finding(&self, finding: &Finding) -> Result<ExportResult, ScannerError> {
        let start = std::time::Instant::now();

        let payload = self.build_payload(finding);
        let json = serde_json::to_string(&payload)?;

        let mut attempts = 0;
        let mut last_error = None;

        while attempts < self.config.max_retries {
            attempts += 1;

            let mut request = self
                .client
                .post(&self.config.url)
                .header("Content-Type", "application/json")
                .header("X-Scanner-ID", &self.scanner_id)
                .header("X-Event-Type", "finding");

            if let Some(token) = &self.config.token {
                request = request.header("Authorization", format!("Bearer {}", token));
            }

            match request.body(json.clone()).send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        return Ok(ExportResult {
                            success: true,
                            retry_count: attempts - 1,
                            duration: start.elapsed(),
                            error: None,
                        });
                    } else {
                        let error = format!(
                            "HTTP {}: {}",
                            status,
                            response.text().await.unwrap_or_default()
                        );
                        warn!("Webhook failed: {}", error);
                        last_error = Some(error);

                        // Don't retry on client errors (4xx)
                        if status.is_client_error() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let error = format!("Request failed: {}", e);
                    warn!("Webhook error: {}", error);
                    last_error = Some(error);
                }
            }

            if attempts < self.config.max_retries {
                let backoff = Duration::from_millis(100 * 2_u64.pow(attempts - 1));
                tokio::time::sleep(backoff).await;
            }
        }

        error!("Webhook export failed after {} attempts", attempts);
        Ok(ExportResult {
            success: false,
            retry_count: attempts,
            duration: start.elapsed(),
            error: last_error,
        })
    }

    /// Export multiple findings as a batch
    pub async fn export_batch(&self, findings: &[Finding]) -> Result<ExportResult, ScannerError> {
        if findings.is_empty() {
            return Ok(ExportResult {
                success: true,
                retry_count: 0,
                duration: Duration::from_secs(0),
                error: None,
            });
        }

        let start = std::time::Instant::now();
        let payloads: Vec<_> = findings.iter().map(|f| self.build_payload(f)).collect();
        let json = serde_json::to_string(&payloads)?;

        let mut attempts = 0;
        let mut last_error = None;

        while attempts < self.config.max_retries {
            attempts += 1;

            let mut request = self
                .client
                .post(&self.config.url)
                .header("Content-Type", "application/json")
                .header("X-Scanner-ID", &self.scanner_id)
                .header("X-Event-Type", "finding-batch")
                .header("X-Batch-Size", findings.len().to_string());

            if let Some(token) = &self.config.token {
                request = request.header("Authorization", format!("Bearer {}", token));
            }

            match request.body(json.clone()).send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        info!("Batch export successful: {} findings", findings.len());
                        return Ok(ExportResult {
                            success: true,
                            retry_count: attempts - 1,
                            duration: start.elapsed(),
                            error: None,
                        });
                    } else {
                        let error = format!(
                            "HTTP {}: {}",
                            status,
                            response.text().await.unwrap_or_default()
                        );
                        warn!("Batch webhook failed: {}", error);
                        last_error = Some(error);

                        if status.is_client_error() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let error = format!("Request failed: {}", e);
                    warn!("Batch webhook error: {}", error);
                    last_error = Some(error);
                }
            }

            if attempts < self.config.max_retries {
                let backoff = Duration::from_millis(100 * 2_u64.pow(attempts - 1));
                tokio::time::sleep(backoff).await;
            }
        }

        error!("Batch export failed after {} attempts", attempts);
        Ok(ExportResult {
            success: false,
            retry_count: attempts,
            duration: start.elapsed(),
            error: last_error,
        })
    }

    /// Build payload from finding
    fn build_payload(&self, finding: &Finding) -> WebhookPayload {
        WebhookPayload {
            version: "1.0".to_string(),
            timestamp: chrono::Utc::now(),
            finding: finding.clone(),
            metadata: if self.config.include_metadata {
                Some(WebhookMetadata {
                    agent_version: env!("CARGO_PKG_VERSION").to_string(),
                    node_name: self.node_name.clone(),
                    scanner_id: self.scanner_id.clone(),
                    source_ip: self.get_source_ip(),
                })
            } else {
                None
            },
        }
    }

    fn get_source_ip(&self) -> String {
        // In real implementation, get actual IP
        "127.0.0.1".to_string()
    }

    /// Check if finding should be exported based on config
    pub fn should_export(&self, finding: &Finding) -> bool {
        let min_priority = match self.config.min_priority.as_str() {
            "Critical" => 4,
            "High" => 3,
            "Medium" => 2,
            "Low" => 1,
            _ => 0,
        };

        let finding_priority = match finding.priority {
            scanner_common::Priority::Critical => 4,
            scanner_common::Priority::High => 3,
            scanner_common::Priority::Medium => 2,
            scanner_common::Priority::Low => 1,
            scanner_common::Priority::Informational => 0,
        };

        finding_priority >= min_priority
    }
}

/// Batch exporter for efficient bulk export
pub struct BatchExporter {
    exporter: WebhookExporter,
    batch: Vec<Finding>,
    last_flush: std::time::Instant,
}

impl BatchExporter {
    pub fn new(exporter: WebhookExporter) -> Self {
        let batch_size = exporter.config.batch_size;
        Self {
            exporter,
            batch: Vec::with_capacity(batch_size),
            last_flush: std::time::Instant::now(),
        }
    }

    /// Add finding to batch
    pub fn push(&mut self, finding: Finding) {
        if self.exporter.should_export(&finding) {
            self.batch.push(finding);
        }
    }

    /// Check if batch should be flushed
    pub fn should_flush(&self) -> bool {
        if self.batch.is_empty() {
            return false;
        }

        if self.batch.len() >= self.exporter.config.batch_size {
            return true;
        }

        if self.last_flush.elapsed().as_secs() >= self.exporter.config.batch_timeout_secs {
            return true;
        }

        false
    }

    /// Flush batch
    pub async fn flush(&mut self) -> Result<ExportResult, ScannerError> {
        let findings = std::mem::take(&mut self.batch);
        self.last_flush = std::time::Instant::now();
        self.exporter.export_batch(&findings).await
    }

    /// Get current batch size
    pub fn len(&self) -> usize {
        self.batch.len()
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }
}

/// Multi-destination webhook manager
pub struct WebhookManager {
    exporters: Vec<(WebhookExporter, WebhookConfig)>,
    scanner_id: String,
    node_name: String,
}

impl WebhookManager {
    pub fn new(scanner_id: String, node_name: String) -> Self {
        Self {
            exporters: Vec::new(),
            scanner_id,
            node_name,
        }
    }

    /// Add webhook endpoint
    pub fn add_endpoint(&mut self, config: WebhookConfig) {
        let exporter = WebhookExporter::new(
            config.clone(),
            self.scanner_id.clone(),
            self.node_name.clone(),
        );
        self.exporters.push((exporter, config));
    }

    /// Export finding to all endpoints
    pub async fn export_finding(&self, finding: &Finding) -> Vec<ExportResult> {
        let mut results = Vec::new();

        for (exporter, _) in &self.exporters {
            if exporter.should_export(finding) {
                match exporter.export_finding(finding).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        results.push(ExportResult {
                            success: false,
                            retry_count: 0,
                            duration: Duration::from_secs(0),
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
        }

        results
    }

    /// Get exporter count
    pub fn endpoint_count(&self) -> usize {
        self.exporters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scanner_common::{Priority, RiskSignal, RuntimeDisposition, RuntimeIdentity};
    use std::collections::{BTreeMap, BTreeSet};

    fn create_test_finding(priority: Priority) -> Finding {
        Finding {
            id: "test-123".to_string(),
            detected_at: chrono::Utc::now(),
            identity: RuntimeIdentity {
                node_name: "test".to_string(),
                namespace: "default".to_string(),
                pod_name: "test-pod".to_string(),
                container_name: "app".to_string(),
                image: "test:latest".to_string(),
                workload: "test".to_string(),
                labels: BTreeMap::new(),
            },
  signal: RiskSignal {
    cve: "CVE-2025-1234".to_string(),
    cvss: 9.0,
    epss: 0.8,
    kev: true,
    runtime: RuntimeDisposition::Reachable,
    package: "test".to_string(),
    observed_paths: BTreeSet::new(),
    signal_weight: 0.0,
  },
            score: 9.0,
            priority,
            recommendation: "Fix it".to_string(),
        }
    }

    #[test]
    fn test_should_export_filtering() {
        let config = WebhookConfig {
            min_priority: "High".to_string(),
            ..Default::default()
        };

        let exporter = WebhookExporter::new(config, "test".to_string(), "node1".to_string());

        assert!(exporter.should_export(&create_test_finding(Priority::Critical)));
        assert!(exporter.should_export(&create_test_finding(Priority::High)));
        assert!(!exporter.should_export(&create_test_finding(Priority::Medium)));
        assert!(!exporter.should_export(&create_test_finding(Priority::Low)));
    }

    #[test]
    fn test_batch_exporter() {
        let config = WebhookConfig {
            batch_size: 3,
            batch_timeout_secs: 60,
            ..Default::default()
        };

        let exporter = WebhookExporter::new(config, "test".to_string(), "node1".to_string());
        let mut batch = BatchExporter::new(exporter);

        assert!(!batch.should_flush());

        batch.push(create_test_finding(Priority::High));
        batch.push(create_test_finding(Priority::High));
        assert!(!batch.should_flush());

        batch.push(create_test_finding(Priority::High));
        assert!(batch.should_flush());
        assert_eq!(batch.len(), 3);
    }
}
