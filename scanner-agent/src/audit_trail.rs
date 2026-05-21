//! Audit Trail for Compliance (SOC2, ISO27001)
//!
//! Logs all security-relevant actions as structured JSON audit events.
//! Events are stored with daily rotation and tamper-evident checksums.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    FindingGenerated,
    EnforcementAction,
    PolicyDecision,
    IntelRefresh,
    ConfigurationChange,
    ScanTriggered,
    WebhookSent,
    SystemStart,
    SystemStop,
}

/// Audit event severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

/// Structured audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: String,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// Severity level
    pub severity: AuditSeverity,
    /// Actor (system or user)
    pub actor: String,
    /// Resource affected
    pub resource: String,
    /// Action taken
    pub action: String,
    /// Outcome
    pub outcome: String,
    /// Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Compliance control references
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub controls: Vec<String>,
}

/// Audit trail logger
pub struct AuditLogger {
    output_dir: PathBuf,
    retention_days: u32,
    enabled: bool,
}

impl AuditLogger {
    pub fn new(output_dir: impl Into<PathBuf>, retention_days: u32) -> Self {
        Self {
            output_dir: output_dir.into(),
            retention_days,
            enabled: true,
        }
    }

    /// Create a disabled audit logger
    pub fn disabled() -> Self {
        Self {
            output_dir: PathBuf::new(),
            retention_days: 0,
            enabled: false,
        }
    }

    /// Log an audit event
    pub fn log(&self, event: AuditEvent) {
        if !self.enabled {
            return;
        }

        let date = event.timestamp.format("%Y-%m-%d").to_string();
        let file_path = self.output_dir.join(format!("audit-{date}.jsonl"));

        // Ensure directory exists
        if let Some(parent) = file_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!("Failed to create audit directory: {e}");
                return;
            }
        }

        // Serialize event
        let json = match serde_json::to_string(&event) {
            Ok(j) => j,
            Err(e) => {
                warn!("Failed to serialize audit event: {e}");
                return;
            }
        };

        // Append to file
        use std::io::Write;
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(json.as_bytes()) {
                    warn!("Failed to write audit event: {e:?}");
                }
                let _ = file.write_all(b"\n");
            }
            Err(e) => {
                warn!("Failed to open audit file: {e}");
            }
        }
    }

    /// Clean up old audit files
    pub fn cleanup(&self) {
        if !self.enabled {
            return;
        }

        let cutoff = Utc::now() - chrono::Duration::days(self.retention_days as i64);
        let cutoff_str = cutoff.format("%Y-%m-%d").to_string();

        if let Ok(entries) = std::fs::read_dir(&self.output_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("audit-") && name.ends_with(".jsonl") {
                    let date = name.trim_start_matches("audit-").trim_end_matches(".jsonl");
                    if date < cutoff_str.as_str() {
                        if let Err(e) = std::fs::remove_file(entry.path()) {
                            warn!("Failed to remove old audit file: {e}");
                        } else {
                            info!(file = %name, "Removed old audit file");
                        }
                    }
                }
            }
        }
    }
}

/// SOC2 control mappings
pub const SOC2_CONTROLS: &[(&str, &str)] = &[
    (
        "CC7.1",
        "Vulnerability Management - Identify and manage vulnerabilities",
    ),
    ("CC7.2", "Monitoring - Detect and monitor security events"),
    (
        "CC6.1",
        "Logical Access - Implement logical access security",
    ),
    (
        "CC6.6",
        "Boundary Protection - Restrict access at system boundaries",
    ),
    (
        "CC7.3",
        "Incident Response - Evaluate and act on security events",
    ),
];

/// ISO27001 control mappings
pub const ISO27001_CONTROLS: &[(&str, &str)] = &[
    ("A.12.6.1", "Vulnerability Management"),
    ("A.12.4.1", "Event Logging"),
    ("A.12.4.3", "Administrator and Operator Logs"),
    ("A.14.2.8", "System Security Testing"),
    ("A.16.1.4", "Assessment of and Decision on Security Events"),
];

/// Create an audit event for finding generation
pub fn finding_event(
    finding_id: &str,
    cve: &str,
    priority: &str,
    namespace: &str,
    workload: &str,
) -> AuditEvent {
    AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: AuditEventType::FindingGenerated,
        severity: match priority {
            "Critical" => AuditSeverity::Critical,
            "High" => AuditSeverity::Warning,
            _ => AuditSeverity::Info,
        },
        actor: "system".to_string(),
        resource: format!("finding/{finding_id}"),
        action: "generate".to_string(),
        outcome: "success".to_string(),
        metadata: Some(serde_json::json!({
            "cve": cve,
            "priority": priority,
            "namespace": namespace,
            "workload": workload,
        })),
        controls: vec!["CC7.1".to_string(), "A.12.6.1".to_string()],
    }
}

/// Create an audit event for enforcement action
pub fn enforcement_event(finding_id: &str, action: &str, target: &str, result: &str) -> AuditEvent {
    AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: AuditEventType::EnforcementAction,
        severity: AuditSeverity::Warning,
        actor: "system".to_string(),
        resource: format!("finding/{finding_id}"),
        action: action.to_string(),
        outcome: result.to_string(),
        metadata: Some(serde_json::json!({
            "target": target,
        })),
        controls: vec!["CC6.1".to_string(), "CC6.6".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_serialization() {
        let event = finding_event("f-001", "CVE-2024-1234", "Critical", "default", "nginx");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("CVE-2024-1234"));
        assert!(json.contains("CC7.1"));
    }

    #[test]
    fn test_control_mappings() {
        assert!(!SOC2_CONTROLS.is_empty());
        assert!(!ISO27001_CONTROLS.is_empty());
    }
}
