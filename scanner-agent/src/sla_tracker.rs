//! SLA Tracker
//!
//! Monitors response times for key operations and tracks SLA compliance.
//! Operations tracked:
//! - Finding detection to webhook delivery
//! - Critical finding to enforcement action
//! - Intel feed refresh propagation
//! - Event ingestion to StateStore update

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use crate::metrics::Metrics;

/// SLA target definitions
#[derive(Debug, Clone)]
pub struct SlaTarget {
    pub operation: String,
    pub max_duration_secs: f64,
    pub description: String,
}

/// Default SLA targets
pub fn default_sla_targets() -> Vec<SlaTarget> {
    vec![
        SlaTarget {
            operation: "finding_notification".to_string(),
            max_duration_secs: 30.0,
            description: "Critical finding notification within 30 seconds".to_string(),
        },
        SlaTarget {
            operation: "enforcement_action".to_string(),
            max_duration_secs: 60.0,
            description: "Enforcement action within 60 seconds".to_string(),
        },
        SlaTarget {
            operation: "intel_refresh".to_string(),
            max_duration_secs: 300.0,
            description: "Intel refresh propagation within 5 minutes".to_string(),
        },
        SlaTarget {
            operation: "event_processing".to_string(),
            max_duration_secs: 0.1,
            description: "Event processing latency under 100ms".to_string(),
        },
    ]
}

/// In-flight operation being tracked
#[derive(Debug)]
struct TrackedOperation {
    operation: String,
    started_at: Instant,
    metadata: HashMap<String, String>,
}

/// SLA compliance tracker
pub struct SlaTracker {
    targets: HashMap<String, SlaTarget>,
    in_flight: Arc<RwLock<HashMap<String, TrackedOperation>>>,
    metrics: Metrics,
}

impl SlaTracker {
    pub fn new(metrics: Metrics) -> Self {
        let targets = default_sla_targets()
            .into_iter()
            .map(|t| (t.operation.clone(), t))
            .collect();

        Self {
            targets,
            in_flight: Arc::new(RwLock::new(HashMap::new())),
            metrics,
        }
    }

    /// Start tracking an operation
    pub async fn start_operation(
        &self,
        operation_id: &str,
        operation: &str,
        metadata: HashMap<String, String>,
    ) {
        let mut in_flight = self.in_flight.write().await;
        in_flight.insert(
            operation_id.to_string(),
            TrackedOperation {
                operation: operation.to_string(),
                started_at: Instant::now(),
                metadata,
            },
        );
    }

    /// Complete an operation and check SLA compliance
    pub async fn complete_operation(&self, operation_id: &str) -> SlaResult {
        let mut in_flight = self.in_flight.write().await;
        let tracked = match in_flight.remove(operation_id) {
            Some(t) => t,
            None => return SlaResult::NotFound,
        };

        let duration = tracked.started_at.elapsed();
        let duration_secs = duration.as_secs_f64();

        // Record response time metric
        self.metrics
            .record_response_time(&tracked.operation, duration_secs);

        // Check against SLA target
        if let Some(target) = self.targets.get(&tracked.operation) {
            if duration_secs > target.max_duration_secs {
                self.metrics.inc_sla_violation(&tracked.operation);

                // Calculate compliance ratio (how close to target)
                let ratio = target.max_duration_secs / duration_secs;
                self.metrics.set_sla_compliance(&tracked.operation, ratio);

                return SlaResult::Violation {
                    operation: tracked.operation,
                    duration_secs,
                    target_secs: target.max_duration_secs,
                    metadata: tracked.metadata,
                };
            }
        }

        SlaResult::Compliant {
            operation: tracked.operation,
            duration_secs,
        }
    }

    /// Get current SLA compliance status
    pub async fn status(&self) -> SlaStatus {
        let in_flight = self.in_flight.read().await;
        let mut operations_by_type: HashMap<String, usize> = HashMap::new();

        for tracked in in_flight.values() {
            *operations_by_type
                .entry(tracked.operation.clone())
                .or_insert(0) += 1;
        }

        SlaStatus {
            in_flight_count: in_flight.len(),
            operations_by_type,
            timestamp: Utc::now(),
        }
    }
}

/// Result of SLA tracking
#[derive(Debug, Serialize)]
pub enum SlaResult {
    Compliant {
        operation: String,
        duration_secs: f64,
    },
    Violation {
        operation: String,
        duration_secs: f64,
        target_secs: f64,
        metadata: HashMap<String, String>,
    },
    NotFound,
}

/// Current SLA status
#[derive(Debug, Serialize)]
pub struct SlaStatus {
    pub in_flight_count: usize,
    pub operations_by_type: HashMap<String, usize>,
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sla_tracking() {
        let metrics = Metrics::new();
        let tracker = SlaTracker::new(metrics);

        let mut metadata = HashMap::new();
        metadata.insert("finding_id".to_string(), "f-001".to_string());

        tracker
            .start_operation("op-001", "event_processing", metadata)
            .await;

        // Complete immediately (should be compliant)
        let result = tracker.complete_operation("op-001").await;
        match result {
            SlaResult::Compliant { .. } => {}
            _ => panic!("Expected compliant result"),
        }
    }

    #[tokio::test]
    async fn test_sla_status() {
        let metrics = Metrics::new();
        let tracker = SlaTracker::new(metrics);

        tracker
            .start_operation("op-001", "event_processing", HashMap::new())
            .await;

        let status = tracker.status().await;
        assert_eq!(status.in_flight_count, 1);
    }
}
