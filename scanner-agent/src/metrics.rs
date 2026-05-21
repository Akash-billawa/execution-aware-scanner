use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

// ── Label sets ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct FindingLabels {
    pub priority: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct EnforcementLabels {
    pub action: String,
    pub status: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct IntelLabels {
    pub feed: String,
    pub status: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct WebhookLabels {
    pub endpoint: String,
    pub status: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct OperationLabels {
    pub operation: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct SlaLabels {
    pub operation: String,
}

// ── Metrics container ───────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Mutex<Registry>>,

    // Core (existing)
    pub events_total: Counter,
    pub findings_total: Family<FindingLabels, Counter>,
    pub dropped_events: Gauge,

    // Batch processing
    pub batches_processed_total: Counter,
    pub batch_duration_seconds: Histogram,
    pub workloads_active: Gauge,

    // Enforcement
    pub enforcement_actions_total: Family<EnforcementLabels, Counter>,
    pub enforcement_rollbacks_total: Counter,
    pub seccomp_profiles_generated_total: Counter,

    // Intel refresh
    pub intel_refresh_total: Family<IntelLabels, Counter>,
    pub intel_kev_count: Gauge,
    pub intel_epss_count: Gauge,
    pub intel_staleness_seconds: Gauge,

    // Webhook
    pub webhook_sent_total: Family<WebhookLabels, Counter>,
    pub webhook_latency_seconds: Histogram,

    // Streaming
    pub stream_events_total: Counter,
    pub stream_alerts_total: Counter,
    pub attack_paths_active: Gauge,

    // SLA
    pub sla_compliance_ratio: Family<SlaLabels, Gauge<f64, AtomicU64>>,
    pub sla_violations_total: Family<SlaLabels, Counter>,
    pub response_time_seconds: Family<OperationLabels, Histogram>,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        // Core
        let events_total = Counter::default();
        let findings_total = Family::<FindingLabels, Counter>::default();
        let dropped_events = Gauge::default();

        // Batch processing
        let batches_processed_total = Counter::default();
        let batch_duration_seconds = Histogram::new([0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]);
        let workloads_active = Gauge::default();

        // Enforcement
        let enforcement_actions_total = Family::<EnforcementLabels, Counter>::default();
        let enforcement_rollbacks_total = Counter::default();
        let seccomp_profiles_generated_total = Counter::default();

        // Intel refresh
        let intel_refresh_total = Family::<IntelLabels, Counter>::default();
        let intel_kev_count = Gauge::default();
        let intel_epss_count = Gauge::default();
        let intel_staleness_seconds = Gauge::default();

        // Webhook
        let webhook_sent_total = Family::<WebhookLabels, Counter>::default();
        let webhook_latency_seconds = Histogram::new([0.01, 0.05, 0.1, 0.5, 1.0, 5.0]);

        // Streaming
        let stream_events_total = Counter::default();
        let stream_alerts_total = Counter::default();
        let attack_paths_active = Gauge::default();

        // SLA
        let sla_compliance_ratio = Family::<SlaLabels, Gauge<f64, AtomicU64>>::default();
        let sla_violations_total = Family::<SlaLabels, Counter>::default();
        let response_time_seconds =
            Family::<OperationLabels, Histogram>::new_with_constructor(|| {
                Histogram::new([0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0, 60.0])
            });

        // ── Registration ────────────────────────────────────────────────────
        registry.register(
            "scanner_events_total",
            "Total runtime events ingested",
            events_total.clone(),
        );
        registry.register(
            "scanner_findings_total",
            "Total prioritized findings",
            findings_total.clone(),
        );
        registry.register(
            "scanner_dropped_events",
            "Approximate dropped kernel events",
            dropped_events.clone(),
        );

        registry.register(
            "scanner_batches_processed_total",
            "Total analysis batches processed",
            batches_processed_total.clone(),
        );
        registry.register(
            "scanner_batch_duration_seconds",
            "Analysis batch duration",
            batch_duration_seconds.clone(),
        );
        registry.register(
            "scanner_workloads_active",
            "Currently tracked workloads",
            workloads_active.clone(),
        );

        registry.register(
            "scanner_enforcement_actions_total",
            "Enforcement actions taken",
            enforcement_actions_total.clone(),
        );
        registry.register(
            "scanner_enforcement_rollbacks_total",
            "Enforcement rollbacks",
            enforcement_rollbacks_total.clone(),
        );
        registry.register(
            "scanner_seccomp_profiles_generated_total",
            "Seccomp profiles generated",
            seccomp_profiles_generated_total.clone(),
        );

        registry.register(
            "scanner_intel_refresh_total",
            "Intel feed refreshes",
            intel_refresh_total.clone(),
        );
        registry.register(
            "scanner_intel_kev_count",
            "Current KEV catalog size",
            intel_kev_count.clone(),
        );
        registry.register(
            "scanner_intel_epss_count",
            "Current EPSS score count",
            intel_epss_count.clone(),
        );
        registry.register(
            "scanner_intel_staleness_seconds",
            "Seconds since last intel refresh",
            intel_staleness_seconds.clone(),
        );

        registry.register(
            "scanner_webhook_sent_total",
            "Webhook deliveries",
            webhook_sent_total.clone(),
        );
        registry.register(
            "scanner_webhook_latency_seconds",
            "Webhook delivery latency",
            webhook_latency_seconds.clone(),
        );

        registry.register(
            "scanner_stream_events_total",
            "Streaming engine events processed",
            stream_events_total.clone(),
        );
        registry.register(
            "scanner_stream_alerts_total",
            "Streaming engine alerts generated",
            stream_alerts_total.clone(),
        );
        registry.register(
            "scanner_attack_paths_active",
            "Active attack paths",
            attack_paths_active.clone(),
        );

        registry.register(
            "scanner_sla_compliance_ratio",
            "SLA compliance ratio (0.0-1.0)",
            sla_compliance_ratio.clone(),
        );
        registry.register(
            "scanner_sla_violations_total",
            "SLA violations",
            sla_violations_total.clone(),
        );
        registry.register(
            "scanner_response_time_seconds",
            "Operation response times",
            response_time_seconds.clone(),
        );

        Self {
            registry: Arc::new(Mutex::new(registry)),
            events_total,
            findings_total,
            dropped_events,
            batches_processed_total,
            batch_duration_seconds,
            workloads_active,
            enforcement_actions_total,
            enforcement_rollbacks_total,
            seccomp_profiles_generated_total,
            intel_refresh_total,
            intel_kev_count,
            intel_epss_count,
            intel_staleness_seconds,
            webhook_sent_total,
            webhook_latency_seconds,
            stream_events_total,
            stream_alerts_total,
            attack_paths_active,
            sla_compliance_ratio,
            sla_violations_total,
            response_time_seconds,
        }
    }

    // ── Convenience helpers ─────────────────────────────────────────────────

    pub fn inc_events(&self) {
        self.events_total.inc();
    }

    pub fn inc_findings(&self, priority: &str) {
        self.findings_total
            .get_or_create(&FindingLabels {
                priority: priority.to_string(),
            })
            .inc();
    }

    pub fn set_dropped_events(&self, dropped: i64) {
        self.dropped_events.set(dropped);
    }

    pub fn record_batch_duration(&self, seconds: f64) {
        self.batches_processed_total.inc();
        self.batch_duration_seconds.observe(seconds);
    }

    pub fn set_workloads_active(&self, count: i64) {
        self.workloads_active.set(count);
    }

    pub fn inc_enforcement_action(&self, action: &str, status: &str) {
        self.enforcement_actions_total
            .get_or_create(&EnforcementLabels {
                action: action.to_string(),
                status: status.to_string(),
            })
            .inc();
    }

    pub fn inc_enforcement_rollback(&self) {
        self.enforcement_rollbacks_total.inc();
    }

    pub fn inc_seccomp_generated(&self) {
        self.seccomp_profiles_generated_total.inc();
    }

    pub fn inc_intel_refresh(&self, feed: &str, status: &str) {
        self.intel_refresh_total
            .get_or_create(&IntelLabels {
                feed: feed.to_string(),
                status: status.to_string(),
            })
            .inc();
    }

    pub fn set_intel_kev_count(&self, count: i64) {
        self.intel_kev_count.set(count);
    }

    pub fn set_intel_epss_count(&self, count: i64) {
        self.intel_epss_count.set(count);
    }

    pub fn set_intel_staleness(&self, seconds: i64) {
        self.intel_staleness_seconds.set(seconds);
    }

    pub fn inc_webhook_sent(&self, endpoint: &str, status: &str) {
        self.webhook_sent_total
            .get_or_create(&WebhookLabels {
                endpoint: endpoint.to_string(),
                status: status.to_string(),
            })
            .inc();
    }

    pub fn record_webhook_latency(&self, seconds: f64) {
        self.webhook_latency_seconds.observe(seconds);
    }

    pub fn inc_stream_events(&self) {
        self.stream_events_total.inc();
    }

    pub fn inc_stream_alerts(&self) {
        self.stream_alerts_total.inc();
    }

    pub fn set_attack_paths_active(&self, count: i64) {
        self.attack_paths_active.set(count);
    }

    pub fn set_sla_compliance(&self, operation: &str, ratio: f64) {
        self.sla_compliance_ratio
            .get_or_create(&SlaLabels {
                operation: operation.to_string(),
            })
            .set(ratio);
    }

    pub fn inc_sla_violation(&self, operation: &str) {
        self.sla_violations_total
            .get_or_create(&SlaLabels {
                operation: operation.to_string(),
            })
            .inc();
    }

    pub fn record_response_time(&self, operation: &str, seconds: f64) {
        self.response_time_seconds
            .get_or_create(&OperationLabels {
                operation: operation.to_string(),
            })
            .observe(seconds);
    }

    pub fn render(&self) -> String {
        let mut output = String::new();
        match self.registry.lock() {
            Ok(registry) => {
                if let Err(e) = encode(&mut output, &registry) {
                    tracing::warn!("Failed to encode metrics: {}", e);
                }
            }
            Err(poisoned) => {
                let registry = poisoned.into_inner();
                let _ = encode(&mut output, &registry);
            }
        }
        output
    }
}
