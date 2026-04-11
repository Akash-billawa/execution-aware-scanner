use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct FindingLabels {
    pub priority: String,
}

#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Mutex<Registry>>,
    events_total: Counter,
    findings_total: Family<FindingLabels, Counter>,
    dropped_events: Gauge,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let events_total = Counter::default();
        let findings_total = Family::<FindingLabels, Counter>::default();
        let dropped_events = Gauge::default();
        registry.register("scanner_events_total", "Total runtime events ingested", events_total.clone());
        registry.register("scanner_findings_total", "Total prioritized findings", findings_total.clone());
        registry.register("scanner_dropped_events", "Approximate dropped kernel events", dropped_events.clone());
        Self {
            registry: Arc::new(Mutex::new(registry)),
            events_total,
            findings_total,
            dropped_events,
        }
    }

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

    pub fn render(&self) -> String {
        let mut output = String::new();
        let registry = self.registry.lock().expect("metrics registry poisoned");
        encode(&mut output, &registry).expect("encode metrics");
        output
    }
}
