//! Stub implementation of event_consumer for non-eBPF builds

#[derive(Debug, Clone, Default)]
pub struct ConsumerStats {
    pub events_received: u64,
    pub events_dropped: u64,
    pub events_filtered: u64,
    pub batches_processed: u64,
    pub exec_batch_size: usize,
    pub file_batch_size: usize,
    pub net_batch_size: usize,
}

pub struct EventConsumer;

impl EventConsumer {
    pub fn new() -> Self {
        Self
    }

    pub async fn run(
        &self,
        _state_store: std::sync::Arc<tokio::sync::Mutex<crate::state::StateStore>>,
        _cgroup_resolver: std::sync::Arc<tokio::sync::Mutex<crate::cgroup::CgroupResolver>>,
        _metrics: crate::metrics::Metrics,
        _shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), crate::error::ScannerError> {
        // Stub: no eBPF events to consume
        Ok(())
    }
}
