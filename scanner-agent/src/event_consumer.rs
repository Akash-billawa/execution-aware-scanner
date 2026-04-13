#![cfg(feature = "ebpf")]

use crate::cgroup::CgroupResolver;
use crate::error::ScannerError;
use crate::k8s::PodCache;
use crate::metrics::Metrics;
use crate::state::StateStore;
use aya::maps::{MapData, RingBuf};
use bytes::BytesMut;
use scanner_common::{c_string, EventKind, ExecEvent, FileEvent, NetEvent};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, error, info, trace, warn};

pub struct EventConsumer {
    exec_rb: RingBuf<MapData>,
    file_rb: RingBuf<MapData>,
    net_rb: RingBuf<MapData>,

    // Buffers for batching
    exec_batch: Vec<ExecEvent>,
    file_batch: Vec<FileEvent>,
    net_batch: Vec<NetEvent>,

    // Configuration
    batch_size: usize,
    batch_timeout: Duration,
    last_flush: Instant,

    // Performance tracking
    events_received: u64,
    events_dropped: u64,
    events_filtered: u64,
    batches_processed: u64,
}

impl EventConsumer {
    pub fn new(
        exec_rb: RingBuf<MapData>,
        file_rb: RingBuf<MapData>,
        net_rb: RingBuf<MapData>,
    ) -> Self {
        Self {
            exec_rb,
            file_rb,
            net_rb,
            exec_batch: Vec::with_capacity(1024),
            file_batch: Vec::with_capacity(1024),
            net_batch: Vec::with_capacity(1024),
            batch_size: 100,
            batch_timeout: Duration::from_millis(100),
            last_flush: Instant::now(),
            events_received: 0,
            events_dropped: 0,
            events_filtered: 0,
            batches_processed: 0,
        }
    }

    /// Consume events with timeout, returning number of events processed
    pub async fn consume_with_timeout(
        &mut self,
        state_store: Arc<Mutex<StateStore>>,
        cgroup_resolver: Arc<Mutex<CgroupResolver>>,
        metrics: &Metrics,
        timeout: Duration,
    ) -> Result<usize, ScannerError> {
        let deadline = Instant::now() + timeout;
        let mut total_events = 0usize;

        while Instant::now() < deadline {
            let mut events_this_iter = 0;

            // Non-blocking consume from each ring buffer
            events_this_iter += self.consume_exec_batch(&state_store, metrics).await?;
            events_this_iter += self.consume_file_batch(&state_store, metrics).await?;
            events_this_iter += self.consume_net_batch(&state_store, metrics).await?;

            total_events += events_this_iter;

            // Check if we need to flush based on time
            if self.last_flush.elapsed() >= self.batch_timeout {
                self.flush_all(state_store.clone(), cgroup_resolver.clone(), metrics)
                    .await?;
            }

            // Small yield if no events to avoid busy looping
            if events_this_iter == 0 {
                tokio::time::sleep(Duration::from_micros(10)).await;
            }
        }

        // Final flush
        self.flush_all(state_store, cgroup_resolver, metrics)
            .await?;

        Ok(total_events)
    }

    /// Continuous event consumption loop
    pub async fn run(
        mut self,
        state_store: Arc<Mutex<StateStore>>,
        cgroup_resolver: Arc<Mutex<CgroupResolver>>,
        metrics: Metrics,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), ScannerError> {
        info!("Event consumer started");

        let mut interval = tokio::time::interval(Duration::from_millis(10));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Process events
                    let _ = self.consume_exec_batch(&state_store, &metrics).await;
                    let _ = self.consume_file_batch(&state_store, &metrics).await;
                    let _ = self.consume_net_batch(&state_store, &metrics).await;

                    // Check flush condition
                    if self.last_flush.elapsed() >= self.batch_timeout
                        || self.exec_batch.len() >= self.batch_size
                        || self.file_batch.len() >= self.batch_size
                        || self.net_batch.len() >= self.batch_size {

                        if let Err(e) = self.flush_all(
                            state_store.clone(),
                            cgroup_resolver.clone(),
                            &metrics
                        ).await {
                            error!(error = %e, "Failed to flush event batches");
                        }
                    }
                }

                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Shutdown signal received, flushing remaining events");
                        self.flush_all(state_store, cgroup_resolver, &metrics).await?;
                        break;
                    }
                }
            }
        }

        info!(
            events_received = self.events_received,
            events_dropped = self.events_dropped,
            events_filtered = self.events_filtered,
            batches_processed = self.batches_processed,
            "Event consumer stopped"
        );

        Ok(())
    }

    async fn consume_exec_batch(
        &mut self,
        state_store: &Arc<Mutex<StateStore>>,
        metrics: &Metrics,
    ) -> Result<usize, ScannerError> {
        let mut count = 0;

        while let Some(data) = self.exec_rb.next() {
            self.events_received += 1;

            match self.parse_exec_event(&data) {
                Some(event) => {
                    // Apply filtering
                    if self.should_filter_exec(&event) {
                        self.events_filtered += 1;
                        continue;
                    }

                    self.exec_batch.push(event);
                    count += 1;

                    // Update state immediately for hot path
                    let mut store = state_store.lock().await;
                    store.apply_exec(&event);
                    drop(store);

                    metrics.inc_events();
                }
                None => {
                    self.events_dropped += 1;
                    warn!("Failed to parse exec event");
                }
            }

            // Stop if batch is full
            if self.exec_batch.len() >= self.batch_size {
                break;
            }
        }

        Ok(count)
    }

    async fn consume_file_batch(
        &mut self,
        state_store: &Arc<Mutex<StateStore>>,
        metrics: &Metrics,
    ) -> Result<usize, ScannerError> {
        let mut count = 0;

        while let Some(data) = self.file_rb.next() {
            self.events_received += 1;

            match self.parse_file_event(&data) {
                Some(event) => {
                    if self.should_filter_file(&event) {
                        self.events_filtered += 1;
                        continue;
                    }

                    self.file_batch.push(event);
                    count += 1;

                    let mut store = state_store.lock().await;
                    store.apply_file(&event);
                    drop(store);

                    metrics.inc_events();
                }
                None => {
                    self.events_dropped += 1;
                }
            }

            if self.file_batch.len() >= self.batch_size {
                break;
            }
        }

        Ok(count)
    }

    async fn consume_net_batch(
        &mut self,
        state_store: &Arc<Mutex<StateStore>>,
        metrics: &Metrics,
    ) -> Result<usize, ScannerError> {
        let mut count = 0;

        while let Some(data) = self.net_rb.next() {
            self.events_received += 1;

            match self.parse_net_event(&data) {
                Some(event) => {
                    if self.should_filter_net(&event) {
                        self.events_filtered += 1;
                        continue;
                    }

                    self.net_batch.push(event);
                    count += 1;

                    let mut store = state_store.lock().await;
                    store.apply_net(&event);
                    drop(store);

                    metrics.inc_events();
                }
                None => {
                    self.events_dropped += 1;
                }
            }

            if self.net_batch.len() >= self.batch_size {
                break;
            }
        }

        Ok(count)
    }

    async fn flush_all(
        &mut self,
        state_store: Arc<Mutex<StateStore>>,
        cgroup_resolver: Arc<Mutex<CgroupResolver>>,
        metrics: &Metrics,
    ) -> Result<(), ScannerError> {
        if self.exec_batch.is_empty() && self.file_batch.is_empty() && self.net_batch.is_empty() {
            return Ok(());
        }

        let start = Instant::now();
        let exec_count = self.exec_batch.len();
        let file_count = self.file_batch.len();
        let net_count = self.net_batch.len();

        // Process batches
        self.process_exec_batch(&state_store, &cgroup_resolver)
            .await?;
        self.process_file_batch(&state_store, &cgroup_resolver)
            .await?;
        self.process_net_batch(&state_store, &cgroup_resolver)
            .await?;

        // Clear batches
        self.exec_batch.clear();
        self.file_batch.clear();
        self.net_batch.clear();

        self.last_flush = Instant::now();
        self.batches_processed += 1;

        let duration = start.elapsed();
        trace!(
            exec_count,
            file_count,
            net_count,
            ?duration,
            "Event batch processed"
        );

        Ok(())
    }

    async fn process_exec_batch(
        &mut self,
        state_store: &Arc<Mutex<StateStore>>,
        cgroup_resolver: &Arc<Mutex<CgroupResolver>>,
    ) -> Result<(), ScannerError> {
        for event in &self.exec_batch {
            let cgroup_id = event.cgroup_id;

            // Resolve container ID
            let mut resolver = cgroup_resolver.lock().await;
            if let Some((container_id, _pid)) = resolver.resolve(cgroup_id).await {
                trace!(
                    cgroup_id,
                    container_id,
                    command = %c_string(&event.command),
                    "Resolved exec event"
                );
            }
            drop(resolver);
        }

        Ok(())
    }

    async fn process_file_batch(
        &mut self,
        state_store: &Arc<Mutex<StateStore>>,
        cgroup_resolver: &Arc<Mutex<CgroupResolver>>,
    ) -> Result<(), ScannerError> {
        for event in &self.file_batch {
            let path = c_string(&event.path);

            // Check for sensitive paths
            if is_sensitive_path(&path) {
                debug!(
                    cgroup_id = event.cgroup_id,
                    path = %path,
                    "Sensitive file access detected"
                );
            }
        }

        Ok(())
    }

    async fn process_net_batch(
        &mut self,
        state_store: &Arc<Mutex<StateStore>>,
        cgroup_resolver: &Arc<Mutex<CgroupResolver>>,
    ) -> Result<(), ScannerError> {
        for event in &self.net_batch {
            // Check for suspicious destinations
            if is_suspicious_destination(event.daddr, event.dport) {
                debug!(
                    cgroup_id = event.cgroup_id,
                    daddr = %format!("{}.{}", (event.daddr >> 24) & 0xFF, (event.daddr >> 16) & 0xFF),
                    dport = event.dport,
                    "Suspicious network connection"
                );
            }
        }

        Ok(())
    }

    // Event parsers
    fn parse_exec_event(&self, data: &[u8]) -> Option<ExecEvent> {
        if data.len() < std::mem::size_of::<ExecEvent>() {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const ExecEvent) })
    }

    fn parse_file_event(&self, data: &[u8]) -> Option<FileEvent> {
        if data.len() < std::mem::size_of::<FileEvent>() {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const FileEvent) })
    }

    fn parse_net_event(&self, data: &[u8]) -> Option<NetEvent> {
        if data.len() < std::mem::size_of::<NetEvent>() {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const NetEvent) })
    }

    // Filtering logic
    fn should_filter_exec(&self, event: &ExecEvent) -> bool {
        let command = c_string(&event.command);

        // Filter out known system processes
        let system_procs: BTreeSet<&str> = [
            "kworker",
            "ksoftirqd",
            "migration",
            "rcu_gp",
            "rcu_par_gp",
            "kthre",
            "systemd",
            "dbus-daemon",
            "networkd",
            "resolved",
        ]
        .iter()
        .cloned()
        .collect();

        if system_procs.iter().any(|p| command.starts_with(p)) {
            return true;
        }

        // Filter high-frequency but low-value events
        false
    }

    fn should_filter_file(&self, event: &FileEvent) -> bool {
        let path = c_string(&event.path);

        // Filter temporary files
        if path.starts_with("/tmp/") || path.starts_with("/var/tmp/") {
            // Still track mmap of shared libraries in tmp
            if !path.ends_with(".so") && event.kind == EventKind::Mmap {
                return true;
            }
        }

        // Filter proc and sys
        if path.starts_with("/proc/") || path.starts_with("/sys/") {
            return true;
        }

        false
    }

    fn should_filter_net(&self, event: &NetEvent) -> bool {
        // Filter localhost
        if event.daddr == 0x7F000001 || event.daddr == 0x0100007F {
            return true;
        }

        // Filter well-known internal DNS
        if event.dport == 53 {
            return false; // Always track DNS
        }

        false
    }

    pub fn get_stats(&self) -> ConsumerStats {
        ConsumerStats {
            events_received: self.events_received,
            events_dropped: self.events_dropped,
            events_filtered: self.events_filtered,
            batches_processed: self.batches_processed,
            exec_batch_size: self.exec_batch.len(),
            file_batch_size: self.file_batch.len(),
            net_batch_size: self.net_batch.len(),
        }
    }
}

#[derive(Debug)]
pub struct ConsumerStats {
    pub events_received: u64,
    pub events_dropped: u64,
    pub events_filtered: u64,
    pub batches_processed: u64,
    pub exec_batch_size: usize,
    pub file_batch_size: usize,
    pub net_batch_size: usize,
}

fn is_sensitive_path(path: &str) -> bool {
    let sensitive_paths: BTreeSet<&str> = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh",
        "/.dockerenv",
        "/.kube",
        "/var/run/secrets",
    ]
    .iter()
    .cloned()
    .collect();

    sensitive_paths.iter().any(|p| path.starts_with(p))
}

fn is_suspicious_destination(_addr: u32, port: u16) -> bool {
    // Check for common C2 ports
    let suspicious_ports: BTreeSet<u16> = [
        4444, 5555, 6666, 8888, 9999,  // Common malware ports
        31337, // Classic
    ]
    .iter()
    .cloned()
    .collect();

    suspicious_ports.contains(&port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_path_detection() {
        assert!(is_sensitive_path("/etc/passwd"));
        assert!(is_sensitive_path("/etc/passwd.backup"));
        assert!(!is_sensitive_path("/usr/bin/ls"));
    }

    #[test]
    fn test_suspicious_destination() {
        assert!(is_suspicious_destination(0x01020304, 4444));
        assert!(!is_suspicious_destination(0x01020304, 443));
    }
}
