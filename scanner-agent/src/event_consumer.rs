#![cfg(all(feature = "ebpf", target_os = "linux"))]

use crate::bpf_loader::EventSources;
use crate::cgroup::CgroupResolver;
use crate::error::ScannerError;
use crate::metrics::Metrics;
use crate::runtime_attack_graph_v2::{GraphUpdate, RuntimeEdge};
use crate::state::StateStore;
use aya::maps::{MapData, RingBuf};
use scanner_common::{c_string, EventKind, ExecEvent, FileEvent, NetEvent};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, error, info, trace, warn};

pub struct EventConsumer {
    exec_rb: Option<RingBuf<MapData>>,
    file_rb: Option<RingBuf<MapData>>,
    net_rb: Option<RingBuf<MapData>>,
    security_rb: Option<RingBuf<MapData>>,

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

    // Event bus sender for streaming engine
    event_tx: Option<tokio::sync::mpsc::Sender<crate::streaming_engine::StreamEvent>>,
}

impl EventConsumer {
    pub fn new(event_sources: EventSources) -> Self {
        let (exec_rb, file_rb, net_rb, security_rb) = match event_sources {
            EventSources::Legacy {
                exec_rb,
                file_rb,
                net_rb,
            } => (Some(exec_rb), Some(file_rb), Some(net_rb), None),
            EventSources::Unified { security_rb } => (None, None, None, Some(security_rb)),
        };

        Self {
            exec_rb,
            file_rb,
            net_rb,
            security_rb,
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
            event_tx: None,
        }
    }

    /// Set the event bus sender for streaming engine integration
    pub fn set_event_sender(
        &mut self,
        sender: tokio::sync::mpsc::Sender<crate::streaming_engine::StreamEvent>,
    ) {
        self.event_tx = Some(sender);
    }

    /// Emit a BPF event to the streaming engine
    async fn emit_bpf_event(&self, timestamp_ns: u64, kind: &str, details: &str) {
        if let Some(tx) = &self.event_tx {
            let event = crate::streaming_engine::StreamEvent::BpfEvent {
                timestamp_ns,
                kind: kind.to_string(),
                details: details.to_string(),
            };
            let _ = tx.send(event).await;
        }
    }

    /// Emit a graph update event
    async fn emit_graph_update(&self, update: crate::runtime_attack_graph_v2::GraphUpdate) {
        if let Some(tx) = &self.event_tx {
            let event = crate::streaming_engine::StreamEvent::GraphUpdate(update);
            let _ = tx.send(event).await;
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

            if self.security_rb.is_some() {
                events_this_iter += self.consume_security_batch(&state_store, metrics).await?;
            } else {
                events_this_iter += self.consume_exec_batch(&state_store, metrics).await?;
                events_this_iter += self.consume_file_batch(&state_store, metrics).await?;
                events_this_iter += self.consume_net_batch(&state_store, metrics).await?;
            }

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
                    if self.security_rb.is_some() {
                        let _ = self.consume_security_batch(&state_store, &metrics).await;
                    } else {
                        let _ = self.consume_exec_batch(&state_store, &metrics).await;
                        let _ = self.consume_file_batch(&state_store, &metrics).await;
                        let _ = self.consume_net_batch(&state_store, &metrics).await;
                    }

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
        let Some(exec_rb) = self.exec_rb.as_mut() else {
            return Ok(0);
        };

        loop {
            let item = match exec_rb.next() {
                Some(i) => i,
                None => break,
            };
            self.events_received += 1;
            // Extract data and drop item immediately to release borrow
            let data_bytes: Vec<u8> = (*item).to_vec();
            drop(item);

            // Parse and process after item is dropped
            let event_opt = Self::parse_exec_event(&data_bytes);

            if let Some(event) = event_opt {
                // Apply filtering
                if Self::should_filter_exec(&event) {
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
            } else {
                self.events_dropped += 1;
                warn!("Failed to parse exec event");
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
        let Some(file_rb) = self.file_rb.as_mut() else {
            return Ok(0);
        };

        loop {
            let item = match file_rb.next() {
                Some(i) => i,
                None => break,
            };
            self.events_received += 1;
            // Extract data and drop item immediately to release borrow
            let data_bytes: Vec<u8> = (*item).to_vec();
            drop(item);

            // Parse and process after item is dropped
            let event_opt = Self::parse_file_event(&data_bytes);

            if let Some(event) = event_opt {
                if Self::should_filter_file(&event) {
                    self.events_filtered += 1;
                    continue;
                }

                self.file_batch.push(event);
                count += 1;

                let mut store = state_store.lock().await;
                store.apply_file(&event);
                drop(store);

                metrics.inc_events();
            } else {
                self.events_dropped += 1;
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
        let Some(net_rb) = self.net_rb.as_mut() else {
            return Ok(0);
        };

        loop {
            let item = match net_rb.next() {
                Some(i) => i,
                None => break,
            };
            self.events_received += 1;
            // Extract data and drop item immediately to release borrow
            let data_bytes: Vec<u8> = (*item).to_vec();
            drop(item);

            // Parse and process after item is dropped
            let event_opt = Self::parse_net_event(&data_bytes);

            if let Some(event) = event_opt {
                if Self::should_filter_net(&event) {
                    self.events_filtered += 1;
                    continue;
                }

                self.net_batch.push(event);
                count += 1;

                let mut store = state_store.lock().await;
                store.apply_net(&event);
                drop(store);

                metrics.inc_events();
            } else {
                self.events_dropped += 1;
            }

            if self.net_batch.len() >= self.batch_size {
                break;
            }
        }

        Ok(count)
    }

    async fn consume_security_batch(
        &mut self,
        state_store: &Arc<Mutex<StateStore>>,
        metrics: &Metrics,
    ) -> Result<usize, ScannerError> {
        let mut count = 0;
        let Some(security_rb) = self.security_rb.as_mut() else {
            return Ok(0);
        };

        loop {
            let item = match security_rb.next() {
                Some(i) => i,
                None => break,
            };
            self.events_received += 1;
            let data_bytes: Vec<u8> = (*item).to_vec();
            drop(item);

            if let Some(event) = Self::parse_security_event(&data_bytes) {
                let mut store = state_store.lock().await;
                let mut accepted = false;

                if let Some(exec) = Self::security_to_exec(&event) {
                    if !Self::should_filter_exec(&exec) {
                        self.exec_batch.push(exec);
                        if let Some(last) = self.exec_batch.last() {
                            store.apply_exec(last);
                            accepted = true;
                        }
                    }
                }
                if let Some(file) = Self::security_to_file(&event) {
                    if !Self::should_filter_file(&file) {
                        self.file_batch.push(file);
                        if let Some(last) = self.file_batch.last() {
                            store.apply_file(last);
                            accepted = true;
                        }
                    }
                }
                if let Some(net) = Self::security_to_net(&event) {
                    if !Self::should_filter_net(&net) {
                        self.net_batch.push(net);
                        if let Some(last) = self.net_batch.last() {
                            store.apply_net(last);
                            accepted = true;
                        }
                    }
                }
                drop(store);

                if accepted {
                    count += 1;
                    metrics.inc_events();
                } else {
                    self.events_filtered += 1;
                }
            } else {
                self.events_dropped += 1;
            }

            if self.exec_batch.len() >= self.batch_size
                || self.file_batch.len() >= self.batch_size
                || self.net_batch.len() >= self.batch_size
            {
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
            let command = c_string(&event.command);

            // Resolve container ID
            let mut resolver = cgroup_resolver.lock().await;
            if let Some((container_id, _pid)) = resolver.resolve(cgroup_id).await {
                trace!(
                    cgroup_id,
                    container_id,
                    command = %command,
                    "Resolved exec event"
                );
            }
            drop(resolver);

            // Emit BPF event for new process execution
            self.emit_bpf_event(
                event.timestamp_ns,
                "exec",
                &format!("pid={} command={}", event.pid, command),
            )
            .await;

            // Emit graph update for new process
            let process_node_id = format!("proc:{}:{}", event.pid, command);
            let cgroup_node_id = format!("cgroup:{}", cgroup_id);

            let update = GraphUpdate::EdgeAdded {
                from: cgroup_node_id,
                to: process_node_id,
                edge: RuntimeEdge::ProcessCreated {
                    timestamp_ns: event.timestamp_ns,
                    confidence: 1.0,
                },
            };
            self.emit_graph_update(update).await;
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
                self.emit_bpf_event(event.timestamp_ns, "file", &format!("sensitive: {}", path))
                    .await;
            }

            // Emit graph updates for library loads
            if event.kind == EventKind::Mmap && is_shared_library(&path) {
                // Get process info from cgroup resolver
                let mut resolver = cgroup_resolver.lock().await;
                let process_name = if let Some((_, pid)) = resolver.resolve(event.cgroup_id).await {
                    format!("pid-{}", pid)
                } else {
                    "unknown".to_string()
                };
                drop(resolver);

                // Emit BPF event for library load
                self.emit_bpf_event(
                    event.timestamp_ns,
                    "library_load",
                    &format!("{} -> {}", process_name, path),
                )
                .await;

                // Emit graph update for library load
                let process_node_id = format!("proc:{}:{}", event.pid, process_name);
                let lib_node_id = format!("lib:{}", path);

                let update = GraphUpdate::EdgeAdded {
                    from: process_node_id,
                    to: lib_node_id,
                    edge: RuntimeEdge::LibraryLoaded {
                        timestamp_ns: event.timestamp_ns,
                        confidence: 1.0,
                    },
                };
                self.emit_graph_update(update).await;
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
            let daddr_str = format!(
                "{}.{}.{}.{}",
                (event.daddr >> 24) & 0xFF,
                (event.daddr >> 16) & 0xFF,
                (event.daddr >> 8) & 0xFF,
                event.daddr & 0xFF
            );

            // Check for suspicious destinations
            if is_suspicious_destination(event.daddr, event.dport) {
                debug!(
                    cgroup_id = event.cgroup_id,
                    daddr = %daddr_str,
                    dport = event.dport,
                    "Suspicious network connection"
                );
                self.emit_bpf_event(
                    event.timestamp_ns,
                    "suspicious_net",
                    &format!("{}:{}", daddr_str, event.dport),
                )
                .await;
            }

            // Emit graph update for network connections
            if event.kind == EventKind::Connect {
                // Get process info
                let mut resolver = cgroup_resolver.lock().await;
                let process_name = if let Some((_, pid)) = resolver.resolve(event.cgroup_id).await {
                    format!("pid-{}", pid)
                } else {
                    "unknown".to_string()
                };
                drop(resolver);

                let process_node_id = format!("proc:{}:{}", event.pid, process_name);
                let net_node_id = format!("net:{}:{}", daddr_str, event.dport);

                let update = GraphUpdate::EdgeAdded {
                    from: process_node_id,
                    to: net_node_id,
                    edge: RuntimeEdge::NetworkConnection {
                        timestamp_ns: event.timestamp_ns,
                        total_bytes: event.data_size as u64,
                        event_count: 1,
                        confidence: 1.0,
                    },
                };
                self.emit_graph_update(update).await;
            }
        }

        Ok(())
    }

    // Event parsers
    fn parse_exec_event(data: &[u8]) -> Option<ExecEvent> {
        if data.len() < std::mem::size_of::<ExecEvent>() {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const ExecEvent) })
    }

    fn parse_file_event(data: &[u8]) -> Option<FileEvent> {
        if data.len() < std::mem::size_of::<FileEvent>() {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const FileEvent) })
    }

    fn parse_net_event(data: &[u8]) -> Option<NetEvent> {
        if data.len() < std::mem::size_of::<NetEvent>() {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const NetEvent) })
    }

    fn parse_security_event(data: &[u8]) -> Option<SecurityEvent> {
        if data.len() < std::mem::size_of::<SecurityEvent>() {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const SecurityEvent) })
    }

    fn security_to_exec(event: &SecurityEvent) -> Option<ExecEvent> {
        if event.kind != SecurityEventKind::Exec {
            return None;
        }

        let exec = unsafe { event.data.exec };
        let mut argv = [0u8; 256];
        argv[..exec.args.len()].copy_from_slice(&exec.args);

        Some(ExecEvent {
            timestamp_ns: event.ts,
            pid: event.pid,
            tgid: event.tgid,
            uid: event.uid,
            gid: event.gid,
            cgroup_id: event.cgroup_id,
            ppid: exec.ppid,
            command: event.comm,
            argv,
        })
    }

    fn security_to_file(event: &SecurityEvent) -> Option<FileEvent> {
        let kind = match event.kind {
            SecurityEventKind::File => EventKind::Open,
            SecurityEventKind::Mmap => EventKind::Mmap,
            _ => return None,
        };

        let file = unsafe { event.data.file };
        let mut path = [0u8; 256];
        path[..file.path.len()].copy_from_slice(&file.path);

        Some(FileEvent {
            timestamp_ns: event.ts,
            pid: event.pid,
            tgid: event.tgid,
            cgroup_id: event.cgroup_id,
            command: event.comm,
            path,
            kind,
        })
    }

    fn security_to_net(event: &SecurityEvent) -> Option<NetEvent> {
        let net = unsafe { event.data.net };
        let kind = match event.kind {
            SecurityEventKind::Connect => EventKind::Connect,
            SecurityEventKind::NetTransfer => {
                if net.protocol == 17 {
                    EventKind::UdpSend
                } else {
                    EventKind::TcpSend
                }
            }
            _ => return None,
        };

        Some(NetEvent {
            timestamp_ns: event.ts,
            pid: event.pid,
            tgid: event.tgid,
            cgroup_id: event.cgroup_id,
            saddr: net.saddr,
            daddr: net.daddr,
            sport: net.sport,
            dport: net.dport,
            family: 2,
            protocol: net.protocol,
            kind,
            data_size: net.bytes.min(u32::MAX as u64) as u32,
        })
    }

    // Filtering logic
    fn should_filter_exec(event: &ExecEvent) -> bool {
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

    fn should_filter_file(event: &FileEvent) -> bool {
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

    fn should_filter_net(event: &NetEvent) -> bool {
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

    /// Read kernel-level metrics from eBPF maps
    /// SAFETY: Requires eBPF maps to be loaded
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    pub fn read_kernel_metrics(&self, bpf: &aya::Ebpf) -> Result<KernelMetrics, ScannerError> {
        use aya::maps::HashMap;

        let mut metrics = KernelMetrics::default();

        // Read dropped events counter
        if let Ok(dropped_map) = HashMap::<_, u32, u64>::try_from(
            bpf.map("DROPPED_EVENTS")
                .ok_or_else(|| ScannerError::Bpf("DROPPED_EVENTS map not found".to_string()))?,
        ) {
            if let Ok(count) = dropped_map.get(&0, 0) {
                metrics.dropped_events = count;
            }
        }

        // Read event counter
        if let Ok(count_map) = HashMap::<_, u32, u64>::try_from(
            bpf.map("EVENT_COUNT")
                .ok_or_else(|| ScannerError::Bpf("EVENT_COUNT map not found".to_string()))?,
        ) {
            if let Ok(count) = count_map.get(&0, 0) {
                metrics.events_emitted = count;
            }
        }

        Ok(metrics)
    }
}

/// Kernel-level metrics from eBPF
#[derive(Debug, Default)]
pub struct KernelMetrics {
    pub events_emitted: u64,
    pub dropped_events: u64,
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

/// Check if path is a shared library
fn is_shared_library(path: &str) -> bool {
    path.ends_with(".so")
        || path.contains(".so.")
        || path.ends_with(".so.1")
        || path.ends_with(".so.2")
        || path.contains("/lib/")
        || path.contains("/usr/lib/")
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum SecurityEventKind {
    Exec = 0,
    File = 1,
    Mmap = 2,
    Connect = 3,
    NetTransfer = 4,
    Dns = 5,
    Exit = 6,
    Suspicious = 7,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SecurityEvent {
    ts: u64,
    kind: SecurityEventKind,
    pid: u32,
    tgid: u32,
    uid: u32,
    gid: u32,
    cgroup_id: u64,
    confidence: u8,
    data: SecurityEventData,
    comm: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
union SecurityEventData {
    exec: SecurityExecData,
    file: SecurityFileData,
    net: SecurityNetData,
    raw: [u8; 128],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SecurityExecData {
    ppid: u32,
    is_setuid: u8,
    _pad: [u8; 3],
    args: [u8; 120],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SecurityFileData {
    path: [u8; 96],
    flags: u32,
    is_sensitive: u8,
    _pad: [u8; 27],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SecurityNetData {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
    bytes: u64,
    protocol: u8,
    is_external: u8,
    is_suspicious_port: u8,
    _pad: [u8; 101],
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
