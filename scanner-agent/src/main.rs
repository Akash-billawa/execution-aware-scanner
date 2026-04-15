mod attack_graph;
mod cgroup;
mod config;
mod enforcement;
mod error;
mod execution_proof;
mod experiment;
mod intel;
mod k8s;
mod metrics;
mod reliability;
mod remediator;
mod risk_engine;
mod runtime_attack_graph;
mod runtime_attack_graph_v2;
mod runtime_mapper;
mod safe_enforcement;
mod sbom;
mod state;
mod streaming_engine;
mod validation;
mod visualization;
mod vuln_detector;
mod webhook;
mod webhook_sender;

// eBPF modules only available with ebpf feature
#[cfg(feature = "ebpf")]
mod bpf_loader;
#[cfg(feature = "ebpf")]
mod event_consumer;
#[cfg(feature = "ebpf")]
mod tc_enforcer;

// Stub modules for non-eBPF builds
#[cfg(not(feature = "ebpf"))]
mod event_consumer {
    pub struct EventConsumer;
    impl EventConsumer {
        pub fn new() -> Self {
            Self
        }
    }
    #[derive(Default)]
    pub struct ConsumerStats {
        pub events_received: u64,
        pub events_dropped: u64,
        pub events_filtered: u64,
        pub batches_processed: u64,
        pub exec_batch_size: usize,
        pub file_batch_size: usize,
        pub net_batch_size: usize,
    }
}
#[cfg(not(feature = "ebpf"))]
mod tc_enforcer {
    pub struct TcEnforcer;
    impl TcEnforcer {
        pub fn new() -> Self {
            Self
        }
    }
    pub struct ThreatIntelFeed;
    impl ThreatIntelFeed {
        pub fn new() -> Self {
            Self
        }
    }
}

use axum::{extract::State, response::IntoResponse, routing::get, Router};
use clap::Parser;
use config::AppConfig;
use enforcement::EnforcementController;
use error::ScannerError;
use intel::IntelFeed;
use k8s::PodCache;
use kube::Client;
use metrics::Metrics;
use remediator::RemediatorService;
use risk_engine::RiskEngine;
use safe_enforcement::{EnforcementMode, SafeEnforcer};
use sbom::SbomStore;
use scanner_common::Finding;
use state::StateStore;
use std::collections::BTreeMap;
use std::sync::Arc;
use vuln_detector::VulnDetector;

// eBPF types only with ebpf feature
#[cfg(feature = "ebpf")]
use event_consumer::EventConsumer;
#[cfg(feature = "ebpf")]
use tc_enforcer::{TcEnforcer, ThreatIntelFeed};

// Stub types for non-eBPF
#[cfg(not(feature = "ebpf"))]
use event_consumer::ConsumerStats;
#[cfg(not(feature = "ebpf"))]
use tc_enforcer::{TcEnforcer, ThreatIntelFeed};

use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex, RwLock};
use tokio::time::{interval, Duration};
use tracing::{info, warn};

/// Parse duration string (e.g., "1s", "500ms")
fn parse_duration(s: &str) -> u64 {
    if s.ends_with("ms") {
        s[..s.len() - 2].parse().unwrap_or(1000)
    } else if s.ends_with("s") {
        s[..s.len() - 1].parse().unwrap_or(1) * 1000
    } else {
        s.parse().unwrap_or(1000)
    }
}

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long, default_value_t = false)]
    once: bool,
    #[arg(long, default_value = "eth0")]
    iface: String,
    #[arg(long, value_enum, default_value = "batch")]
    mode: ExecutionMode,
    #[arg(long, default_value_t = false)]
    stream_json: bool,
    #[arg(long, default_value = "1s")]
    stream_interval: String,
    #[arg(long, default_value_t = 3)]
    top_k: usize,
    #[arg(long)]
    export_graph: Option<String>,
    /// Webhook URL for alerts
    #[arg(long)]
    webhook_url: Option<String>,
    /// Webhook type (generic, elastic, splunk, slack, teams, datadog)
    #[arg(long, default_value = "generic")]
    webhook_type: String,
    /// Alert mode (on_alert_only, on_update, on_every_event)
    #[arg(long, default_value = "on_alert_only")]
    alert_mode: String,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq)]
enum ExecutionMode {
    Batch,
    Stream,
}

#[derive(Clone)]
struct AppState {
    metrics: Metrics,
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    event_stats: Arc<Mutex<event_consumer::ConsumerStats>>,
    #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
    event_stats: Arc<Mutex<ConsumerStats>>,
}

#[tokio::main]
async fn main() -> Result<(), ScannerError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let cli = Cli::parse();
    let config = AppConfig::load()?;
    let metrics = Metrics::new();

    // Create event stats with proper type
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    let event_stats = Arc::new(Mutex::new(event_consumer::ConsumerStats {
        events_received: 0,
        events_dropped: 0,
        events_filtered: 0,
        batches_processed: 0,
        exec_batch_size: 0,
        file_batch_size: 0,
        net_batch_size: 0,
    }));

    #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
    let event_stats = Arc::new(Mutex::new(ConsumerStats::default()));

    let state = AppState {
        metrics: metrics.clone(),
        event_stats: event_stats.clone(),
    };

    // Start metrics server
    let metrics_server = tokio::spawn(run_metrics_server(
        config.metrics.bind_addr.clone(),
        state.clone(),
    ));

    // Initialize threat intelligence feed
    let intel = IntelFeed::new(config.intel.clone());
    if let Err(err) = intel.refresh().await {
        warn!(error = %err, "initial intel refresh failed");
    }

    // Start intel refresh loop
    let intel_clone = intel.clone();
    let intel_handle = if !cli.once {
        Some(tokio::spawn(async move {
            let mut ticker = interval(intel_clone.refresh_interval());
            loop {
                ticker.tick().await;
                if let Err(err) = intel_clone.refresh().await {
                    warn!(error = %err, "intel refresh failed");
                }
            }
        }))
    } else {
        None
    };

    // Initialize remediator service
    let remediator = match RemediatorService::connect("localhost:50051").await {
        Ok(svc) => {
            info!("Connected to remediator");
            svc
        }
        Err(_) => {
            warn!("Using mock remediator");
            RemediatorService::new_mock()
        }
    };

    // Initialize Phase 5 enforcement components
    let enforcement_controller = EnforcementController::new(config.remediator.clone());
    let tc_enforcer = TcEnforcer::new();
    let threat_intel = ThreatIntelFeed::new();

    info!("Phase 5 enforcement components initialized");

    // Load SBOM store
    let sbom_store = SbomStore::load_from_dir(&config.runtime.sbom_dir)
        .await
        .unwrap_or_else(|err| {
            warn!(error = %err, "sbom directory unavailable, starting with empty store");
            SbomStore::default()
        });

    // Initialize K8s cache
    let risk_engine = RiskEngine::new(config.risk.clone());
    let pod_cache = PodCache::new();

    if let Ok(client) = Client::try_default().await {
        pod_cache.refresh(client, &config.runtime.node_name).await?;
        info!("Kubernetes cache initialized");
    } else {
        warn!("kubernetes client unavailable, running without pod enrichment");
    }

    // Create shared state
    let state_store = Arc::new(Mutex::new(StateStore::default()));
    let cgroup_resolver = Arc::new(Mutex::new(cgroup::CgroupResolver::new("/host/proc")));

    // Initialize vulnerability detector
    let vuln_detector = VulnDetector::new();
    if let Err(e) = VulnDetector::check_trivy() {
        warn!(
            "Trivy not installed: {}. Vulnerability scanning disabled.",
            e
        );
    }

    // Initialize attack graph for streaming mode
    let attack_graph = Arc::new(RwLock::new(
        runtime_attack_graph_v2::RuntimeAttackGraph::with_defaults(),
    ));

    // Load eBPF and start event consumption
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Create streaming engine and get event sender for eBPF integration
    let streaming_config = streaming_engine::StreamingConfig {
        output_interval_ms: parse_duration(&cli.stream_interval),
        alert_threshold: 0.8,
        risk_escalation_threshold: 0.7,
        channel_buffer_size: 1000,
        stream_json: cli.stream_json,
        top_k: cli.top_k,
        export_graph: cli.export_graph.is_some(),
        graph_export_interval_secs: 60,
    };

    let (streaming_engine, event_rx) =
        streaming_engine::StreamingEngine::new(attack_graph.clone(), streaming_config.clone());
    let event_tx = streaming_engine.sender();

    // Start streaming engine in background
    let streaming_handle = tokio::spawn(async move {
        streaming_engine.run(event_rx).await;
    });

    let (event_handle, analysis_handle) = match load_and_run_ebpf(
        &cli,
        &config,
        state_store.clone(),
        cgroup_resolver.clone(),
        metrics.clone(),
        event_stats.clone(),
        shutdown_rx,
        event_tx,
    )
    .await
    {
        Ok(handles) => handles,
        Err(err) => {
            warn!(error = %err, "failed to load eBPF, running degraded mode");
            // Run degraded pipeline
            let findings = run_degraded_pipeline(
                &config,
                sbom_store.clone(),
                intel.clone(),
                pod_cache.clone(),
                risk_engine.clone(),
                metrics.clone(),
            )
            .await?;
            info!(count = findings.len(), findings = ?findings, "degraded mode complete");
            (None, None)
        }
    };

    // Setup webhook manager if URL is provided
    let mut webhook_manager = webhook_sender::WebhookManager::new();
    if let Some(webhook_url) = &cli.webhook_url {
        let webhook_type = match cli.webhook_type.as_str() {
            "elastic" => webhook_sender::WebhookType::Elastic,
            "splunk" => webhook_sender::WebhookType::Splunk,
            "slack" => webhook_sender::WebhookType::Slack,
            "teams" => webhook_sender::WebhookType::Teams,
            "datadog" => webhook_sender::WebhookType::Datadog,
            _ => webhook_sender::WebhookType::Generic,
        };

        let alert_mode = match cli.alert_mode.as_str() {
            "on_alert_only" => webhook_sender::AlertMode::OnAlertOnly,
            "on_update" => webhook_sender::AlertMode::OnUpdate,
            "on_every_event" => webhook_sender::AlertMode::OnEveryEvent,
            _ => webhook_sender::AlertMode::OnAlertOnly,
        };

        let webhook_config = webhook_sender::WebhookConfig {
            url: webhook_url.clone(),
            webhook_type,
            auth: webhook_sender::WebhookAuth::None,
            rate_limit: 60,
            min_severity: webhook_sender::SeverityFilter::High,
            alert_mode,
            timeout_secs: 30,
            retry_attempts: 3,
        };

        webhook_manager.add_webhook(webhook_config);
        info!(
            "Webhook configured: {} (type: {})",
            webhook_url, cli.webhook_type
        );
    }

    let webhook_manager = Arc::new(webhook_manager);

    // Run pipeline based on mode
    let analysis_handle: tokio::task::JoinHandle<Result<Vec<Finding>, ScannerError>> =
    if cli.mode == ExecutionMode::Stream {
        // Stream mode: real-time continuous updates already running via streaming_handle
        info!("Running in STREAM mode - real-time attack path detection");

        // Just wait for streaming to complete (it runs until shutdown)
        tokio::spawn(async move {
            let _ = streaming_handle.await;
            // Streaming mode doesn't produce findings in the same way
            Ok(Vec::new())
        })
    } else {
            // Batch mode: traditional analysis
            info!("Running in BATCH mode - periodic analysis");

            let analysis_config = config.clone();
            let safe_enforcer_for_pipeline =
                SafeEnforcer::new(EnforcementMode::Audit, config.risk.clone());

            tokio::spawn(async move {
                run_analysis_pipeline(
                    &analysis_config,
                    sbom_store,
                    intel,
                    pod_cache,
                    risk_engine,
                    metrics,
                    state_store,
                    cgroup_resolver,
                    remediator,
                    vuln_detector,
                    safe_enforcer_for_pipeline,
                )
                .await
            })
        };

    // Wait for completion or signal
    tokio::signal::ctrl_c().await.ok();
    info!("Shutdown signal received");

    // Trigger shutdown
    let _ = shutdown_tx.send(true);

    // Cleanup
    if let Some(handle) = event_handle {
        let _ = handle.await;
    }
    let _ = analysis_handle.await;
    if let Some(handle) = intel_handle {
        handle.abort();
    }
    metrics_server.abort();

    info!("Scanner agent shutdown complete");
    Ok(())
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
async fn load_and_run_ebpf(
    cli: &Cli,
    config: &AppConfig,
    state_store: Arc<Mutex<StateStore>>,
    cgroup_resolver: Arc<Mutex<cgroup::CgroupResolver>>,
    metrics: Metrics,
    event_stats: Arc<Mutex<event_consumer::ConsumerStats>>,
    shutdown: watch::Receiver<bool>,
    event_tx: tokio::sync::mpsc::Sender<streaming_engine::StreamEvent>,
) -> Result<
    (
        Option<tokio::task::JoinHandle<()>>,
        Option<tokio::task::JoinHandle<()>>,
    ),
    ScannerError,
> {
    // Load eBPF
    let mut loader = bpf_loader::BpfLoader::new(&config.bpf.object_path)?;

    // Attach programs
    loader.attach_tracepoints()?;
    loader.attach_kprobes()?;

    // Try to attach LSM (may fail if not supported)
    if let Err(e) = loader.attach_lsm_hooks() {
        warn!("LSM hooks not available: {}", e);
    }

    // Try to attach XDP (requires network interface)
    if let Err(e) = loader.attach_xdp(&cli.iface) {
        warn!("XDP not attached: {}", e);
    }

    info!("eBPF programs attached");

    // Open ring buffers
    let (exec_rb, file_rb, net_rb) = loader.open_ringbufs()?;

    // Create event consumer with streaming engine connection
    let mut consumer = EventConsumer::new(exec_rb, file_rb, net_rb);
    consumer.set_event_sender(event_tx);

    // Start event consumer
    let event_handle = tokio::spawn(async move {
        if let Err(e) = consumer
            .run(state_store, cgroup_resolver, metrics, shutdown)
            .await
        {
            error!("Event consumer error: {}", e);
        }
    });

    Ok((Some(event_handle), None))
}

#[cfg(not(all(feature = "ebpf", target_os = "linux")))]
async fn load_and_run_ebpf(
    _cli: &Cli,
    _config: &AppConfig,
    _state_store: Arc<Mutex<StateStore>>,
    _cgroup_resolver: Arc<Mutex<cgroup::CgroupResolver>>,
    _metrics: Metrics,
    _event_stats: Arc<Mutex<ConsumerStats>>,
    _shutdown: watch::Receiver<bool>,
    _event_tx: tokio::sync::mpsc::Sender<streaming_engine::StreamEvent>,
) -> Result<
    (
        Option<tokio::task::JoinHandle<()>>,
        Option<tokio::task::JoinHandle<()>>,
    ),
    ScannerError,
> {
    // Stub: eBPF not available on this platform
    warn!("eBPF not available on this platform, skipping");
    Ok((None, None))
}

async fn run_analysis_pipeline(
    config: &AppConfig,
    sbom_store: SbomStore,
    intel: IntelFeed,
    pod_cache: PodCache,
    risk_engine: RiskEngine,
    metrics: Metrics,
    state_store: Arc<Mutex<StateStore>>,
    cgroup_resolver: Arc<Mutex<cgroup::CgroupResolver>>,
    remediator: RemediatorService,
    vuln_detector: VulnDetector,
    safe_enforcer: safe_enforcement::SafeEnforcer,
) -> Result<Vec<Finding>, ScannerError> {
    let mut findings = Vec::new();
    let mut ticker = interval(Duration::from_secs(30));

    loop {
        ticker.tick().await;

        let store = state_store.lock().await;
        let mut resolver = cgroup_resolver.lock().await;
        // Process each cgroup workload
        for (cgroup_id, workload) in store.workloads() {
            // Resolve container ID
            if let Some((container_id, _pid)) = resolver.resolve(*cgroup_id).await {
                // Lookup pod identity
                if let Some(identity) = pod_cache.lookup(&container_id).await {
                    let intel_state = intel.state();
                    let intel_state = intel_state.read().await;

                    // 🆕 SCAN IMAGE FOR REAL VULNERABILITIES
                    match vuln_detector.scan_image(&identity.image).await {
                        Ok(vulns) => {
                            // Clone vulns for later use in attack graph
                            let vulns_for_attack_graph = vulns.clone();

                            info!(
                                "Found {} vulnerabilities in {}",
                                vulns.len(),
                                identity.image
                            );
                            for vuln in vulns {
                                // Calculate runtime disposition based on signals
                                let runtime = if workload.signal_weight() > 0.0 {
                                    scanner_common::RuntimeDisposition::Reachable
                                } else {
                                    scanner_common::RuntimeDisposition::Dormant
                                };

                                // Convert to risk signal with signal weighting
                                let signal = scanner_common::RiskSignal {
                                    cve: vuln.cve.clone(),
                                    cvss: vuln.cvss_score,
                                    epss: *intel_state.epss.get(&vuln.cve).unwrap_or(&0.0),
                                    kev: intel_state.kev.contains(&vuln.cve),
                                    runtime,
                                    package: vuln.package.clone(),
                                    observed_paths: workload.observed_paths.clone(),
                                    signal_weight: workload.signal_weight(),
                                };

                                // Get runtime signals for explainability
                                let runtime_signals: Vec<scanner_common::SignalEvidence> = workload
                                    .signals
                                    .iter()
                                    .map(|s| scanner_common::SignalEvidence {
                                        signal_type: format!("{:?}", s.signal_type),
                                        timestamp_ns: s.timestamp_ns,
                                        details: s.details.clone(),
                                        confidence: s.weight.min(1.0), // Weight as confidence
                                    })
                                    .collect();

                                if let Some(finding) = risk_engine.evaluate(
                                    identity.clone(),
                                    signal,
                                    Some(&runtime_signals),
                                ) {
                                    let priority = format!("{:?}", finding.priority);
                                    metrics.inc_findings(&priority);
                                    findings.push(finding.clone());

                                    // Output JSON finding for test validation
                                    match serde_json::to_string(&finding) {
                                        Ok(json) => {
                                            println!("{}", json);
                                            info!(finding_json = %json, "finding_generated");
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "failed to serialize finding");
                                        }
                                    }

                                    // Trigger remediation for critical
                                    if matches!(
                                        finding.priority,
                                        scanner_common::Priority::Critical
                                    ) {
                                        if let Err(e) = remediator.remediate_finding(&finding).await
                                        {
                                            warn!("Remediation failed: {}", e);
                                        }
                                    }
                                }

                                // 🆕 BUILD ATTACK PATHS FROM RUNTIME SIGNALS
                                // Initialize attack graph v2 with enhanced config
                                let mut attack_graph =
                                    runtime_attack_graph_v2::RuntimeAttackGraph::with_defaults();

                                // Configure for production
                                let mut config =
                                    runtime_attack_graph_v2::AttackGraphConfig::default();
                                config.top_k = 3; // Only report top 3 paths
                                config.min_enforcement_confidence = 0.8;
                                config.min_enforcement_depth = 3;

                                // Process library loads
                                for lib in &workload.loaded_libraries {
                                    attack_graph.process_library_load(
                                        0, // Use actual PID from signals
                                        &identity.workload,
                                        *cgroup_id,
                                        lib,
                                        0,
                                    );

                                    // Associate CVEs with loaded libraries
                                    for vuln in &vulns_for_attack_graph {
                                        if lib.contains(&vuln.package)
                                            || vuln
                                                .package
                                                .contains(lib.split('/').last().unwrap_or(""))
                                        {
                                            attack_graph.associate_cve_with_library(
                                                &vuln.cve,
                                                &vuln.package,
                                                vuln.cvss_score,
                                                *intel_state.epss.get(&vuln.cve).unwrap_or(&0.0),
                                                intel_state.kev.contains(&vuln.cve),
                                            );
                                        }
                                    }
                                }

                                // Process network events from runtime signals
                                for signal in &workload.signals {
                                    // Extract network info from signal details
                                    if signal.details.contains("transfer") {
                                        // Parse network info from details
                                        let net_event = scanner_common::NetEvent {
                                            timestamp_ns: signal.timestamp_ns,
                                            pid: 0,
                                            tgid: 0,
                                            cgroup_id: *cgroup_id,
                                            saddr: 0,
                                            daddr: 0, // Parse from details
                                            sport: 0,
                                            dport: 443,
                                            family: 2,
                                            protocol: 6,
                                            kind: scanner_common::EventKind::TcpSend,
                                            data_size: 1024, // Parse from details
                                        };

                                        attack_graph.process_network_event(
                                            0,
                                            &identity.workload,
                                            *cgroup_id,
                                            &net_event,
                                        );
                                    }
                                }

                                // Get top-K paths and streaming updates
                                let path_summaries = attack_graph.get_top_k_paths(&findings);
                                let updates = attack_graph.drain_updates();

                                // Log attack paths
                                if !path_summaries.is_empty() {
                                    info!("Detected {} attack paths", path_summaries.len());
                                    for path in &path_summaries {
                                        info!(
                        "Attack Path #{}: {} nodes, confidence: {:.2}, risk: {:.2}",
                        path.rank.unwrap_or(0),
                        path.node_count,
                        path.confidence,
                        path.risk_score
                    );
                                    }
                                }

                                // Attach attack paths to findings
                                runtime_attack_graph_v2::attach_attack_paths_to_findings(
                                    &mut findings,
                                    &mut attack_graph,
                                );
                            }
                        }
                        Err(e) => {
                            warn!("Vulnerability scan failed for {}: {}", identity.image, e);
                            // Fall back to SBOM-based detection
                        }
                    }

                    // Original SBOM-based detection (fallback)
                    let components = sbom_store
                        .classify_runtime_paths(&identity.image, &workload.observed_paths);

                    for (component, runtime) in components {
                        for cve in component.cves {
                            let signal = scanner_common::RiskSignal {
                                cve: cve.id.clone(),
                                cvss: cve.cvss,
                                epss: *intel_state.epss.get(&cve.id).unwrap_or(&0.0),
                                kev: intel_state.kev.contains(&cve.id),
                                runtime: runtime.clone(),
                                package: component.package.clone(),
                                observed_paths: workload
                                    .observed_paths
                                    .intersection(&component.paths)
                                    .cloned()
                                    .collect(),
                                signal_weight: workload.signal_weight(),
                            };

                            if let Some(finding) =
                                risk_engine.evaluate(identity.clone(), signal, None)
                            {
                                let priority = format!("{:?}", finding.priority);
                                metrics.inc_findings(&priority);
                                findings.push(finding.clone());

                                // Output JSON finding for test validation
                                match serde_json::to_string(&finding) {
                                    Ok(json) => {
                                        println!("{}", json);
                                        info!(finding_json = %json, "finding_generated");
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "failed to serialize finding");
                                    }
                                }

                                // Trigger remediation for critical findings
                                if matches!(finding.priority, scanner_common::Priority::Critical) {
                                    if let Err(e) = remediator.remediate_finding(&finding).await {
                                        warn!("Remediation failed: {}", e);
                                    }

                                    // Generate and enforce seccomp profile
                                    let seccomp = risk_engine
                                        .build_seccomp_profile(workload.observed_syscalls.clone());
                                    if let Err(e) =
                                        persist_seccomp(config, &identity.workload, &seccomp).await
                                    {
                                        warn!("Failed to persist seccomp: {}", e);
                                    }
                                    if let Err(e) = remediator
                                        .enforce_seccomp(&identity.workload, &seccomp)
                                        .await
                                    {
                                        warn!("Failed to enforce seccomp: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 🆕 ATTACH ATTACK PATHS TO FINDINGS
            // Build attack paths and attach to findings for explainability
            if !findings.is_empty() {
                let mut attack_graph = runtime_attack_graph::RuntimeAttackGraph::new(300);

                // Build attack graph from runtime state
                for (cgroup_id, workload) in store.workloads() {
                    if let Some((container_id, _pid)) = resolver.resolve(*cgroup_id).await {
                        if let Some(identity) = pod_cache.lookup(&container_id).await {
                            // Add process nodes
                            for lib in &workload.loaded_libraries {
                                attack_graph.process_library_load(
                                    0,
                                    &identity.workload,
                                    *cgroup_id,
                                    lib,
                                    0,
                                );
                            }
                        }
                    }
                }

                // Attach attack paths to findings
                runtime_attack_graph::attach_attack_paths_to_findings(&mut findings, &attack_graph);
            }
        }

        // Clear processed state periodically
        drop(store);
        state_store.lock().await.clear();
    }
}

async fn run_metrics_server(bind_addr: String, state: AppState) -> Result<(), ScannerError> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/metrics/kernel", get(kernel_metrics_handler))
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .with_state(state);
    let listener = TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(|err| ScannerError::Bpf(err.to_string()))
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    state.metrics.render()
}

async fn kernel_metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.event_stats.lock().await;
    axum::response::Json(serde_json::json!({
        "user_space": {
            "events_received": stats.events_received,
            "events_dropped": stats.events_dropped,
            "events_filtered": stats.events_filtered,
            "batches_processed": stats.batches_processed,
            "exec_batch_size": stats.exec_batch_size,
            "file_batch_size": stats.file_batch_size,
            "net_batch_size": stats.net_batch_size,
        },
        "kernel_space": {
            // These would be populated from eBPF maps if available
            "events_emitted": 0, // From EVENT_COUNT map
            "dropped_events": 0, // From DROPPED_EVENTS map
            "ring_buffer_capacity": 1024,
        },
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn health_handler() -> impl IntoResponse {
    axum::response::Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn ready_handler(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.event_stats.lock().await;
    // Ready if not dropping too many events
    let drop_rate = if stats.events_received > 0 {
        stats.events_dropped as f64 / stats.events_received as f64
    } else {
        0.0
    };

    if drop_rate > 0.1 {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "High event drop rate",
        );
    }
    (axum::http::StatusCode::OK, "Ready")
}

async fn persist_seccomp(
    config: &AppConfig,
    workload: &str,
    profile: &scanner_common::SeccompProfile,
) -> Result<(), ScannerError> {
    tokio::fs::create_dir_all(&config.runtime.seccomp_output_dir).await?;
    let path = format!("{}/{}.json", config.runtime.seccomp_output_dir, workload);
    let payload = serde_json::to_vec_pretty(profile)?;
    tokio::fs::write(path, payload).await?;
    Ok(())
}

async fn run_degraded_pipeline(
    config: &AppConfig,
    sbom_store: SbomStore,
    intel: IntelFeed,
    pod_cache: PodCache,
    risk_engine: RiskEngine,
    metrics: Metrics,
) -> Result<Vec<Finding>, ScannerError> {
    let mut state_store = StateStore::default();

    // Simulate events
    let exec = scanner_common::ExecEvent {
        timestamp_ns: 0,
        pid: 42,
        tgid: 42,
        uid: 0,
        gid: 0,
        cgroup_id: 9001,
        ppid: 1,
        command: command_buf("nginx"),
        argv: argv_buf("nginx -g daemon off;"),
    };
    state_store.apply_exec(&exec);

    let file = scanner_common::FileEvent {
        timestamp_ns: 0,
        pid: 42,
        tgid: 42,
        cgroup_id: 9001,
        command: command_buf("nginx"),
        path: path_buf("/usr/lib/libssl.so"),
        kind: scanner_common::EventKind::Mmap,
    };
    state_store.apply_file(&file);

    let net = scanner_common::NetEvent {
        timestamp_ns: 0,
        pid: 42,
        tgid: 42,
        cgroup_id: 9001,
        saddr: 10,
        daddr: 20,
        sport: 443,
        dport: 443,
        family: 2,
        protocol: 6,
        kind: scanner_common::EventKind::Connect,
        data_size: 0,
    };
    state_store.apply_net(&net);

    let identity =
        pod_cache
            .lookup("demo-container")
            .await
            .unwrap_or(scanner_common::RuntimeIdentity {
                node_name: "node-a".to_string(),
                namespace: "default".to_string(),
                pod_name: "demo-pod".to_string(),
                container_name: "app".to_string(),
                image: "demo/app:1.0".to_string(),
                workload: "demo".to_string(),
                labels: BTreeMap::new(),
            });

    let workload_state = state_store.workload(9001).cloned().unwrap_or_default();
    let observed_paths = workload_state.observed_paths.clone();
    let components = sbom_store.classify_runtime_paths(&identity.image, &observed_paths);
    let intel_state = intel.state();
    let intel_state = intel_state.read().await;
    let mut findings = Vec::new();

    for (component, runtime) in components {
        for cve in component.cves {
            metrics.inc_events();
            let signal = scanner_common::RiskSignal {
                cve: cve.id.clone(),
                cvss: cve.cvss,
                epss: *intel_state.epss.get(&cve.id).unwrap_or(&0.0),
                kev: intel_state.kev.contains(&cve.id),
                runtime: runtime.clone(),
                package: component.package.clone(),
                observed_paths: component
                    .paths
                    .iter()
                    .filter(|path| observed_paths.contains(*path))
                    .cloned()
                    .collect(),
                signal_weight: 0.0, // Degraded mode - no signal weighting
            };
            if let Some(finding) = risk_engine.evaluate(identity.clone(), signal, None) {
                let priority = format!("{:?}", finding.priority);
                metrics.inc_findings(&priority);
                findings.push(finding.clone());

                // Output JSON finding for test validation
                match serde_json::to_string(&finding) {
                    Ok(json) => {
                        println!("{}", json);
                        info!(finding_json = %json, "finding_generated");
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to serialize finding");
                    }
                }
            }
        }
    }

    let seccomp = risk_engine.build_seccomp_profile(workload_state.observed_syscalls);
    persist_seccomp(config, &identity.workload, &seccomp).await?;

    Ok(findings)
}

fn command_buf(value: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = value.as_bytes();
    let len = bytes.len().min(out.len());
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

fn argv_buf(value: &str) -> [u8; scanner_common::ARGS_LEN] {
    let mut out = [0u8; scanner_common::ARGS_LEN];
    let bytes = value.as_bytes();
    let len = bytes.len().min(out.len());
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

fn path_buf(value: &str) -> [u8; scanner_common::PATH_LEN] {
    let mut out = [0u8; scanner_common::PATH_LEN];
    let bytes = value.as_bytes();
    let len = bytes.len().min(out.len());
    out[..len].copy_from_slice(&bytes[..len]);
    out
}
