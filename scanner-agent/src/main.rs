mod cgroup;
mod config;
mod enforcement;
mod error;
mod intel;
mod k8s;
mod metrics;
mod remediator;
mod risk_engine;
mod sbom;
mod state;
mod webhook;

// eBPF modules only available on Linux with ebpf feature
#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod bpf_loader;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod event_consumer;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod tc_enforcer;

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
use risk::RiskEngine;
use scanner_common::Finding;
use sbom::SbomStore;
use state::StateStore;
use std::collections::BTreeMap;
use std::sync::Arc;

// eBPF types only on Linux
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use event_consumer::EventConsumer;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use tc_enforcer::{TcEnforcer, ThreatIntelFeed};
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex};
use tokio::time::{interval, Duration, Instant};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long, default_value_t = false)]
    once: bool,
    #[arg(long, default_value = "eth0")]
    iface: String,
}

#[derive(Clone)]
struct AppState {
    metrics: Metrics,
    event_stats: Arc<Mutex<event_consumer::ConsumerStats>>,
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
    let event_stats = Arc::new(Mutex::new(event_consumer::ConsumerStats {
        events_received: 0,
        events_dropped: 0,
        events_filtered: 0,
        batches_processed: 0,
        exec_batch_size: 0,
        file_batch_size: 0,
        net_batch_size: 0,
    }));
    
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

    // Load eBPF and start event consumption
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_handle, analysis_handle) = match load_and_run_ebpf(
        &cli,
        &config,
        state_store.clone(),
        cgroup_resolver.clone(),
        metrics.clone(),
        event_stats.clone(),
        shutdown_rx,
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

    // Run analysis pipeline
    let analysis_config = config.clone();
    let analysis_handle = tokio::spawn(async move {
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
        )
        .await
    });

    // Wait for completion or signal
    tokio::signal::ctrl_c().await.ok();
    info!("Shutdown signal received");

    // Trigger shutdown
    let _ = shutdown_tx.send(true);

    // Cleanup
    if let Some(handle) = event_handle {
        let _ = handle.await;
    }
    if let Some(handle) = analysis_handle {
        let _ = handle.await;
    }
    if let Some(handle) = intel_handle {
        handle.abort();
    }
    metrics_server.abort();

    info!("Scanner agent shutdown complete");
    Ok(())
}

async fn load_and_run_ebpf(
    cli: &Cli,
    config: &AppConfig,
    state_store: Arc<Mutex<StateStore>>,
    cgroup_resolver: Arc<Mutex<cgroup::CgroupResolver>>,
    metrics: Metrics,
    event_stats: Arc<Mutex<event_consumer::ConsumerStats>>,
    shutdown: watch::Receiver<bool>,
) -> Result<(Option<tokio::task::JoinHandle<()>>, Option<tokio::task::JoinHandle<()>>), ScannerError> {
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

    // Create event consumer
    let consumer = EventConsumer::new(exec_rb, file_rb, net_rb);

    // Start event consumer
    let event_handle = tokio::spawn(async move {
        if let Err(e) = consumer.run(state_store, cgroup_resolver, metrics, shutdown).await {
            error!("Event consumer error: {}", e);
        }
    });

    Ok((Some(event_handle), None))
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
) -> Result<Vec<Finding>, ScannerError> {
    let mut findings = Vec::new();
    let mut ticker = interval(Duration::from_secs(30));

    loop {
        ticker.tick().await;

        let store = state_store.lock().await;
        let resolver = cgroup_resolver.lock().await;

        // Process each cgroup workload
        for (cgroup_id, workload) in store.workloads() {
            // Resolve container ID
            if let Some((container_id, _pid)) = resolver.resolve(*cgroup_id).await {
                // Lookup pod identity
                if let Some(identity) = pod_cache.lookup(&container_id).await {
                    let intel_state = intel.state();
                    let intel_state = intel_state.read().await;

                    // Classify runtime paths against SBOM
                    let components = sbom_store.classify_runtime_paths(
                        &identity.image,
                        &workload.observed_paths,
                    );

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
                            };

                            if let Some(finding) = risk_engine.evaluate(identity.clone(), signal) {
                                let priority = format!("{:?}", finding.priority);
                                metrics.inc_findings(&priority);
                                findings.push(finding.clone());

                                // Trigger remediation for critical findings
                                if matches!(finding.priority, scanner_common::Priority::Critical) {
                                    if let Err(e) = remediator.remediate_finding(&finding).await {
                                        warn!("Remediation failed: {}", e);
                                    }

                                    // Generate and enforce seccomp profile
                                    let seccomp = risk_engine
                                        .build_seccomp_profile(workload.observed_syscalls.clone());
                                    if let Err(e) = persist_seccomp(config, &identity.workload, &seccomp).await {
                                        warn!("Failed to persist seccomp: {}", e);
                                    }
                                    if let Err(e) = remediator.enforce_seccomp(&identity.workload, &seccomp).await {
                                        warn!("Failed to enforce seccomp: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
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

async fn health_handler() -> impl IntoResponse {
    "OK"
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
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "High event drop rate");
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
    };
    state_store.apply_net(&net);

    let identity = pod_cache
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
            };
            if let Some(finding) = risk_engine.evaluate(identity.clone(), signal) {
                let priority = format!("{:?}", finding.priority);
                metrics.inc_findings(&priority);
                findings.push(finding);
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
