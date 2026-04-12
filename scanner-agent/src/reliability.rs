//! Production Reliability Module
//!
//! Features for stable production deployment:
//! - Backpressure handling (channel full detection)
//! - Dropped event metrics
//! - Watchdog restart logic
//! - Health checks and probes
//! - Circuit breaker pattern
//! - Graceful degradation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Reliability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityConfig {
    /// Channel buffer size before backpressure
    pub channel_buffer_size: usize,
    /// Channel high water mark (80% of buffer)
    pub channel_high_water: usize,
    /// Channel low water mark (50% of buffer)
    pub channel_low_water: usize,
    /// Watchdog timeout seconds
    pub watchdog_timeout_secs: u64,
    /// Max consecutive errors before restart
    pub max_consecutive_errors: u32,
    /// Circuit breaker threshold
    pub circuit_breaker_threshold: u32,
    /// Circuit breaker recovery time
    pub circuit_breaker_recovery_secs: u64,
    /// Health check interval
    pub health_check_interval_secs: u64,
    /// Enable graceful degradation
    pub enable_degradation: bool,
}

impl Default for ReliabilityConfig {
    fn default() -> Self {
        let buffer_size = 10000;
        Self {
            channel_buffer_size: buffer_size,
            channel_high_water: (buffer_size as f64 * 0.8) as usize,
            channel_low_water: (buffer_size as f64 * 0.5) as usize,
            watchdog_timeout_secs: 60,
            max_consecutive_errors: 5,
            circuit_breaker_threshold: 10,
            circuit_breaker_recovery_secs: 60,
            health_check_interval_secs: 30,
            enable_degradation: true,
        }
    }
}

/// Health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Component metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComponentMetrics {
    pub events_processed: u64,
    pub events_dropped: u64,
    pub events_queued: u64,
    pub errors: u64,
    pub latency_ms: u64,
    pub last_event_time: Option<i64>,
}

/// Reliability metrics collector
pub struct ReliabilityMetrics {
    metrics: Arc<RwLock<HashMap<String, ComponentMetrics>>>,
    total_dropped: AtomicU64,
    total_processed: AtomicU64,
    start_time: Instant,
}

impl ReliabilityMetrics {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            total_dropped: AtomicU64::new(0),
            total_processed: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Record event processed
    pub fn record_processed(&self, component: &str) {
        self.total_processed.fetch_add(1, Ordering::Relaxed);
        // Update component metrics
        let metrics = self.metrics.clone();
        let component = component.to_string();
        tokio::spawn(async move {
            let mut m = metrics.write().await;
            let cm = m.entry(component).or_default();
            cm.events_processed += 1;
            cm.last_event_time = Some(chrono::Utc::now().timestamp());
        });
    }

    /// Record event dropped
    pub fn record_dropped(&self, component: &str, count: u64) {
        self.total_dropped.fetch_add(count, Ordering::Relaxed);
        let metrics = self.metrics.clone();
        let component = component.to_string();
        tokio::spawn(async move {
            let mut m = metrics.write().await;
            let cm = m.entry(component).or_default();
            cm.events_dropped += count;
        });
    }

    /// Record error
    pub fn record_error(&self, component: &str) {
        let metrics = self.metrics.clone();
        let component = component.to_string();
        tokio::spawn(async move {
            let mut m = metrics.write().await;
            let cm = m.entry(component).or_default();
            cm.errors += 1;
        });
    }

    /// Get total processed
    pub fn total_processed(&self) -> u64 {
        self.total_processed.load(Ordering::Relaxed)
    }

    /// Get total dropped
    pub fn total_dropped(&self) -> u64 {
        self.total_dropped.load(Ordering::Relaxed)
    }

    /// Get drop rate
    pub fn drop_rate(&self) -> f64 {
        let processed = self.total_processed();
        let dropped = self.total_dropped();
        if processed + dropped == 0 {
            0.0
        } else {
            dropped as f64 / (processed + dropped) as f64
        }
    }

    /// Get uptime seconds
    pub fn uptime_secs(&self) -> u64 {
        Instant::now().duration_since(self.start_time).as_secs()
    }

    /// Get component metrics
    pub async fn get_component_metrics(&self, component: &str) -> Option<ComponentMetrics> {
        let m = self.metrics.read().await;
        m.get(component).cloned()
    }

    /// Get all metrics
    pub async fn get_all_metrics(&self) -> HashMap<String, ComponentMetrics> {
        self.metrics.read().await.clone()
    }
}

/// Backpressure controller
pub struct BackpressureController {
    config: ReliabilityConfig,
    current_load: Arc<AtomicU64>,
    in_backpressure: Arc<RwLock<bool>>,
}

impl BackpressureController {
    pub fn new(config: ReliabilityConfig) -> Self {
        Self {
            config,
            current_load: Arc::new(AtomicU64::new(0)),
            in_backpressure: Arc::new(RwLock::new(false)),
        }
    }

    /// Check if should apply backpressure
    pub async fn check_backpressure(&self, queue_size: usize) -> bool {
        let current = self.current_load.load(Ordering::Relaxed) as usize;
        let is_high = queue_size >= self.config.channel_high_water;
        let is_low = queue_size <= self.config.channel_low_water;

        let mut in_pressure = self.in_backpressure.write().await;

        if is_high && !*in_pressure {
            warn!(
                "Backpressure activated: queue {} >= high water {}",
                queue_size, self.config.channel_high_water
            );
            *in_pressure = true;
        } else if is_low && *in_pressure {
            info!(
                "Backpressure released: queue {} <= low water {}",
                queue_size, self.config.channel_low_water
            );
            *in_pressure = false;
        }

        *in_pressure
    }

    /// Get current load
    pub fn current_load(&self) -> u64 {
        self.current_load.load(Ordering::Relaxed)
    }

    /// Update load
    pub fn update_load(&self, load: u64) {
        self.current_load.store(load, Ordering::Relaxed);
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,    // Normal operation
    Open,      // Failing, rejecting requests
    HalfOpen,  // Testing recovery
}

/// Circuit breaker for external calls
pub struct CircuitBreaker {
    config: ReliabilityConfig,
    state: Arc<RwLock<CircuitState>>,
    failure_count: Arc<AtomicU64>,
    last_failure: Arc<RwLock<Option<Instant>>>,
}

impl CircuitBreaker {
    pub fn new(config: ReliabilityConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: Arc::new(AtomicU64::new(0)),
            last_failure: Arc::new(RwLock::new(None)),
        }
    }

    /// Check if operation should proceed
    pub async fn should_proceed(&self) -> bool {
        let state = *self.state.read().await;

        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let last = *self.last_failure.read().await;
                if let Some(last_time) = last {
                    let elapsed = Instant::now().duration_since(last_time).as_secs();
                    if elapsed >= self.config.circuit_breaker_recovery_secs {
                        info!("Circuit breaker: transitioning to half-open");
                        *self.state.write().await = CircuitState::HalfOpen;
                        true
                    } else {
                        false
                    }
                } else {
                    true
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record success
    pub async fn record_success(&self) {
        let state = *self.state.read().await;
        if state == CircuitState::HalfOpen {
            info!("Circuit breaker: recovered, closing circuit");
            *self.state.write().await = CircuitState::Closed;
            self.failure_count.store(0, Ordering::Relaxed);
        }
    }

    /// Record failure
    pub async fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last_failure.write().await = Some(Instant::now());

        if count >= self.config.circuit_breaker_threshold as u64 {
            warn!(
                "Circuit breaker: {} failures, opening circuit",
                self.config.circuit_breaker_threshold
            );
            *self.state.write().await = CircuitState::Open;
        }
    }

    /// Get current state
    pub async fn state(&self) -> CircuitState {
        *self.state.read().await
    }
}

/// Watchdog for component health
pub struct Watchdog {
    config: ReliabilityConfig,
    last_heartbeat: Arc<RwLock<Instant>>,
    consecutive_errors: Arc<AtomicU64>,
}

impl Watchdog {
    pub fn new(config: ReliabilityConfig) -> Self {
        Self {
            config,
            last_heartbeat: Arc::new(RwLock::new(Instant::now())),
            consecutive_errors: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Heartbeat to signal health
    pub async fn heartbeat(&self) {
        *self.last_heartbeat.write().await = Instant::now();
        self.consecutive_errors.store(0, Ordering::Relaxed);
    }

    /// Check if watchdog is healthy
    pub async fn is_healthy(&self) -> bool {
        let last = *self.last_heartbeat.read().await;
        let elapsed = Instant::now().duration_since(last).as_secs();
        let errors = self.consecutive_errors.load(Ordering::Relaxed);

        if elapsed > self.config.watchdog_timeout_secs {
            warn!(
                "Watchdog timeout: {}s since last heartbeat",
                elapsed
            );
            return false;
        }

        if errors >= self.config.max_consecutive_errors as u64 {
            warn!(
                "Watchdog: {} consecutive errors, marking unhealthy",
                errors
            );
            return false;
        }

        true
    }

    /// Record error
    pub fn record_error(&self) {
        self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get error count
    pub fn error_count(&self) -> u64 {
        self.consecutive_errors.load(Ordering::Relaxed)
    }
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub status: HealthStatus,
    pub components: HashMap<String, ComponentHealth>,
    pub uptime_secs: u64,
    pub drop_rate: f64,
    pub total_processed: u64,
    pub total_dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: HealthStatus,
    pub message: Option<String>,
}

/// Health monitor
pub struct HealthMonitor {
    metrics: Arc<ReliabilityMetrics>,
    watchdogs: Arc<RwLock<HashMap<String, Arc<Watchdog>>>>,
}

impl HealthMonitor {
    pub fn new(metrics: Arc<ReliabilityMetrics>) -> Self {
        Self {
            metrics,
            watchdogs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a watchdog
    pub async fn register_watchdog(&self, name: &str, watchdog: Arc<Watchdog>) {
        let mut w = self.watchdogs.write().await;
        w.insert(name.to_string(), watchdog);
    }

    /// Run health check
    pub async fn check_health(&self) -> HealthCheck {
        let mut components = HashMap::new();
        let watchdogs = self.watchdogs.read().await;

        for (name, watchdog) in watchdogs.iter() {
            let is_healthy = watchdog.is_healthy().await;
            let status = if is_healthy {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unhealthy
            };

            let message = if !is_healthy {
                Some(format!("{} errors", watchdog.error_count()))
            } else {
                None
            };

            components.insert(
                name.clone(),
                ComponentHealth { status, message },
            );
        }

        let overall_status = if components.values().any(|c| c.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if components.values().any(|c| c.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        HealthCheck {
            status: overall_status,
            components,
            uptime_secs: self.metrics.uptime_secs(),
            drop_rate: self.metrics.drop_rate(),
            total_processed: self.metrics.total_processed(),
            total_dropped: self.metrics.total_dropped(),
        }
    }
}

/// Production-ready runner with all reliability features
pub struct ProductionRunner {
    config: ReliabilityConfig,
    metrics: Arc<ReliabilityMetrics>,
    health_monitor: Arc<HealthMonitor>,
}

impl ProductionRunner {
    pub fn new(config: ReliabilityConfig) -> Self {
        let metrics = Arc::new(ReliabilityMetrics::new());
        let health_monitor = Arc::new(HealthMonitor::new(metrics.clone()));

        Self {
            config,
            metrics,
            health_monitor,
        }
    }

    /// Get metrics
    pub fn metrics(&self) -> Arc<ReliabilityMetrics> {
        self.metrics.clone()
    }

    /// Get health monitor
    pub fn health_monitor(&self) -> Arc<HealthMonitor> {
        self.health_monitor.clone()
    }

    /// Run health check loop
    pub async fn run_health_checks(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(
            self.config.health_check_interval_secs
        ));

        loop {
            interval.tick().await;
            let health = self.health_monitor.check_health().await;

            match health.status {
                HealthStatus::Healthy => {
                    info!(
                        "Health: HEALTHY | uptime: {}s | processed: {} | dropped: {} ({:.2}%)",
                        health.uptime_secs,
                        health.total_processed,
                        health.total_dropped,
                        health.drop_rate * 100.0
                    );
                }
                HealthStatus::Degraded => {
                    warn!(
                        "Health: DEGRADED | uptime: {}s | processed: {} | dropped: {} ({:.2}%)",
                        health.uptime_secs,
                        health.total_processed,
                        health.total_dropped,
                        health.drop_rate * 100.0
                    );
                }
                HealthStatus::Unhealthy => {
                    error!(
                        "Health: UNHEALTHY | uptime: {}s | processed: {} | dropped: {} ({:.2}%)",
                        health.uptime_secs,
                        health.total_processed,
                        health.total_dropped,
                        health.drop_rate * 100.0
                    );
                    // Signal restart needed
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ReliabilityConfig {
                circuit_breaker_threshold: 3,
                circuit_breaker_recovery_secs: 1, // 1 second recovery for test
                ..Default::default()
            };

            let cb = CircuitBreaker::new(config);

            // Initially closed
            assert!(cb.should_proceed().await);
            assert_eq!(cb.state().await, CircuitState::Closed);

            // Record failures
            cb.record_failure().await;
            cb.record_failure().await;
            assert!(cb.should_proceed().await);

            // Third failure opens circuit
            cb.record_failure().await;
            assert_eq!(cb.state().await, CircuitState::Open);
            assert!(!cb.should_proceed().await);

            // Wait for recovery and check half-open
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert!(cb.should_proceed().await);
            assert_eq!(cb.state().await, CircuitState::HalfOpen);

            // Success closes circuit
            cb.record_success().await;
            assert_eq!(cb.state().await, CircuitState::Closed);
        });
    }

    #[test]
    fn test_watchdog() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ReliabilityConfig {
                watchdog_timeout_secs: 1,
                max_consecutive_errors: 2,
                ..Default::default()
            };

            let wd = Watchdog::new(config);

            // Initially healthy
            wd.heartbeat().await;
            assert!(wd.is_healthy().await);

            // Record errors
            wd.record_error();
            wd.record_error();
            assert!(!wd.is_healthy().await);

            // Heartbeat resets
            wd.heartbeat().await;
            assert!(wd.is_healthy().await);
        });
    }
}
