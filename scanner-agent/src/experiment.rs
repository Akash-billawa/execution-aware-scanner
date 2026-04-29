use scanner_common::EventKind;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for A/B testing and signal ablation studies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentConfig {
    /// Experiment mode
    pub mode: ExperimentMode,

    /// Signal ablation configuration
    pub ablation: AblationConfig,

    /// Signal quality thresholds
    pub thresholds: SignalThresholds,

    /// Time windows for signal correlation
    pub time_windows: TimeWindows,

    /// Confidence gating for enforcement
    pub confidence_gating: ConfidenceGating,
}

impl Default for ExperimentConfig {
    fn default() -> Self {
        Self {
            mode: ExperimentMode::FullRuntimeWithSignals,
            ablation: AblationConfig::default(),
            thresholds: SignalThresholds::default(),
            time_windows: TimeWindows::default(),
            confidence_gating: ConfidenceGating::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ExperimentMode {
    /// Static SBOM-only scanning (baseline)
    StaticOnly,
    /// Runtime scanning without signal boost
    RuntimeNoSignals,
    /// Full runtime with signal weighting (production)
    FullRuntimeWithSignals,
}

impl std::fmt::Display for ExperimentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExperimentMode::StaticOnly => write!(f, "static"),
            ExperimentMode::RuntimeNoSignals => write!(f, "runtime-no-signals"),
            ExperimentMode::FullRuntimeWithSignals => write!(f, "full-runtime"),
        }
    }
}

/// Configuration for ablation studies (disable specific signals)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct AblationConfig {
    pub disable_mmap: bool,
    pub disable_tcp: bool,
    pub disable_udp: bool,
    pub disable_ssl: bool,
    pub disable_dns: bool,
    pub disable_mprotect: bool,
    pub disable_suspicious_exec: bool,
}


impl AblationConfig {
    /// Check if a signal type is disabled
    pub fn is_disabled(&self, kind: &EventKind) -> bool {
        match kind {
            EventKind::Mmap | EventKind::MmapAnon => self.disable_mmap,
            EventKind::TcpSend | EventKind::TcpRecv => self.disable_tcp,
            EventKind::UdpSend | EventKind::UdpRecv => self.disable_udp,
            EventKind::SslWrite | EventKind::SslRead => self.disable_ssl,
            EventKind::DnsQuery => self.disable_dns,
            EventKind::Mprotect => self.disable_mprotect,
            EventKind::Exec => self.disable_suspicious_exec,
            _ => false,
        }
    }

    /// Get list of disabled signals for reporting
    pub fn disabled_signals(&self) -> Vec<String> {
        let mut disabled = Vec::new();
        if self.disable_mmap {
            disabled.push("mmap".to_string());
        }
        if self.disable_tcp {
            disabled.push("tcp".to_string());
        }
        if self.disable_udp {
            disabled.push("udp".to_string());
        }
        if self.disable_ssl {
            disabled.push("ssl".to_string());
        }
        if self.disable_dns {
            disabled.push("dns".to_string());
        }
        if self.disable_mprotect {
            disabled.push("mprotect".to_string());
        }
        if self.disable_suspicious_exec {
            disabled.push("suspicious_exec".to_string());
        }
        disabled
    }
}

/// Quality thresholds for signals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalThresholds {
    /// Minimum bytes to trigger large transfer signal
    pub large_transfer_threshold: usize,
    /// Minimum SSL calls to count as SSL usage
    pub min_ssl_calls: u32,
    /// Minimum DNS queries to count as DNS usage
    pub min_dns_queries: u32,
    /// Minimum suspicious command score
    pub suspicious_threshold: f32,
    /// Minimum time between duplicate signals (deduplication)
    pub dedup_window_secs: u64,
}

impl Default for SignalThresholds {
    fn default() -> Self {
        Self {
            large_transfer_threshold: 64 * 1024, // 64KB
            min_ssl_calls: 3,
            min_dns_queries: 2,
            suspicious_threshold: 0.7,
            dedup_window_secs: 5,
        }
    }
}

/// Time windows for signal correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindows {
    /// Window for correlating signals per PID
    pub pid_correlation_window: Duration,
    /// Window for burst detection
    pub burst_window: Duration,
    /// Window for attack path building
    pub attack_path_window: Duration,
}

impl Default for TimeWindows {
    fn default() -> Self {
        Self {
            pid_correlation_window: Duration::from_secs(60),
            burst_window: Duration::from_secs(5),
            attack_path_window: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Confidence gating for safe enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceGating {
    /// Minimum EPSS for enforcement
    pub min_epss: f32,
    /// Minimum KEV confidence (0-1)
    pub min_kev_confidence: f32,
    /// Minimum signal boost
    pub min_signal_boost: f32,
    /// Required signal types for enforcement
    pub required_signals: Vec<String>,
}

impl Default for ConfidenceGating {
    fn default() -> Self {
        Self {
            min_epss: 0.7,
            min_kev_confidence: 0.9,
            min_signal_boost: 2.0,
            required_signals: vec!["mmap".to_string()],
        }
    }
}

impl ConfidenceGating {
    /// Check if enforcement should be gated
    pub fn should_gate(&self, epss: f32, kev: bool, signal_boost: f32, signals: &[String]) -> bool {
        // Check EPSS threshold
        if epss < self.min_epss {
            return false;
        }

        // Check KEV
        if !kev {
            return false;
        }

        // Check signal boost
        if signal_boost < self.min_signal_boost {
            return false;
        }

        // Check required signals present
        for required in &self.required_signals {
            if !signals.iter().any(|s| s.contains(required)) {
                return false;
            }
        }

        true
    }
}

/// Experiment results for comparison
#[derive(Debug, Clone, Serialize)]
pub struct ExperimentResult {
    pub mode: ExperimentMode,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub signal_boost_avg: f32,
    pub false_positive_estimate: f32,
    pub ablation_disabled: Vec<String>,
}

impl ExperimentResult {
    /// Compare two experiment results
    pub fn compare(&self, baseline: &ExperimentResult) -> Comparison {
        Comparison {
            reduction_percent: if baseline.total_findings > 0 {
                ((baseline.total_findings - self.total_findings) as f32
                    / baseline.total_findings as f32)
                    * 100.0
            } else {
                0.0
            },
            critical_change: self.critical_count as i32 - baseline.critical_count as i32,
            signal_boost_delta: self.signal_boost_avg - baseline.signal_boost_avg,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Comparison {
    pub reduction_percent: f32,
    pub critical_change: i32,
    pub signal_boost_delta: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ablation_config() {
        let mut config = AblationConfig::default();
        assert!(!config.is_disabled(&EventKind::Mmap));

        config.disable_mmap = true;
        assert!(config.is_disabled(&EventKind::Mmap));
        assert!(!config.is_disabled(&EventKind::Connect));
    }

    #[test]
    fn test_confidence_gating() {
        let gating = ConfidenceGating::default();

        // Should gate: high EPSS, KEV, high signal boost
        assert!(gating.should_gate(0.8, true, 2.5, &["mmap".to_string(), "ssl".to_string()]));

        // Should not gate: low EPSS
        assert!(!gating.should_gate(0.5, true, 2.5, &["mmap".to_string()]));

        // Should not gate: missing required signal
        assert!(!gating.should_gate(0.8, true, 2.5, &["tcp".to_string()]));
    }
}
