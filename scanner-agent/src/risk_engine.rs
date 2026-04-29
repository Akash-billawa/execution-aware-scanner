use crate::config::RiskConfig;
use scanner_common::{
    ExplainabilityReport, Finding, Priority, RiskComponents, RiskSignal, RuntimeDisposition,
    RuntimeIdentity, SeccompProfile, SeccompRule, SignalEvidence,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use tokio::sync::RwLock;

/// EXF (Exploitability × Exposure × Threat Intelligence) Risk Engine
/// Combines multiple risk factors into a unified score
#[derive(Clone)]
pub struct ExfRiskEngine {
    config: RiskConfig,
    cache: Arc<RwLock<RiskCache>>,
}

/// Cached risk calculations
#[derive(Default)]
pub struct RiskCache {
    /// CVE ID -> Risk score
    scores: HashMap<String, RiskCacheEntry>,
    /// Historical risk trends
    history: BTreeMap<String, Vec<RiskSnapshot>>,
}

#[derive(Clone)]
pub struct RiskCacheEntry {
    pub score: f32,
    pub calculated_at: chrono::DateTime<chrono::Utc>,
    pub ttl: std::time::Duration,
}

#[derive(Clone)]
pub struct RiskSnapshot {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub score: f32,
    pub runtime_reachable: bool,
}

impl ExfRiskEngine {
    pub fn new(config: RiskConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(RiskCache::default())),
        }
    }

    /// Calculate EXF score using weighted components
    ///
    /// Formula: EXF = (CVSS × 0.50) + (EPSS × 10 × 0.30) + KEV + Runtime + signal boost.
    /// Enhanced with signal weighting for precise risk calculation
    pub fn calculate_exf_score(&self, signal: &RiskSignal) -> f32 {
        // Normalize CVSS (already 0-10)
        let cvss_component = signal.cvss * 0.50;

        // EPSS is 0-1, scale to 0-10
        let epss_component = signal.epss * 10.0 * 0.30;

        // KEV bonus: +1.5 points if known exploited
        let kev_component = if signal.kev { 1.5 } else { 0.0 };

        // Runtime component: active exposure increases risk
        let runtime_component = match signal.runtime {
            RuntimeDisposition::Reachable => 2.0,
            RuntimeDisposition::Dormant => 0.5,
            RuntimeDisposition::Unknown => 0.75,
        };

        // Signal weighting: boost score based on runtime signals
        // Signal weight ranges from 0.0 to ~10.0 based on collected signals
        let signal_boost = if signal.signal_weight > 0.0 {
            signal.signal_weight.min(3.0) // Cap at +3.0 points
        } else {
            0.0
        };

        let score =
            cvss_component + epss_component + kev_component + runtime_component + signal_boost;

        // Clamp to 0-10 range with explicit type
        score.min(10.0).max(0.0)
    }

    /// Evaluate a signal and produce a finding if it meets thresholds
    pub fn evaluate(
        &self,
        identity: RuntimeIdentity,
        signal: RiskSignal,
        signals: Option<&[SignalEvidence]>,
    ) -> Option<Finding> {
        // Check minimum thresholds
        if signal.cvss < self.config.minimum_cvss as f32 && !signal.kev {
            return None;
        }

        if signal.epss < self.config.minimum_epss as f32 && !signal.kev {
            return None;
        }

        // Must be reachable or KEV
        if !matches!(signal.runtime, RuntimeDisposition::Reachable) && !signal.kev {
            return None;
        }

        let score = self.calculate_exf_score(&signal);

        // Determine priority based on EXF score
        let priority = if score >= 9.0 {
            Priority::Critical
        } else if signal.kev || score >= 8.0 {
            Priority::High
        } else if score >= 6.0 {
            Priority::Medium
        } else if score >= 4.0 {
            Priority::Low
        } else {
            Priority::Informational
        };

        // Skip informational findings
        if matches!(priority, Priority::Informational) {
            return None;
        }

        // Build recommendations based on risk factors
        let recommendation = self.build_recommendation(&signal, &priority);

        // Build explainability report
        let explainability = self.build_explainability(&signal, score, &priority, signals);

        Some(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            detected_at: chrono::Utc::now(),
            identity,
            signal: signal.clone(),
            score,
            priority,
            recommendation,
            explainability,
        })
    }

    /// Build contextual recommendations based on risk factors
    fn build_recommendation(&self, signal: &RiskSignal, priority: &Priority) -> String {
        let mut parts = Vec::new();

        // Base recommendation
        parts.push(format!(
            "Patch {} to remediate {}.",
            signal.package, signal.cve
        ));

        // Runtime-specific guidance
        match signal.runtime {
            RuntimeDisposition::Reachable => {
                parts.push(format!(
                    "CRITICAL: This vulnerability is actively loaded at runtime via paths: {:?}",
                    signal.observed_paths
                ));
            }
            RuntimeDisposition::Dormant => {
                parts.push(
                    "Vulnerability present but not currently active. Schedule patching."
                        .to_string(),
                );
            }
            _ => {}
        }

        // KEV-specific
        if signal.kev {
            parts.push(
                "This CVE is in CISA KEV catalog - actively exploited in the wild.".to_string(),
            );
        }

        // EPSS guidance
        if signal.epss >= 0.5 {
            parts.push(format!(
                "EPSS score {} indicates high probability of exploitation.",
                signal.epss
            ));
        }

        // Priority-specific actions
        match priority {
            Priority::Critical => {
                parts.push(
                    "IMMEDIATE ACTION: Consider quarantining workload until patched.".to_string(),
                );
            }
            Priority::High => {
                parts.push("URGENT: Patch within 24-48 hours.".to_string());
            }
            Priority::Medium => {
                parts.push("Patch within 7 days.".to_string());
            }
            _ => {
                parts.push("Patch during next maintenance window.".to_string());
            }
        }

        parts.join(" ")
    }

    /// Build explainability report with detailed reasoning
    fn build_explainability(
        &self,
        signal: &RiskSignal,
        score: f32,
        priority: &Priority,
        signals: Option<&[SignalEvidence]>,
    ) -> ExplainabilityReport {
        // Calculate confidence based on signal quality
        let confidence = self.calculate_confidence(signal, signals);

        // Build decision string
        let decision = format!(
            "{} + {} + {:.2} signal boost = {:.1} score",
            if signal.kev { "KEV" } else { "No KEV" },
            match signal.runtime {
                RuntimeDisposition::Reachable => "ACTIVE_RUNTIME",
                RuntimeDisposition::Dormant => "DORMANT",
                RuntimeDisposition::Unknown => "UNKNOWN",
            },
            signal.signal_weight,
            score
        );

        ExplainabilityReport {
            decision,
            confidence,
            components: RiskComponents {
                cvss: signal.cvss,
                epss: signal.epss,
                kev: signal.kev,
                runtime: signal.runtime.clone(),
                signal_boost: signal.signal_weight,
            },
            signals: signals.map(|s| s.to_vec()).unwrap_or_default(),
            ablation_disabled: Vec::new(), // Populated by caller
        }
    }

    /// Calculate confidence score (0.0 - 1.0)
    fn calculate_confidence(&self, signal: &RiskSignal, signals: Option<&[SignalEvidence]>) -> f32 {
        let mut confidence = 0.0;

        // Base confidence from data quality
        confidence += 0.3; // CVSS always available

        // EPSS availability
        if signal.epss > 0.0 {
            confidence += 0.2;
        }

        // KEV presence
        if signal.kev {
            confidence += 0.2;
        }

        // Runtime signals
        if let Some(sigs) = signals {
            if !sigs.is_empty() {
                confidence += 0.3;
                // Boost for multiple signal types
                if sigs.len() > 1 {
                    confidence += 0.1; // Bonus for correlation
                }
            }
        }

        (confidence as f32).min(1.0)
    }

    /// Build seccomp profile from observed syscalls
    pub fn build_seccomp_profile(&self, observed_syscalls: BTreeSet<String>) -> SeccompProfile {
        let mut allowlist: BTreeSet<String> = observed_syscalls.clone();

        // Always allow essential syscalls
        allowlist.insert("exit".to_string());
        allowlist.insert("exit_group".to_string());
        allowlist.insert("rt_sigreturn".to_string());
        allowlist.insert("sigreturn".to_string());

        // Memory management
        allowlist.insert("brk".to_string());
        allowlist.insert("mmap".to_string());
        allowlist.insert("munmap".to_string());
        allowlist.insert("mprotect".to_string());

        // File operations (common)
        if allowlist.contains("openat") {
            allowlist.insert("openat2".to_string());
        }

        // Build syscall groups for better readability
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for syscall in &allowlist {
            let category = categorize_syscall(syscall);
            groups.entry(category).or_default().push(syscall.clone());
        }

        SeccompProfile {
            default_action: "SCMP_ACT_ERRNO".to_string(),
            architectures: vec![
                "SCMP_ARCH_X86_64".to_string(),
                "SCMP_ARCH_X86".to_string(),
                "SCMP_ARCH_AARCH64".to_string(),
            ],
            syscalls: vec![SeccompRule {
                names: allowlist.into_iter().collect(),
                action: "SCMP_ACT_ALLOW".to_string(),
            }],
        }
    }

    /// Get cached score or calculate new
    pub async fn get_cached_score(&self, cve_id: &str, signal: &RiskSignal) -> f32 {
        let cache = self.cache.read().await;

        if let Some(entry) = cache.scores.get(cve_id) {
            if entry.calculated_at + entry.ttl > chrono::Utc::now() {
                return entry.score;
            }
        }

        drop(cache);

        let score = self.calculate_exf_score(signal);
        let mut cache = self.cache.write().await;

        cache.scores.insert(
            cve_id.to_string(),
            RiskCacheEntry {
                score,
                calculated_at: chrono::Utc::now(),
                ttl: std::time::Duration::from_secs(3600), // 1 hour TTL
            },
        );

        // Update history
        cache
            .history
            .entry(cve_id.to_string())
            .or_default()
            .push(RiskSnapshot {
                timestamp: chrono::Utc::now(),
                score,
                runtime_reachable: matches!(signal.runtime, RuntimeDisposition::Reachable),
            });

        score
    }

    /// Get historical trend for a CVE
    pub async fn get_risk_trend(&self, cve_id: &str) -> Vec<RiskSnapshot> {
        let cache = self.cache.read().await;
        cache.history.get(cve_id).cloned().unwrap_or_default()
    }

    /// Clear expired cache entries
    pub async fn clear_expired(&self) {
        let mut cache = self.cache.write().await;
        let now = chrono::Utc::now();

        cache
            .scores
            .retain(|_, entry| entry.calculated_at + entry.ttl > now);
    }

    /// Export risk summary
    pub async fn export_risk_summary(&self) -> RiskSummary {
        let cache = self.cache.read().await;

        RiskSummary {
            total_cves: cache.scores.len(),
            critical_count: cache.scores.values().filter(|e| e.score >= 9.0).count(),
            high_count: cache
                .scores
                .values()
                .filter(|e| e.score >= 7.0 && e.score < 9.0)
                .count(),
            medium_count: cache
                .scores
                .values()
                .filter(|e| e.score >= 4.0 && e.score < 7.0)
                .count(),
            low_count: cache.scores.values().filter(|e| e.score < 4.0).count(),
        }
    }
}

/// Risk summary statistics
#[derive(Debug)]
pub struct RiskSummary {
    pub total_cves: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

fn categorize_syscall(syscall: &str) -> String {
    match syscall {
        "mmap" | "munmap" | "mprotect" | "brk" | "sbrk" => "memory".to_string(),
        "openat" | "openat2" | "read" | "write" | "close" | "fstat" | "lseek" => "file".to_string(),
        "execve" | "execveat" | "clone" | "fork" | "vfork" | "exit" | "wait4" => "process".to_string(),
        "socket" | "connect" | "bind" | "listen" | "accept" | "sendto" | "recvfrom" => "network".to_string(),
        "rt_sigaction" | "rt_sigprocmask" | "rt_sigreturn" | "kill" | "tkill" => "signal".to_string(),
        "clock_gettime" | "gettimeofday" | "nanosleep" => "time".to_string(),
        _ => "other".to_string(),
    }
}

// Backwards compatibility alias
pub use ExfRiskEngine as RiskEngine;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn create_test_config() -> RiskConfig {
        RiskConfig {
            minimum_cvss: 4.0,
            minimum_epss: 0.1,
        }
    }

    #[test]
    fn test_exf_score_calculation() {
        let engine = ExfRiskEngine::new(create_test_config());

        // Critical: CVSS 9.8, EPSS 0.91, KEV, Reachable
        let signal = RiskSignal {
            cve: "CVE-2025-1234".to_string(),
            cvss: 9.8,
            epss: 0.91,
            kev: true,
            runtime: RuntimeDisposition::Reachable,
            package: "openssl".to_string(),
            observed_paths: BTreeSet::from(["/usr/lib/libssl.so".to_string()]),
            signal_weight: 2.0, // Library loaded
        };

        let score = engine.calculate_exf_score(&signal);
        assert!(
            score >= 9.0,
            "Expected critical score >= 9.0, got {score}"
        );

        // High: CVSS 8.0, EPSS 0.5, Not KEV, Reachable
        let signal2 = RiskSignal {
            cve: "CVE-2025-5678".to_string(),
            cvss: 8.0,
            epss: 0.5,
            kev: false,
            runtime: RuntimeDisposition::Reachable,
            package: "nginx".to_string(),
            observed_paths: BTreeSet::new(),
            signal_weight: 0.0,
        };

        let score2 = engine.calculate_exf_score(&signal2);
        assert!(
            (7.0..9.0).contains(&score2),
            "Expected high score, got {score2}"
        );
    }

    #[test]
    fn test_dormant_not_prioritized() {
        let engine = ExfRiskEngine::new(create_test_config());

        // Dormant with no KEV - should not produce finding
        let signal = RiskSignal {
            cve: "CVE-2025-9999".to_string(),
            cvss: 9.8,
            epss: 0.95,
            kev: false,
            runtime: RuntimeDisposition::Dormant,
            package: "openssl".to_string(),
            observed_paths: BTreeSet::new(),
            signal_weight: 0.0,
        };

        let identity = RuntimeIdentity {
            node_name: "test".to_string(),
            namespace: "default".to_string(),
            pod_name: "test-pod".to_string(),
            container_name: "app".to_string(),
            image: "test:latest".to_string(),
            workload: "test".to_string(),
            labels: BTreeMap::new(),
        };

        let finding = engine.evaluate(identity, signal, None);
        assert!(finding.is_none());
    }

    #[test]
    fn test_kev_prioritizes_dormant() {
        let engine = ExfRiskEngine::new(create_test_config());

        // Dormant but KEV - should produce finding
        let signal = RiskSignal {
            cve: "CVE-2025-8888".to_string(),
            cvss: 7.5,
            epss: 0.3,
            kev: true,
            runtime: RuntimeDisposition::Dormant,
            package: "log4j".to_string(),
            observed_paths: BTreeSet::new(),
            signal_weight: 0.0,
        };

        let identity = RuntimeIdentity {
            node_name: "test".to_string(),
            namespace: "default".to_string(),
            pod_name: "test-pod".to_string(),
            container_name: "app".to_string(),
            image: "test:latest".to_string(),
            workload: "test".to_string(),
            labels: BTreeMap::new(),
        };

        let finding = engine.evaluate(identity, signal, None);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().priority, Priority::High);
    }
}
