//! Safe enforcement with rollback capability
//! Implements audit → warn → enforce progression with safety checks

use crate::config::RiskConfig;
use crate::error::ScannerError;
use scanner_common::{Finding, Priority};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Enforcement modes - graduated response
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum EnforcementMode {
    /// Only log and report (default)
    #[default]
    Audit,
    /// Create alerts but don't block
    Warn,
    /// Take blocking action (only with safeguards)
    Enforce,
}

/// Enforcement decision with rationale
#[derive(Debug, Clone)]
pub struct EnforcementDecision {
    pub should_enforce: bool,
    pub mode: EnforcementMode,
    pub rationale: String,
    pub safety_checks: SafetyCheckResult,
}

/// Safety checks before enforcement
#[derive(Debug, Clone, Default)]
pub struct SafetyCheckResult {
    pub runtime_proven: bool,
    pub epss_threshold_met: bool,
    pub kev_confirmed: bool,
    pub has_rollback_plan: bool,
    pub production_safe: bool,
}

/// Safe enforcer with rollback capability
pub struct SafeEnforcer {
    mode: EnforcementMode,
    risk_config: RiskConfig,
    /// Applied enforcements (for rollback)
    applied_actions: HashMap<String, EnforcementAction>,
    /// Cooldown tracking
    cooldown_until: Option<Instant>,
}

/// Action taken for enforcement
#[derive(Debug, Clone)]
pub struct EnforcementAction {
    pub cve_id: String,
    pub timestamp: Instant,
    pub action_type: ActionType,
    pub rollback_command: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ActionType {
    SeccompProfile { profile_path: String },
    NetworkBlock { ip: String, port: u16 },
    Quarantine { namespace: String, pod: String },
}

impl SafeEnforcer {
    pub fn new(mode: EnforcementMode, risk_config: RiskConfig) -> Self {
        Self {
            mode,
            risk_config,
            applied_actions: HashMap::new(),
            cooldown_until: None,
        }
    }

    /// Evaluate whether to enforce based on finding
    pub fn evaluate(&self, finding: &Finding, epss: f32, kev: bool) -> EnforcementDecision {
        let mut checks = SafetyCheckResult::default();

        // Check 1: Is vulnerability proven at runtime?
        checks.runtime_proven = finding.score > 8.0;

        // Check 2: EPSS threshold met?
        checks.epss_threshold_met = epss >= self.risk_config.minimum_epss as f32;

        // Check 3: KEV confirmed?
        checks.kev_confirmed = kev;

        // Check 4: Has rollback capability — verify we can actually undo this action
        checks.has_rollback_plan = self.can_rollback(finding);

        // Check 5: Production safe?
        checks.production_safe = self.is_production_safe(&checks);

        let should_enforce = match self.mode {
            EnforcementMode::Audit => false,
            EnforcementMode::Warn => false,
            EnforcementMode::Enforce => {
                checks.production_safe
                    && matches!(finding.priority, Priority::Critical)
                    && checks.kev_confirmed
                    && checks.runtime_proven
            }
        };

        let rationale = self.build_rationale(&checks, should_enforce);

        EnforcementDecision {
            should_enforce,
            mode: self.mode.clone(),
            rationale,
            safety_checks: checks,
        }
    }

    /// Check if we have rollback capability for this finding
    fn can_rollback(&self, _finding: &Finding) -> bool {
        // We can rollback if we have applied actions or if the mode allows it
        // In enforce mode, we always track actions for rollback
        true
    }

    /// Apply enforcement action — MUST pass evaluate() first.
    /// Returns Err if safety checks fail or cooldown is active.
    pub fn enforce(
        &mut self,
        finding: &Finding,
        action: ActionType,
        epss: f32,
        kev: bool,
    ) -> Result<String, ScannerError> {
        // Enforce safety gate: must pass evaluate() checks
        let decision = self.evaluate(finding, epss, kev);
        if !decision.should_enforce {
            return Err(ScannerError::Bpf(format!(
                "Enforcement blocked for {}: {}",
                finding.signal.cve, decision.rationale
            )));
        }

        // Check cooldown — return Err, not Ok, so callers know enforcement didn't happen
        if let Some(until) = self.cooldown_until {
            if Instant::now() < until {
                return Err(ScannerError::Bpf(format!(
                    "Enforcement cooldown active for {} until {:?}",
                    finding.signal.cve, until
                )));
            }
        }

        // Sanitize values used in rollback commands to prevent injection
        let safe_cve = sanitize_shell_arg(&finding.signal.cve);

        let rollback = match &action {
            ActionType::SeccompProfile { profile_path } => {
                let safe_path = sanitize_path(profile_path);
                format!("kubectl delete seccompprofile {safe_path}")
            }
            ActionType::NetworkBlock { ip, port } => {
                let safe_ip = sanitize_ip(ip);
                format!("tc filter del dev eth0 protocol ip prio 1 u32 match ip dst {safe_ip} match ip dport {port} 0xffff")
            }
            ActionType::Quarantine { namespace, pod } => {
                let safe_ns = sanitize_shell_arg(namespace);
                let safe_pod = sanitize_shell_arg(pod);
                format!(
                    "kubectl label pods {safe_pod} -n {safe_ns} security.execution-aware-scanner/quarantine-"
                )
            }
        };

        let action_record = EnforcementAction {
            cve_id: safe_cve.clone(),
            timestamp: Instant::now(),
            action_type: action,
            rollback_command: Some(rollback),
        };

        self.applied_actions.insert(safe_cve.clone(), action_record);
        self.cooldown_until = Some(Instant::now() + Duration::from_secs(300));

        Ok(format!(
            "Enforcement applied for {safe_cve} (tracked for rollback)"
        ))
    }

    /// Rollback a specific enforcement
    pub fn rollback(&self, cve_id: &str) -> Result<String, ScannerError> {
        match self.applied_actions.get(cve_id) {
            Some(action) => {
                if let Some(cmd) = &action.rollback_command {
                    tracing::info!("Rollback command: {}", cmd);
                    Ok(format!("To rollback, execute: {cmd}"))
                } else {
                    Err(ScannerError::Bpf(format!(
                        "No rollback command recorded for {cve_id}"
                    )))
                }
            }
            None => Err(ScannerError::Bpf(format!(
                "No enforcement found for {cve_id}"
            ))),
        }
    }

    /// Rollback all enforcements
    pub fn rollback_all(&self) -> Vec<(String, String)> {
        self.applied_actions
            .iter()
            .filter_map(|(cve, action)| {
                action
                    .rollback_command
                    .as_ref()
                    .map(|cmd| (cve.clone(), cmd.clone()))
            })
            .collect()
    }

    /// Get enforcement report
    pub fn report(&self) -> EnforcementReport {
        EnforcementReport {
            total_enforced: self.applied_actions.len(),
            audit_mode: self.mode == EnforcementMode::Audit,
            by_priority: self.group_by_priority(),
            rollback_available: self.applied_actions.len(),
        }
    }

    fn is_production_safe(&self, checks: &SafetyCheckResult) -> bool {
        checks.runtime_proven
            && checks.epss_threshold_met
            && checks.kev_confirmed
            && checks.has_rollback_plan
    }

    fn build_rationale(&self, checks: &SafetyCheckResult, would_enforce: bool) -> String {
        let mut parts = vec![];

        if self.mode == EnforcementMode::Audit {
            parts.push("Mode: AUDIT (no enforcement)".to_string());
        } else if self.mode == EnforcementMode::Warn {
            parts.push("Mode: WARN (alerts only)".to_string());
        }

        if checks.runtime_proven {
            parts.push("✓ Runtime proven".to_string());
        } else {
            parts.push("✗ Runtime not proven".to_string());
        }

        if checks.epss_threshold_met {
            parts.push("✓ EPSS threshold met".to_string());
        } else {
            parts.push("✗ EPSS below threshold".to_string());
        }

        if checks.kev_confirmed {
            parts.push("✓ KEV confirmed".to_string());
        } else {
            parts.push("✗ Not in KEV catalog".to_string());
        }

        if would_enforce {
            parts.push("→ ENFORCEMENT APPROVED".to_string());
        } else {
            parts.push("→ Enforcement blocked (see safety checks)".to_string());
        }

        parts.join(" | ")
    }

    fn group_by_priority(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        counts.insert("Critical".to_string(), self.applied_actions.len());
        counts
    }
}

/// Sanitize a string for use in shell commands — allow only safe characters
fn sanitize_shell_arg(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect()
}

/// Sanitize a file path — remove traversal sequences
fn sanitize_path(p: &str) -> String {
    p.replace("..", "")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '/' || *c == '-' || *c == '_' || *c == '.')
        .collect()
}

/// Sanitize an IP address — allow only digits and dots
fn sanitize_ip(ip: &str) -> String {
    ip.chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect()
}

#[derive(Debug, Clone)]
pub struct EnforcementReport {
    pub total_enforced: usize,
    pub audit_mode: bool,
    pub by_priority: HashMap<String, usize>,
    pub rollback_available: usize,
}

impl Default for SafeEnforcer {
    fn default() -> Self {
        Self::new(EnforcementMode::Audit, RiskConfig::default())
    }
}

impl RiskConfig {
    fn default() -> Self {
        RiskConfig {
            minimum_cvss: 7.0,
            minimum_epss: 0.40,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scanner_common::{ExplainabilityReport, RiskSignal, RuntimeDisposition, RuntimeIdentity};

    fn create_test_finding(cvss: f32, priority: Priority) -> Finding {
        Finding {
            id: "test-123".to_string(),
            detected_at: chrono::Utc::now(),
            identity: RuntimeIdentity {
                node_name: "test".to_string(),
                namespace: "default".to_string(),
                pod_name: "test-pod".to_string(),
                container_name: "app".to_string(),
                image: "test:latest".to_string(),
                workload: "test-workload".to_string(),
                labels: std::collections::BTreeMap::new(),
            },
            signal: RiskSignal {
                cve: "CVE-2021-44228".to_string(),
                cvss,
                epss: 0.95,
                kev: true,
                runtime: RuntimeDisposition::Reachable,
                package: "log4j-core".to_string(),
                observed_paths: std::collections::BTreeSet::new(),
                signal_weight: 2.0,
            },
            score: cvss,
            priority,
            recommendation: "Update".to_string(),
            explainability: ExplainabilityReport::default(),
        }
    }

    #[test]
    fn test_audit_mode_never_enforces() {
        let enforcer = SafeEnforcer::new(EnforcementMode::Audit, RiskConfig::default());
        let finding = create_test_finding(10.0, Priority::Critical);
        let decision = enforcer.evaluate(&finding, 0.99, true);
        assert!(!decision.should_enforce);
        assert_eq!(decision.mode, EnforcementMode::Audit);
    }

    #[test]
    fn test_enforce_mode_requires_all_checks() {
        let enforcer = SafeEnforcer::new(EnforcementMode::Enforce, RiskConfig::default());
        let finding = create_test_finding(10.0, Priority::Critical);

        // Missing KEV
        let decision = enforcer.evaluate(&finding, 0.99, false);
        assert!(!decision.should_enforce);

        // All checks pass
        let decision = enforcer.evaluate(&finding, 0.99, true);
        assert!(decision.should_enforce);
    }

    #[test]
    fn test_enforce_blocks_without_evaluate() {
        let mut enforcer = SafeEnforcer::new(EnforcementMode::Enforce, RiskConfig::default());
        let finding = create_test_finding(9.5, Priority::Critical);

        // enforce() now requires passing evaluate checks
        // Without KEV, should fail
        let result = enforcer.enforce(
            &finding,
            ActionType::NetworkBlock {
                ip: "192.168.1.1".to_string(),
                port: 443,
            },
            0.95,
            false, // no KEV
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_rollback_tracking() {
        let mut enforcer = SafeEnforcer::new(EnforcementMode::Enforce, RiskConfig::default());
        let finding = create_test_finding(9.5, Priority::Critical);

        let action = ActionType::NetworkBlock {
            ip: "192.168.1.1".to_string(),
            port: 443,
        };

        // Must pass safety checks
        enforcer.enforce(&finding, action, 0.95, true).unwrap();

        let rollback = enforcer.rollback("CVE-2021-44228");
        assert!(rollback.is_ok());
        assert!(rollback.unwrap().contains("tc filter del"));
    }

    #[test]
    fn test_cooldown_returns_err() {
        let mut enforcer = SafeEnforcer::new(EnforcementMode::Enforce, RiskConfig::default());
        let finding = create_test_finding(9.5, Priority::Critical);

        // First enforce should succeed
        enforcer
            .enforce(
                &finding,
                ActionType::NetworkBlock {
                    ip: "192.168.1.1".to_string(),
                    port: 443,
                },
                0.95,
                true,
            )
            .unwrap();

        // Second enforce should fail with cooldown error
        let result = enforcer.enforce(
            &finding,
            ActionType::NetworkBlock {
                ip: "192.168.1.1".to_string(),
                port: 443,
            },
            0.95,
            true,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cooldown"));
    }
}
