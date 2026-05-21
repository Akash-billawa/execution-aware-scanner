//! Policy engine for OPA/Rego policy evaluation
//!
//! Loads Rego policies from disk and evaluates them against findings.
//! Uses `opa eval` as a subprocess for policy evaluation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Policy engine that evaluates Rego policies
pub struct PolicyEngine {
    policies: Vec<PolicyInfo>,
    policy_dir: PathBuf,
    last_loaded: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub rules_count: usize,
    pub source_path: String,
    pub last_loaded: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub reason: String,
    pub rule_id: String,
    pub policy_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Allow,
    Alert,
    Block,
    Quarantine,
    Audit,
}

pub struct ReloadResult {
    pub reloaded: usize,
    pub errors: Vec<String>,
}

/// Input data for policy evaluation
#[derive(Debug, Serialize)]
struct PolicyInput {
    finding: FindingInput,
    namespace: String,
    workload: String,
    labels: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct FindingInput {
    id: String,
    cve: String,
    cvss: f32,
    epss: f32,
    kev: bool,
    priority: String,
    score: f32,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            policy_dir: PathBuf::from("/etc/scanner/policies"),
            last_loaded: None,
        }
    }

    /// Create a new policy engine with a custom policy directory
    pub fn with_dir(policy_dir: impl Into<PathBuf>) -> Self {
        Self {
            policies: Vec::new(),
            policy_dir: policy_dir.into(),
            last_loaded: None,
        }
    }

    /// List all loaded policies
    pub fn list_policies(&self) -> &[PolicyInfo] {
        &self.policies
    }

    /// Get a specific policy by ID
    pub fn get_policy(&self, id: &str) -> Option<&PolicyInfo> {
        self.policies.iter().find(|p| p.id == id)
    }

    /// Reload policies from disk
    pub fn reload(&mut self) -> ReloadResult {
        let mut result = ReloadResult {
            reloaded: 0,
            errors: Vec::new(),
        };

        if !self.policy_dir.exists() {
            info!(path = %self.policy_dir.display(), "Policy directory does not exist, skipping");
            self.last_loaded = Some(Utc::now());
            return result;
        }

        let mut new_policies = Vec::new();

        match std::fs::read_dir(&self.policy_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "rego") {
                        match load_policy_file(&path) {
                            Ok(info) => {
                                new_policies.push(info);
                                result.reloaded += 1;
                            }
                            Err(e) => {
                                result.errors.push(format!("{}: {e}", path.display()));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to read policy dir: {e}"));
            }
        }

        self.policies = new_policies;
        self.last_loaded = Some(Utc::now());

        info!(
            reloaded = result.reloaded,
            errors = result.errors.len(),
            "Policies reloaded"
        );

        result
    }

    /// Evaluate a finding against all loaded policies
    /// Returns the first matching policy decision, or None if no policy matches
    pub async fn evaluate(
        &self,
        finding_id: &str,
        cve: &str,
        cvss: f32,
        epss: f32,
        kev: bool,
        priority: &str,
        score: f32,
        namespace: &str,
        workload: &str,
        labels: &HashMap<String, String>,
    ) -> Option<PolicyDecision> {
        if self.policies.is_empty() {
            return None;
        }

        let input = PolicyInput {
            finding: FindingInput {
                id: finding_id.to_string(),
                cve: cve.to_string(),
                cvss,
                epss,
                kev,
                priority: priority.to_string(),
                score,
            },
            namespace: namespace.to_string(),
            workload: workload.to_string(),
            labels: labels.clone(),
        };

        let input_json = serde_json::to_string(&input).ok()?;

        // Evaluate each policy in order
        for policy in &self.policies {
            if !policy.enabled {
                continue;
            }

            match evaluate_policy(&policy.source_path, &input_json).await {
                Ok(Some(decision)) => return Some(decision),
                Ok(None) => continue,
                Err(e) => {
                    warn!(policy = %policy.name, error = %e, "Policy evaluation failed");
                }
            }
        }

        None
    }

    /// Check if OPA is available on the system
    pub async fn is_available() -> bool {
        tokio::process::Command::new("opa")
            .arg("version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Load a policy file and extract metadata
fn load_policy_file(path: &Path) -> Result<PolicyInfo, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Read error: {e}"))?;

    let name = extract_metadata(&content, "name")
        .unwrap_or_else(|| path.file_stem().unwrap().to_string_lossy().to_string());
    let description = extract_metadata(&content, "description").unwrap_or_default();
    let rules_count = content.matches("rule").count().max(1);

    Ok(PolicyInfo {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        description,
        enabled: true,
        rules_count,
        source_path: path.to_string_lossy().to_string(),
        last_loaded: Utc::now(),
    })
}

/// Extract metadata from Rego comments (e.g., # @name: my-policy)
fn extract_metadata(content: &str, key: &str) -> Option<String> {
    let prefix = format!("# @{key}:");
    content
        .lines()
        .find(|line| line.trim_start().starts_with(&prefix))
        .and_then(|line| line.split_once(':'))
        .map(|(_, value)| value.trim().to_string())
}

/// Evaluate a single policy against input data
async fn evaluate_policy(
    policy_path: &str,
    input_json: &str,
) -> Result<Option<PolicyDecision>, String> {
    let output = tokio::process::Command::new("opa")
        .args([
            "eval",
            "--format",
            "json",
            "--input",
            "/dev/stdin",
            "--data",
            policy_path,
            "data.scanner.decision",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn OPA: {e}"))?
        .wait_with_output()
        .await
        .map_err(|e| format!("OPA execution failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("OPA error: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse OPA output
    let result: serde_json::Value =
        serde_json::from_str(&stdout).map_err(|e| format!("JSON parse error: {e}"))?;

    // Check if result has a decision
    if let Some(decision) = result.get("result").and_then(|r| r.get(0)) {
        if let Ok(decision) = serde_json::from_value::<PolicyDecision>(decision.clone()) {
            return Ok(Some(decision));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_metadata() {
        let content = r#"# @name: kev-auto-block
# @description: Auto-block KEV findings with high EPSS
package scanner"#;
        assert_eq!(
            extract_metadata(content, "name"),
            Some("kev-auto-block".to_string())
        );
        assert_eq!(
            extract_metadata(content, "description"),
            Some("Auto-block KEV findings with high EPSS".to_string())
        );
    }

    #[test]
    fn test_policy_action_serde() {
        let action = PolicyAction::Block;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"block\"");

        let action: PolicyAction = serde_json::from_str("\"quarantine\"").unwrap();
        assert_eq!(action, PolicyAction::Quarantine);
    }
}
