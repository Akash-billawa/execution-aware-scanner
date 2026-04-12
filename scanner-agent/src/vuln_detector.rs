//! Vulnerability detection using Trivy scanner
//! Detects real CVEs from container images and filesystems

use crate::error::ScannerError;
use scanner_common::{CveRecord, SbomComponent};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// Vulnerability detection result
#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub package: String,
    pub version: String,
    pub cve: String,
    pub severity: Severity,
    pub cvss_score: f32,
    pub description: String,
    pub fixed_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Trivy vulnerability scanner
pub struct VulnDetector {
    timeout_secs: u64,
}

impl VulnDetector {
    pub fn new() -> Self {
        Self {
            timeout_secs: 300, // 5 minutes
        }
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Scan a container image for vulnerabilities
    pub async fn scan_image(&self, image: &str) -> Result<Vec<Vulnerability>, ScannerError> {
        tracing::info!("Scanning image for vulnerabilities: {}", image);

        let output = Command::new("trivy")
            .args([
                "image",
                "--format",
                "json",
                "--severity",
                "CRITICAL,HIGH,MEDIUM",
                "--timeout",
                &format!("{}s", self.timeout_secs),
                image,
            ])
            .output()
            .map_err(|e| ScannerError::Bpf(format!("Failed to run trivy: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Trivy scan warning: {}", stderr);
            // Continue anyway - might have partial results
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_trivy_output(&stdout)
    }

    /// Scan filesystem/SBOM for vulnerabilities
    pub async fn scan_sbom(&self, sbom_path: &Path) -> Result<Vec<Vulnerability>, ScannerError> {
        tracing::info!("Scanning SBOM: {}", sbom_path.display());

        let output = Command::new("trivy")
            .args([
                "sbom",
                "--format",
                "json",
                "--severity",
                "CRITICAL,HIGH,MEDIUM",
                sbom_path.to_str().unwrap_or("sbom.json"),
            ])
            .output()
            .map_err(|e| ScannerError::Bpf(format!("Failed to run trivy sbom: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Trivy SBOM scan warning: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_trivy_output(&stdout)
    }

    /// Parse Trivy JSON output
    fn parse_trivy_output(&self, json_output: &str) -> Result<Vec<Vulnerability>, ScannerError> {
        let report: TrivyReport = serde_json::from_str(json_output).map_err(|e| {
            ScannerError::Bpf(format!(
                "Failed to parse trivy output: {} - raw: {}",
                e,
                json_output.chars().take(200).collect::<String>()
            ))
        })?;

        let mut vulns = Vec::new();

        for result in report.results {
            for vuln in result.vulnerabilities {
                let severity = match vuln.severity.as_str() {
                    "CRITICAL" => Severity::Critical,
                    "HIGH" => Severity::High,
                    "MEDIUM" => Severity::Medium,
                    "LOW" => Severity::Low,
                    _ => Severity::Unknown,
                };

                let cvss_score = vuln
                    .cvss
                    .as_ref()
                    .and_then(|c| c.nvd.as_ref().map(|n| n.v3_score))
                    .unwrap_or(0.0);

                vulns.push(Vulnerability {
                    package: vuln.pkg_name,
                    version: vuln.installed_version,
                    cve: vuln.vulnerability_id,
                    severity,
                    cvss_score: cvss_score as f32,
                    description: vuln
                        .title
                        .unwrap_or_else(|| vuln.description.unwrap_or_default()),
                    fixed_version: vuln.fixed_version,
                });
            }
        }

        tracing::info!("Found {} vulnerabilities", vulns.len());
        Ok(vulns)
    }

    /// Check if Trivy is installed
    pub fn check_trivy() -> Result<(), ScannerError> {
        match Command::new("trivy").arg("--version").output() {
            Ok(_) => Ok(()),
            Err(_) => Err(ScannerError::Bpf(
                "Trivy not found. Install with: sudo apt install trivy".to_string(),
            )),
        }
    }
}

impl Default for VulnDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert vulnerability to CVE record
impl From<Vulnerability> for CveRecord {
    fn from(v: Vulnerability) -> Self {
        CveRecord {
            id: v.cve,
            cvss: v.cvss_score,
            severity: match v.severity {
                Severity::Critical => scanner_common::Severity::Critical,
                Severity::High => scanner_common::Severity::High,
                Severity::Medium => scanner_common::Severity::Medium,
                Severity::Low => scanner_common::Severity::Low,
                Severity::Unknown => scanner_common::Severity::Low,
            },
            description: Some(v.description),
            cwe: None,
        }
    }
}

// Trivy JSON structures
#[derive(Debug, Deserialize)]
struct TrivyReport {
    #[serde(default)]
    results: Vec<TrivyResult>,
}

#[derive(Debug, Deserialize)]
struct TrivyResult {
    #[serde(default)]
    vulnerabilities: Vec<TrivyVulnerability>,
}

#[derive(Debug, Deserialize)]
struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    vulnerability_id: String,
    #[serde(rename = "PkgName")]
    pkg_name: String,
    #[serde(rename = "InstalledVersion")]
    installed_version: String,
    #[serde(rename = "FixedVersion")]
    fixed_version: Option<String>,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(rename = "Title")]
    title: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "CVSS")]
    cvss: Option<CVSSData>,
}

#[derive(Debug, Deserialize)]
struct CVSSData {
    #[serde(rename = "nvd")]
    nvd: Option<NvdCvss>,
}

#[derive(Debug, Deserialize)]
struct NvdCvss {
    #[serde(rename = "V3Score")]
    v3_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample_output() {
        let json = r#"
        {
            "results": [{
                "vulnerabilities": [{
                    "VulnerabilityID": "CVE-2021-44228",
                    "PkgName": "log4j-core",
                    "InstalledVersion": "2.14.1",
                    "FixedVersion": "2.17.0",
                    "Severity": "CRITICAL",
                    "Title": "Log4Shell Remote Code Execution",
                    "Description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                    "CVSS": {
                        "nvd": {
                            "V3Score": 10.0
                        }
                    }
                }]
            }]
        }
        "#;

        let detector = VulnDetector::new();
        let vulns = detector.parse_trivy_output(json).unwrap();

        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].cve, "CVE-2021-44228");
        assert_eq!(vulns[0].package, "log4j-core");
        assert!(matches!(vulns[0].severity, Severity::Critical));
    }
}
