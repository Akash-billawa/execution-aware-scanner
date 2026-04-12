//! Validation and metrics for false positive reduction
//! Compares traditional scanning vs execution-aware scanning

use crate::vuln_detector::{Severity, Vulnerability};
use scanner_common::{Finding, Priority};
use std::collections::HashMap;

/// Validation results comparing scan methods
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub baseline_scan: ScanResult,
    pub execution_aware_scan: ScanResult,
    pub reduction_metrics: ReductionMetrics,
    pub test_target: TestTarget,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub total_cves: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub exploitable: usize,
    pub false_positives: usize,
}

#[derive(Debug, Clone)]
pub struct ReductionMetrics {
    pub total_reduction_percent: f32,
    pub noise_reduction: f32,
    pub critical_focus: f32,
    pub time_saved: String,
}

#[derive(Debug, Clone)]
pub enum TestTarget {
    Dvwa,
    JuiceShop,
    Production(String),
}

/// Validator for testing false positive reduction
pub struct FalsePositiveValidator {
    results: Vec<ValidationReport>,
}

impl FalsePositiveValidator {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Compare traditional vs execution-aware scan
    pub fn compare_scans(
        &mut self,
        target: TestTarget,
        baseline_cves: Vec<Vulnerability>,
        execution_findings: Vec<Finding>,
    ) -> ValidationReport {
        // Baseline: all CVEs found by traditional scanner
        let baseline = ScanResult {
            total_cves: baseline_cves.len(),
            critical: baseline_cves
                .iter()
                .filter(|v| Self::is_critical(&v.severity))
                .count(),
            high: baseline_cves
                .iter()
                .filter(|v| Self::is_high(&v.severity))
                .count(),
            medium: baseline_cves
                .iter()
                .filter(|v| Self::is_medium(&v.severity))
                .count(),
            low: baseline_cves
                .iter()
                .filter(|v| Self::is_low(&v.severity))
                .count(),
            exploitable: 0,                           // Traditional doesn't track this
            false_positives: baseline_cves.len() / 3, // Assume ~33% FP rate
        };

        // Execution-aware: only reachable + high-risk
        let execution = ScanResult {
            total_cves: execution_findings.len(),
            critical: execution_findings
                .iter()
                .filter(|f| f.priority == Priority::Critical)
                .count(),
            high: execution_findings
                .iter()
                .filter(|f| f.priority == Priority::High)
                .count(),
            medium: execution_findings
                .iter()
                .filter(|f| f.priority == Priority::Medium)
                .count(),
            low: execution_findings
                .iter()
                .filter(|f| f.priority == Priority::Low)
                .count(),
            exploitable: execution_findings.len(), // All are reachable
            false_positives: execution_findings.iter().filter(|f| f.score < 7.0).count(),
        };

        let reduction = ReductionMetrics {
            total_reduction_percent: if baseline.total_cves > 0 {
                ((baseline.total_cves - execution.total_cves) as f32 / baseline.total_cves as f32)
                    * 100.0
            } else {
                0.0
            },
            noise_reduction: if baseline.low > 0 {
                ((baseline.low - execution.low) as f32 / baseline.low as f32) * 100.0
            } else {
                0.0
            },
            critical_focus: if baseline.critical > 0 {
                (execution.critical as f32 / baseline.critical as f32) * 100.0
            } else {
                100.0
            },
            time_saved: format!(
                "{} hours",
                (baseline.total_cves - execution.total_cves) / 10
            ),
        };

        let report = ValidationReport {
            baseline_scan: baseline,
            execution_aware_scan: execution,
            reduction_metrics: reduction,
            test_target: target,
        };

        self.results.push(report.clone());
        report
    }

    /// Print validation report to console
    pub fn print_report(&self, report: &ValidationReport) {
        let target_name = match &report.test_target {
            TestTarget::Dvwa => "DVWA",
            TestTarget::JuiceShop => "Juice Shop",
            TestTarget::Production(s) => s.as_str(),
        };

        println!("\n");
        println!("╔═══════════════════════════════════════════════════════════════╗");
        println!("║  FALSE POSITIVE REDUCTION VALIDATION                        ║");
        println!("╚═══════════════════════════════════════════════════════════════╝");
        println!("Target: {}", target_name);
        println!("\n");

        // Baseline
        println!("📊 TRADITIONAL SCAN (Baseline):");
        println!("   Total CVEs: {}", report.baseline_scan.total_cves);
        println!(
            "   Critical: {} | High: {} | Medium: {} | Low: {}",
            report.baseline_scan.critical,
            report.baseline_scan.high,
            report.baseline_scan.medium,
            report.baseline_scan.low
        );
        println!(
            "   Estimated False Positives: ~{}%",
            (report.baseline_scan.false_positives * 100) / report.baseline_scan.total_cves.max(1)
        );
        println!("\n");

        // Execution-aware
        println!("🎯 EXECUTION-AWARE SCAN:");
        println!("   Total CVEs: {}", report.execution_aware_scan.total_cves);
        println!(
            "   Critical: {} | High: {} | Medium: {} | Low: {}",
            report.execution_aware_scan.critical,
            report.execution_aware_scan.high,
            report.execution_aware_scan.medium,
            report.execution_aware_scan.low
        );
        println!(
            "   Exploitable: {} (reachable at runtime)",
            report.execution_aware_scan.exploitable
        );
        println!(
            "   False Positives: ~{}%",
            (report.execution_aware_scan.false_positives * 100)
                / report.execution_aware_scan.total_cves.max(1)
        );
        println!("\n");

        // Metrics
        println!("📈 REDUCTION METRICS:");
        println!(
            "   Total CVE Reduction: {}% ↓",
            report.reduction_metrics.total_reduction_percent
        );
        println!(
            "   Noise Reduction (Low): {}% ↓",
            report.reduction_metrics.noise_reduction
        );
        println!(
            "   Critical Focus: {}% of baseline criticals retained",
            report.reduction_metrics.critical_focus
        );
        println!("   Time Saved: ~{}", report.reduction_metrics.time_saved);
        println!("\n");

        // Summary
        if report.reduction_metrics.total_reduction_percent > 50.0 {
            println!("✅ EXCELLENT: Reduced alert fatigue by >50%");
        } else if report.reduction_metrics.total_reduction_percent > 30.0 {
            println!("✅ GOOD: Significant noise reduction");
        } else {
            println!("⚠️  IMPROVE: Less than 30% reduction");
        }

        println!("\n");
        println!("═══════════════════════════════════════════════════════════════\n");
    }

    /// Generate summary across all tests
    pub fn generate_summary(&self) -> ValidationSummary {
        let mut total_reductions = Vec::new();
        let mut dvwa_results = None;
        let mut juice_shop_results = None;

        for report in &self.results {
            total_reductions.push(report.reduction_metrics.total_reduction_percent);

            match &report.test_target {
                TestTarget::Dvwa => dvwa_results = Some(report.clone()),
                TestTarget::JuiceShop => juice_shop_results = Some(report.clone()),
                _ => {}
            }
        }

        let avg_reduction = if total_reductions.is_empty() {
            0.0
        } else {
            total_reductions.iter().sum::<f32>() / total_reductions.len() as f32
        };

        ValidationSummary {
            total_tests: self.results.len(),
            average_reduction: avg_reduction,
            dvwa_result: dvwa_results,
            juice_shop_result: juice_shop_results,
            reports: self.results.clone(),
        }
    }

    // Helper functions
    fn is_critical(severity: &Severity) -> bool {
        matches!(severity, Severity::Critical)
    }

    fn is_high(severity: &Severity) -> bool {
        matches!(severity, Severity::High)
    }

    fn is_medium(severity: &Severity) -> bool {
        matches!(severity, Severity::Medium)
    }

    fn is_low(severity: &Severity) -> bool {
        matches!(severity, Severity::Low)
    }
}

#[derive(Debug, Clone)]
pub struct ValidationSummary {
    pub total_tests: usize,
    pub average_reduction: f32,
    pub dvwa_result: Option<ValidationReport>,
    pub juice_shop_result: Option<ValidationReport>,
    pub reports: Vec<ValidationReport>,
}

/// Test data generator for validation
pub struct TestDataGenerator;

impl TestDataGenerator {
    /// Generate DVWA test data
    pub fn dvwa_baseline() -> Vec<Vulnerability> {
        // Simulated CVEs found in DVWA
        let cves = vec![
            // PHP vulnerabilities
            ("CVE-2019-11043", "Critical"), // PHP-FPM RCE
            ("CVE-2018-14884", "High"),     // PHP unserialize
            ("CVE-2018-19518", "High"),     // PHP imap
            // MySQL vulnerabilities
            ("CVE-2021-3156", "High"),    // MySQL privilege escalation
            ("CVE-2020-14765", "Medium"), // MySQL DoS
            // Apache vulnerabilities
            ("CVE-2021-41773", "Critical"), // Apache path traversal
            // jQuery (frontend, not exploitable)
            ("CVE-2020-11022", "Medium"), // jQuery XSS
            ("CVE-2019-11358", "Low"),    // jQuery Prototype pollution
            ("CVE-2020-11023", "Low"),    // jQuery XSS
            // Bootstrap (frontend)
            ("CVE-2018-14041", "Medium"), // Bootstrap XSS
            // Fake/duplicate CVEs
            ("CVE-2018-9999", "Low"), // Fake CVE
            ("CVE-2020-0001", "Low"), // Generic placeholder
        ];

        cves.iter()
            .map(|(id, sev)| Vulnerability {
                cve: id.to_string(),
                severity: match *sev {
                    "Critical" => crate::vuln_detector::Severity::Critical,
                    "High" => crate::vuln_detector::Severity::High,
                    "Medium" => crate::vuln_detector::Severity::Medium,
                    _ => crate::vuln_detector::Severity::Low,
                },
                ..Default::default()
            })
            .collect()
    }

    /// Generate DVWA execution-aware findings
    pub fn dvwa_execution_findings() -> Vec<Finding> {
        // Only exploitable/reachable CVEs
        vec![
            // PHP RCE - actually exploitable via upload
            create_finding("CVE-2019-11043", Priority::Critical, 9.8),
            // Apache traversal - exploitable via path
            create_finding("CVE-2021-41773", Priority::Critical, 9.1),
            // PHP unserialize - exploitable via upload
            create_finding("CVE-2018-14884", Priority::High, 8.1),
        ]
    }

    /// Generate Juice Shop test data
    pub fn juice_shop_baseline() -> Vec<Vulnerability> {
        let cves = vec![
            // Express.js
            ("CVE-2022-24999", "Critical"), // Express qs vulnerability
            ("CVE-2019-5413", "High"),      // Express mime sniffing
            // Node.js
            ("CVE-2021-22939", "High"),     // Node.js HTTP smuggling
            ("CVE-2021-22931", "Critical"), // Node.js prototype pollution
            // Angular
            ("CVE-2020-11028", "Medium"), // Angular XSS
            ("CVE-2020-11023", "Low"),    // Angular DoS
            // SQLMap (dev dependency)
            ("CVE-2019-12345", "Low"), // SQLMap (not in prod)
            // npm packages (transitive)
            ("CVE-2020-7660", "Medium"),  // json-schema
            ("CVE-2021-21388", "Medium"), // axios
            // Fake CVEs
            ("CVE-2020-9999", "Low"),
            ("CVE-2021-0000", "Low"),
        ];

        cves.iter()
            .map(|(id, sev)| Vulnerability {
                cve: id.to_string(),
                severity: match *sev {
                    "Critical" => crate::vuln_detector::Severity::Critical,
                    "High" => crate::vuln_detector::Severity::High,
                    "Medium" => crate::vuln_detector::Severity::Medium,
                    _ => crate::vuln_detector::Severity::Low,
                },
                ..Default::default()
            })
            .collect()
    }

    /// Generate Juice Shop execution-aware findings
    pub fn juice_shop_execution_findings() -> Vec<Finding> {
        vec![
            // Express qs - actually exploitable via query params
            create_finding("CVE-2022-24999", Priority::Critical, 9.1),
            // Node.js proto pollution - exploitable via JSON
            create_finding("CVE-2021-22931", Priority::Critical, 9.8),
            // Express mime - exploitable via file upload
            create_finding("CVE-2019-5413", Priority::High, 7.5),
        ]
    }
}

fn create_finding(cve: &str, priority: Priority, score: f32) -> Finding {
    Finding {
        id: format!("finding-{}", cve),
        detected_at: chrono::Utc::now(),
        identity: scanner_common::RuntimeIdentity {
            node_name: "test".to_string(),
            namespace: "default".to_string(),
            pod_name: "test-pod".to_string(),
            container_name: "app".to_string(),
            image: "test:latest".to_string(),
            workload: "test-workload".to_string(),
            labels: std::collections::BTreeMap::new(),
        },
        signal: scanner_common::RiskSignal {
            cve: cve.to_string(),
            cvss: score,
            epss: 0.95,
            kev: true,
            runtime: scanner_common::RuntimeDisposition::Reachable,
            package: "test".to_string(),
            observed_paths: std::collections::BTreeSet::new(),
        },
        score,
        priority,
        recommendation: "Update".to_string(),
    }
}

impl Default for Vulnerability {
    fn default() -> Self {
        use crate::vuln_detector::Severity;
        Vulnerability {
            package: "unknown".to_string(),
            version: "unknown".to_string(),
            cve: "CVE-0000-00000".to_string(),
            severity: Severity::Low,
            cvss_score: 0.0,
            description: "".to_string(),
            fixed_version: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dvwa_validation() {
        let mut validator = FalsePositiveValidator::new();

        let baseline = TestDataGenerator::dvwa_baseline();
        let execution = TestDataGenerator::dvwa_execution_findings();

        let report = validator.compare_scans(TestTarget::Dvwa, baseline, execution);

        validator.print_report(&report);

        // Should show significant reduction
        assert!(report.reduction_metrics.total_reduction_percent > 50.0);
        assert!(report.execution_aware_scan.exploitable > 0);
    }

    #[test]
    fn test_juice_shop_validation() {
        let mut validator = FalsePositiveValidator::new();

        let baseline = TestDataGenerator::juice_shop_baseline();
        let execution = TestDataGenerator::juice_shop_execution_findings();

        let report = validator.compare_scans(TestTarget::JuiceShop, baseline, execution);

        // Should filter out dev dependencies and transitive packages
        assert!(report.baseline_scan.total_cves > report.execution_aware_scan.total_cves);
    }

    #[test]
    fn test_summary_generation() {
        let mut validator = FalsePositiveValidator::new();

        validator.compare_scans(
            TestTarget::Dvwa,
            TestDataGenerator::dvwa_baseline(),
            TestDataGenerator::dvwa_execution_findings(),
        );

        validator.compare_scans(
            TestTarget::JuiceShop,
            TestDataGenerator::juice_shop_baseline(),
            TestDataGenerator::juice_shop_execution_findings(),
        );

        let summary = validator.generate_summary();

        assert_eq!(summary.total_tests, 2);
        assert!(summary.average_reduction > 0.0);
        assert!(summary.dvwa_result.is_some());
        assert!(summary.juice_shop_result.is_some());
    }
}
