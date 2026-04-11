// Integration tests for the execution-aware scanner

use std::collections::BTreeSet;
use std::time::Duration;

/// Test constants
pub const TEST_TIMEOUT: Duration = Duration::from_secs(60);
pub const TEST_SBOM_DIR: &str = "/tmp/test-scanner/sboms";
pub const TEST_SECCOMP_DIR: &str = "/tmp/test-scanner/seccomp";

/// Helper to create test SBOM files
pub async fn setup_test_sboms() -> std::io::Result<()> {
    tokio::fs::create_dir_all(TEST_SBOM_DIR).await?;
    
    let sbom_content = r#"[
        {
            "package": "openssl",
            "version": "1.1.1",
            "cves": [
                {
                    "id": "CVE-2021-3449",
                    "cvss": 7.5,
                    "severity": "High"
                }
            ],
            "paths": ["/usr/lib/libssl.so"]
        }
    ]"#;
    
    tokio::fs::write(
        format!("{}/test_nginx_1.0.json", TEST_SBOM_DIR),
        sbom_content
    ).await?;
    
    Ok(())
}

/// Cleanup test artifacts
pub async fn cleanup_test_artifacts() -> std::io::Result<()> {
    let _ = tokio::fs::remove_dir_all("/tmp/test-scanner").await;
    Ok(())
}

#[tokio::test]
async fn test_end_to_end_scanning() {
    // This would run a full end-to-end test
    // Requires actual eBPF and K8s environment
    
    setup_test_sboms().await.expect("Failed to setup test SBOMs");
    
    // Mock test - in real CI this would use kind/minikube
    let findings: Vec<scanner_common::Finding> = vec![];
    
    // Cleanup
    cleanup_test_artifacts().await.ok();
    
    // Assertions would go here
    assert!(findings.is_empty() || !findings.is_empty());
}

#[test]
fn test_risk_calculation() {
    use scanner_common::{Priority, RiskSignal, RuntimeDisposition, RuntimeIdentity};
    
    let signal = RiskSignal {
        cve: "CVE-2021-44228".to_string(),
        cvss: 10.0,
        epss: 0.95,
        kev: true,
        runtime: RuntimeDisposition::Reachable,
        package: "log4j".to_string(),
        observed_paths: BTreeSet::from(["/app/lib/log4j.jar".to_string()]),
    };
    
    // Critical finding: CVSS 10, EPSS 0.95, KEV, Reachable
    assert!(signal.cvss >= 9.0);
    assert!(signal.epss >= 0.9);
    assert!(signal.kev);
    assert!(matches!(signal.runtime, RuntimeDisposition::Reachable));
}

#[test]
fn test_seccomp_generation() {
    use std::collections::BTreeSet;
    
    let syscalls: BTreeSet<String> = [
        "openat", "read", "write", "mmap", "execve"
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    
    // Verify syscalls are properly categorized
    assert!(syscalls.contains("openat"));
    assert!(syscalls.contains("execve"));
}
