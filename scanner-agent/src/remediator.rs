use crate::config::RiskConfig;
use crate::error::ScannerError;
use scanner_common::{Finding, Priority, SeccompProfile};
use std::collections::BTreeSet;
use std::time::Duration;

// Conditionally compile protobuf code only if it was generated
#[cfg(feature = "remediator-proto")]
pub mod proto {
    tonic::include_proto!("remediator");
}

#[cfg(feature = "remediator-proto")]
use proto::remediator_client::RemediatorClient;
#[cfg(feature = "remediator-proto")]
use proto::{
    BlockRequest, EnforcementAction, EnforcementRule, QuarantineRequest, RemediationRequest,
    SeccompProfileRequest, ThreatLevel,
};
#[cfg(feature = "remediator-proto")]
use tonic::{transport::Channel, Request};

#[derive(Clone)]
pub struct RemediatorService {
    #[cfg(feature = "remediator-proto")]
    client: Option<RemediatorClient<Channel>>,
    #[cfg(not(feature = "remediator-proto"))]
    client: Option<MockClient>,
    config: RiskConfig,
}

#[cfg(not(feature = "remediator-proto"))]
#[derive(Clone)]
struct MockClient;

impl RemediatorService {
    #[cfg(feature = "remediator-proto")]
    pub async fn connect(addr: &str) -> Result<Self, ScannerError> {
        let endpoint = format!("http://{}", addr);
        let client = RemediatorClient::connect(endpoint)
            .await
            .map_err(|e| ScannerError::Bpf(format!("Failed to connect to remediator: {}", e)))?;

        Ok(Self {
            client: Some(client),
            config: RiskConfig {
                minimum_cvss: 7.0,
                minimum_epss: 0.4,
            },
        })
    }

    #[cfg(not(feature = "remediator-proto"))]
    pub async fn connect(_addr: &str) -> Result<Self, ScannerError> {
        // Protobuf not compiled, use mock
        tracing::info!("Remediator protobuf not compiled, using mock");
        Ok(Self::new_mock())
    }

    pub fn new_mock() -> Self {
        Self {
            client: None,
            config: RiskConfig {
                minimum_cvss: 7.0,
                minimum_epss: 0.4,
            },
        }
    }

    #[cfg(feature = "remediator-proto")]
    pub async fn remediate_finding(&self, finding: &Finding) -> Result<(), ScannerError> {
        let Some(ref client) = self.client else {
            tracing::info!("Mock remediator: would remediate {}", finding.id);
            return Ok(());
        };

        let mut client = client.clone();

        let request = RemediationRequest {
            finding_id: finding.id.clone(),
            threat_level: priority_to_threat_level(&finding.priority),
            workload_id: finding.identity.workload.clone(),
            namespace: finding.identity.namespace.clone(),
            pod_name: finding.identity.pod_name.clone(),
            container_name: finding.identity.container_name.clone(),
            cve_id: finding.signal.cve.clone(),
            cvss_score: finding.signal.cvss,
            epss_score: finding.signal.epss,
            is_kev: finding.signal.kev,
            package_name: finding.signal.package.clone(),
            recommended_action: finding.recommendation.clone(),
        };

        let response = client
            .remediate(Request::new(request))
            .await
            .map_err(|e| ScannerError::Bpf(format!("Remediation failed: {}", e)))?;

        tracing::info!(
            "Remediation response: success={}, action_taken={}",
            response.get_ref().success,
            response.get_ref().action_taken
        );

        Ok(())
    }

    #[cfg(not(feature = "remediator-proto"))]
    pub async fn remediate_finding(&self, finding: &Finding) -> Result<(), ScannerError> {
        tracing::info!("Mock remediator: would remediate {}", finding.id);
        Ok(())
    }

    #[cfg(feature = "remediator-proto")]
    pub async fn enforce_seccomp(
        &self,
        workload: &str,
        profile: &SeccompProfile,
    ) -> Result<(), ScannerError> {
        let Some(ref client) = self.client else {
            tracing::info!("Mock remediator: would enforce seccomp for {}", workload);
            return Ok(());
        };

        let mut client = client.clone();

        let request = SeccompProfileRequest {
            workload_id: workload.to_string(),
            profile_json: serde_json::to_string(profile)?,
            namespace: "default".to_string(),
            dry_run: false,
        };

        let response = client
            .apply_seccomp(Request::new(request))
            .await
            .map_err(|e| ScannerError::Bpf(format!("Seccomp enforcement failed: {}", e)))?;

        tracing::info!(
            "Seccomp enforcement: applied={}",
            response.get_ref().applied
        );

        Ok(())
    }

    #[cfg(not(feature = "remediator-proto"))]
    pub async fn enforce_seccomp(
        &self,
        workload: &str,
        _profile: &SeccompProfile,
    ) -> Result<(), ScannerError> {
        tracing::info!("Mock remediator: would enforce seccomp for {}", workload);
        Ok(())
    }

    #[cfg(feature = "remediator-proto")]
    pub async fn block_egress(&self, pod_name: &str, namespace: &str) -> Result<(), ScannerError> {
        let Some(ref client) = self.client else {
            tracing::info!("Mock remediator: would block egress for {}/{}", namespace, pod_name);
            return Ok(());
        };

        let mut client = client.clone();

        let request = BlockRequest {
            workload_id: pod_name.to_string(),
            namespace: namespace.to_string(),
            direction: "egress".to_string(),
            reason: "Suspicious network activity detected".to_string(),
            duration_sec: 3600,
        };

        let _response = client
            .block_network(Request::new(request))
            .await
            .map_err(|e| ScannerError::Bpf(format!("Network block failed: {}", e)))?;

        tracing::info!("Egress blocked for {}/{}", namespace, pod_name);

        Ok(())
    }

    #[cfg(not(feature = "remediator-proto"))]
    pub async fn block_egress(&self, pod_name: &str, namespace: &str) -> Result<(), ScannerError> {
        tracing::info!("Mock remediator: would block egress for {}/{}", namespace, pod_name);
        Ok(())
    }

    #[cfg(feature = "remediator-proto")]
    pub async fn quarantine_pod(
        &self,
        pod_name: &str,
        namespace: &str,
        reason: &str,
    ) -> Result<(), ScannerError> {
        let Some(ref client) = self.client else {
            tracing::info!("Mock remediator: would quarantine {}/{}: {}", namespace, pod_name, reason);
            return Ok(());
        };

        let mut client = client.clone();

        let request = QuarantineRequest {
            workload_id: pod_name.to_string(),
            namespace: namespace.to_string(),
            reason: reason.to_string(),
            isolate_network: true,
            isolate_storage: false,
        };

        let _response = client
            .quarantine(Request::new(request))
            .await
            .map_err(|e| ScannerError::Bpf(format!("Quarantine failed: {}", e)))?;

        tracing::info!("Pod {}/{} quarantined", namespace, pod_name);

        Ok(())
    }

    #[cfg(not(feature = "remediator-proto"))]
    pub async fn quarantine_pod(
        &self,
        pod_name: &str,
        namespace: &str,
        reason: &str,
    ) -> Result<(), ScannerError> {
        tracing::info!("Mock remediator: would quarantine {}/{}: {}", namespace, pod_name, reason);
        Ok(())
    }
}

#[cfg(feature = "remediator-proto")]
fn priority_to_threat_level(priority: &Priority) -> i32 {
    match priority {
        Priority::Informational => 0,
        Priority::Low => 1,
        Priority::Medium => 2,
        Priority::High => 3,
        Priority::Critical => 4,
    }
}

#[cfg(not(feature = "remediator-proto"))]
pub async fn remediate_finding_mock(finding: &Finding) -> Result<(), ScannerError> {
    tracing::info!("Mock remediator: would remediate {}", finding.id);
    Ok(())
}

#[cfg(not(feature = "remediator-proto"))]
pub async fn enforce_seccomp_mock(workload: &str, _profile: &SeccompProfile) -> Result<(), ScannerError> {
    tracing::info!("Mock remediator: would enforce seccomp for {}", workload);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_remediator_works() {
        let service = RemediatorService::new_mock();
        let finding = Finding {
            id: "test-123".to_string(),
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
                cve: "CVE-2025-1234".to_string(),
                cvss: 9.8,
                epss: 0.95,
                kev: true,
                runtime: scanner_common::RuntimeDisposition::Reachable,
                package: "openssl".to_string(),
                observed_paths: std::collections::BTreeSet::new(),
            },
            score: 9.5,
            priority: Priority::Critical,
            recommendation: "Patch immediately".to_string(),
        };

        assert!(service.remediate_finding(&finding).await.is_ok());
    }
}
