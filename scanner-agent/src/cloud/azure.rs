//! Azure Instance Metadata Service Client
//!
//! Fetches instance metadata from the Azure Instance Metadata Service (IMDS).

use super::*;
use reqwest::Client;
use std::time::Duration;

const AZURE_METADATA_BASE: &str = "http://169.254.169.254/metadata/instance";
const AZURE_METADATA_TIMEOUT: Duration = Duration::from_secs(2);

/// Azure metadata client
pub struct AzureMetadataClient {
    client: Client,
}

impl AzureMetadataClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(AZURE_METADATA_TIMEOUT)
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    async fn fetch_json(&self, path: &str) -> Result<serde_json::Value, CloudError> {
        let url = format!("{AZURE_METADATA_BASE}/{path}?api-version=2021-02-01");
        let resp = self
            .client
            .get(&url)
            .header("Metadata", "true")
            .send()
            .await
            .map_err(|e| CloudError::Unreachable(e.to_string()))?;

        resp.json()
            .await
            .map_err(|e| CloudError::ParseError(e.to_string()))
    }
}

#[async_trait::async_trait]
impl CloudProviderClient for AzureMetadataClient {
    async fn detect(&self) -> bool {
        self.fetch_json("").await.is_ok()
    }

    async fn get_instance_metadata(&self) -> Result<CloudMetadata, CloudError> {
        let data = self.fetch_json("").await?;

        let compute = data
            .get("compute")
            .ok_or_else(|| CloudError::ParseError("Missing compute section".to_string()))?;

        let instance_id = compute
            .get("vmId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let instance_type = compute
            .get("vmSize")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let region = compute
            .get("location")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let az = compute
            .get("zone")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let resource_group = compute
            .get("resourceGroupName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(CloudMetadata {
            provider: CloudProvider::Azure,
            instance_id,
            instance_type,
            region,
            availability_zone: az,
            vpc_id: resource_group, // Azure uses resource groups instead of VPCs
            subnet_id: String::new(),
            security_groups: Vec::new(),
            tags: HashMap::new(),
        })
    }

    async fn get_network_metadata(&self) -> Result<NetworkMetadata, CloudError> {
        let data = self.fetch_json("network").await?;

        let interface = data
            .get("interface")
            .and_then(|i| i.get(0))
            .ok_or_else(|| CloudError::ParseError("No network interfaces".to_string()))?;

        let ipv4 = interface
            .get("ipv4")
            .and_then(|i| i.get("ipAddress"))
            .and_then(|i| i.get(0));

        let private_ip = ipv4
            .and_then(|i| i.get("privateIpAddress"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let public_ip = ipv4
            .and_then(|i| i.get("publicIpAddress"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(NetworkMetadata {
            public_ip,
            private_ip,
            public_dns: None,
            private_dns: String::new(),
            is_public_subnet: false,
        })
    }
}
