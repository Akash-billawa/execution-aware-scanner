//! GCP Compute Engine Metadata Service Client
//!
//! Fetches instance metadata from the GCP metadata server.

use super::*;
use reqwest::Client;
use std::time::Duration;

const GCP_METADATA_BASE: &str = "http://metadata.google.internal/computeMetadata/v1";
const GCP_METADATA_TIMEOUT: Duration = Duration::from_secs(2);

/// GCP metadata client
pub struct GcpMetadataClient {
    client: Client,
}

impl GcpMetadataClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(GCP_METADATA_TIMEOUT)
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    async fn fetch_text(&self, path: &str) -> Result<String, CloudError> {
        let url = format!("{GCP_METADATA_BASE}/{path}");
        let resp = self
            .client
            .get(&url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| CloudError::Unreachable(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(CloudError::Unreachable(format!("HTTP {}", resp.status())));
        }

        resp.text()
            .await
            .map_err(|e| CloudError::ParseError(e.to_string()))
    }
}

#[async_trait::async_trait]
impl CloudProviderClient for GcpMetadataClient {
    async fn detect(&self) -> bool {
        self.fetch_text("instance/id").await.is_ok()
    }

    async fn get_instance_metadata(&self) -> Result<CloudMetadata, CloudError> {
        let instance_id = self.fetch_text("instance/id").await?;
        let instance_type = self.fetch_text("instance/machine-type").await?;
        let zone = self.fetch_text("instance/zone").await.unwrap_or_default();
        let zone_name = zone.rsplit_once('/').map(|(_, z)| z).unwrap_or("");

        // Extract region from zone (e.g., us-central1-a -> us-central1)
        let region = zone_name
            .rsplit_once('-')
            .map(|(r, _)| r.to_string())
            .unwrap_or_else(|| zone_name.to_string());

        Ok(CloudMetadata {
            provider: CloudProvider::Gcp,
            instance_id,
            instance_type: instance_type
                .rsplit_once('/')
                .map(|(_, t)| t)
                .unwrap_or(&instance_type)
                .to_string(),
            region,
            availability_zone: zone_name.to_string(),
            vpc_id: String::new(),
            subnet_id: String::new(),
            security_groups: Vec::new(),
            tags: HashMap::new(),
        })
    }

    async fn get_network_metadata(&self) -> Result<NetworkMetadata, CloudError> {
        let private_ip = self
            .fetch_text("instance/network-interfaces/0/ip")
            .await
            .unwrap_or_default();

        let public_ip = self
            .fetch_text("instance/network-interfaces/0/access-configs/0/external-ip")
            .await
            .ok();

        let hostname = self
            .fetch_text("instance/hostname")
            .await
            .unwrap_or_default();

        Ok(NetworkMetadata {
            public_ip,
            private_ip,
            public_dns: None,
            private_dns: hostname,
            is_public_subnet: false,
        })
    }
}
