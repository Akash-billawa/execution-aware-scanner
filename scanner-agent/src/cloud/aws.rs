//! AWS EC2 Metadata Service Client
//!
//! Fetches instance metadata from the EC2 instance metadata service (IMDS).

use super::*;
use reqwest::Client;
use std::time::Duration;

const AWS_METADATA_BASE: &str = "http://169.254.169.254/latest/meta-data";
const AWS_METADATA_TIMEOUT: Duration = Duration::from_secs(2);

/// AWS EC2 metadata client
pub struct AwsMetadataClient {
    client: Client,
}

impl AwsMetadataClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(AWS_METADATA_TIMEOUT)
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    async fn fetch_text(&self, path: &str) -> Result<String, CloudError> {
        let url = format!("{AWS_METADATA_BASE}/{path}");
        self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| CloudError::Unreachable(e.to_string()))?
            .text()
            .await
            .map_err(|e| CloudError::ParseError(e.to_string()))
    }
}

#[async_trait::async_trait]
impl CloudProviderClient for AwsMetadataClient {
    async fn detect(&self) -> bool {
        self.fetch_text("instance-id").await.is_ok()
    }

    async fn get_instance_metadata(&self) -> Result<CloudMetadata, CloudError> {
        let instance_id = self.fetch_text("instance-id").await?;
        let instance_type = self.fetch_text("instance-type").await?;
        let region = self.fetch_text("placement/region").await?;
        let az = self.fetch_text("placement/availability-zone").await?;

        // Get network info
        let mac = self.fetch_text("network/interfaces/macs/").await?;
        let mac = mac.trim().trim_end_matches('/');
        let vpc_id = self
            .fetch_text(&format!("network/interfaces/macs/{mac}/vpc-id"))
            .await
            .unwrap_or_default();
        let subnet_id = self
            .fetch_text(&format!("network/interfaces/macs/{mac}/subnet-id"))
            .await
            .unwrap_or_default();

        Ok(CloudMetadata {
            provider: CloudProvider::Aws,
            instance_id,
            instance_type,
            region,
            availability_zone: az,
            vpc_id,
            subnet_id,
            security_groups: Vec::new(),
            tags: HashMap::new(),
        })
    }

    async fn get_network_metadata(&self) -> Result<NetworkMetadata, CloudError> {
        let private_ip = self.fetch_text("local-ipv4").await?;
        let public_ip = self.fetch_text("public-ipv4").await.ok();
        let public_dns = self.fetch_text("public-hostname").await.ok();
        let private_dns = self.fetch_text("local-hostname").await?;

        let is_public_subnet = public_ip.is_some();

        Ok(NetworkMetadata {
            public_ip,
            private_ip,
            public_dns,
            private_dns,
            is_public_subnet,
        })
    }
}
