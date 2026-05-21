//! Multi-Cloud Support
//!
//! Provides cloud metadata enrichment for AWS, Azure, and GCP.
//! Auto-detects cloud provider and enriches findings with cloud context.

pub mod aws;
pub mod azure;
pub mod gcp;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cloud provider
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    Unknown,
}

/// Cloud instance metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMetadata {
    pub provider: CloudProvider,
    pub instance_id: String,
    pub instance_type: String,
    pub region: String,
    pub availability_zone: String,
    pub vpc_id: String,
    pub subnet_id: String,
    pub security_groups: Vec<String>,
    pub tags: HashMap<String, String>,
}

impl Default for CloudMetadata {
    fn default() -> Self {
        Self {
            provider: CloudProvider::Unknown,
            instance_id: String::new(),
            instance_type: String::new(),
            region: String::new(),
            availability_zone: String::new(),
            vpc_id: String::new(),
            subnet_id: String::new(),
            security_groups: Vec::new(),
            tags: HashMap::new(),
        }
    }
}

/// Network metadata from cloud provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetadata {
    pub public_ip: Option<String>,
    pub private_ip: String,
    pub public_dns: Option<String>,
    pub private_dns: String,
    pub is_public_subnet: bool,
}

/// Cloud provider trait
#[async_trait::async_trait]
pub trait CloudProviderClient: Send + Sync {
    /// Detect if running on this cloud provider
    async fn detect(&self) -> bool;

    /// Get instance metadata
    async fn get_instance_metadata(&self) -> Result<CloudMetadata, CloudError>;

    /// Get network metadata
    async fn get_network_metadata(&self) -> Result<NetworkMetadata, CloudError>;
}

/// Cloud error types
#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    #[error("Metadata endpoint unreachable: {0}")]
    Unreachable(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Authentication error: {0}")]
    AuthError(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
}

/// Auto-detect cloud provider and get metadata
pub async fn detect_cloud_provider() -> Option<(CloudProvider, CloudMetadata)> {
    // Try AWS first
    let aws_client = aws::AwsMetadataClient::new();
    if aws_client.detect().await {
        match aws_client.get_instance_metadata().await {
            Ok(metadata) => return Some((CloudProvider::Aws, metadata)),
            Err(e) => tracing::warn!("AWS metadata fetch failed: {e}"),
        }
    }

    // Try Azure
    let azure_client = azure::AzureMetadataClient::new();
    if azure_client.detect().await {
        match azure_client.get_instance_metadata().await {
            Ok(metadata) => return Some((CloudProvider::Azure, metadata)),
            Err(e) => tracing::warn!("Azure metadata fetch failed: {e}"),
        }
    }

    // Try GCP
    let gcp_client = gcp::GcpMetadataClient::new();
    if gcp_client.detect().await {
        match gcp_client.get_instance_metadata().await {
            Ok(metadata) => return Some((CloudProvider::Gcp, metadata)),
            Err(e) => tracing::warn!("GCP metadata fetch failed: {e}"),
        }
    }

    None
}
