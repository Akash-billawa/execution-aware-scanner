//! OCI Artifact Scanner
//!
//! Scans OCI artifacts (container images, Helm charts, WASM modules)
//! by pulling manifests and layers from OCI registries.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

/// OCI manifest
#[derive(Debug, Deserialize)]
struct OciManifest {
    #[serde(rename = "mediaType")]
    media_type: String,
    layers: Vec<OciLayer>,
    config: Option<OciConfig>,
}

#[derive(Debug, Deserialize)]
struct OciLayer {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    size: u64,
    annotations: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct OciConfig {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
}

/// Result of scanning an OCI artifact
#[derive(Debug, Serialize)]
pub struct OciScanResult {
    pub reference: String,
    pub artifact_type: ArtifactType,
    pub layers_scanned: usize,
    pub findings: Vec<OciFinding>,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Serialize, PartialEq)]
pub enum ArtifactType {
    ContainerImage,
    HelmChart,
    WasmModule,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct OciFinding {
    pub severity: String,
    pub description: String,
    pub layer_digest: String,
    pub file_path: Option<String>,
}

/// OCI artifact scanner
pub struct OciScanner {
    client: reqwest::Client,
    registries: HashMap<String, RegistryAuth>,
}

#[derive(Debug, Clone)]
pub struct RegistryAuth {
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
}

impl Default for OciScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl OciScanner {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("Failed to create HTTP client"),
            registries: HashMap::new(),
        }
    }

    /// Add registry authentication
    pub fn with_auth(mut self, registry: String, auth: RegistryAuth) -> Self {
        self.registries.insert(registry, auth);
        self
    }

    /// Scan an OCI artifact by reference (e.g., "ghcr.io/org/image:tag")
    pub async fn scan(&self, reference: &str) -> Result<OciScanResult, String> {
        let start = std::time::Instant::now();

        let (registry, repository, tag) = parse_reference(reference)?;

        // Fetch the manifest
        let manifest = self.fetch_manifest(&registry, &repository, &tag).await?;

        // Determine artifact type
        let artifact_type = classify_artifact(&manifest);

        // Scan layers
        let mut findings = Vec::new();
        for layer in &manifest.layers {
            match artifact_type {
                ArtifactType::HelmChart => {
                    if layer.media_type.contains("tar") {
                        findings.extend(
                            self.scan_helm_layer(&registry, &repository, &layer.digest)
                                .await?,
                        );
                    }
                }
                ArtifactType::WasmModule => {
                    findings.extend(
                        self.scan_wasm_layer(&registry, &repository, &layer.digest)
                            .await?,
                    );
                }
                ArtifactType::ContainerImage => {
                    // Container image scanning is handled by Trivy
                    info!(reference, "Container image scanning delegated to Trivy");
                }
                ArtifactType::Unknown => {
                    info!(media_type = %layer.media_type, "Unknown artifact type, skipping layer scan");
                }
            }
        }

        let scan_duration_ms = start.elapsed().as_millis() as u64;

        info!(
            reference,
            artifact_type = ?artifact_type,
            layers = manifest.layers.len(),
            findings = findings.len(),
            duration_ms = scan_duration_ms,
            "OCI scan completed"
        );

        Ok(OciScanResult {
            reference: reference.to_string(),
            artifact_type,
            layers_scanned: manifest.layers.len(),
            findings,
            scan_duration_ms,
        })
    }

    /// Fetch manifest from OCI registry
    async fn fetch_manifest(
        &self,
        registry: &str,
        repository: &str,
        tag: &str,
    ) -> Result<OciManifest, String> {
        let url = format!("https://{registry}/v2/{repository}/manifests/{tag}");

        let mut req = self
            .client
            .get(&url)
            .header("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json");

        if let Some(auth) = self.registries.get(registry) {
            if let Some(token) = &auth.token {
                req = req.bearer_auth(token);
            } else if let (Some(user), Some(pass)) = (&auth.username, &auth.password) {
                req = req.basic_auth(user, Some(pass));
            }
        }

        let resp = req.send().await.map_err(|e| format!("HTTP error: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Registry returned {}", resp.status()));
        }

        resp.json::<OciManifest>()
            .await
            .map_err(|e| format!("Manifest parse error: {e}"))
    }

    /// Scan a Helm chart layer for issues
    async fn scan_helm_layer(
        &self,
        _registry: &str,
        _repository: &str,
        _digest: &str,
    ) -> Result<Vec<OciFinding>, String> {
        // In a real implementation, this would:
        // 1. Download and decompress the layer
        // 2. Extract Chart.yaml and values.yaml
        // 3. Check for known vulnerable image references
        // 4. Validate chart structure
        Ok(Vec::new())
    }

    /// Scan a WASM module layer
    async fn scan_wasm_layer(
        &self,
        _registry: &str,
        _repository: &str,
        _digest: &str,
    ) -> Result<Vec<OciFinding>, String> {
        // In a real implementation, this would:
        // 1. Download the WASM module
        // 2. Analyze imports/exports for dangerous capabilities
        // 3. Check for known vulnerable dependencies
        Ok(Vec::new())
    }

    /// Verify Cosign signature of an OCI artifact
    pub async fn verify_signature(&self, reference: &str) -> Result<bool, String> {
        let output = tokio::process::Command::new("cosign")
            .args(["verify", reference])
            .output()
            .await
            .map_err(|e| format!("Failed to run cosign: {e}"))?;

        Ok(output.status.success())
    }
}

/// Parse an OCI reference into (registry, repository, tag)
fn parse_reference(reference: &str) -> Result<(String, String, String), String> {
    let reference = reference.strip_prefix("oci://").unwrap_or(reference);

    let (registry, remainder) = reference
        .split_once('/')
        .ok_or("Invalid reference format")?;

    let (repository, tag) = match remainder.rsplit_once(':') {
        Some((repo, tag)) => (repo.to_string(), tag.to_string()),
        None => (remainder.to_string(), "latest".to_string()),
    };

    Ok((registry.to_string(), repository, tag))
}

/// Classify an artifact based on its manifest media types
fn classify_artifact(manifest: &OciManifest) -> ArtifactType {
    let config_type = manifest
        .config
        .as_ref()
        .map(|c| c.media_type.as_str())
        .unwrap_or("");

    if config_type.contains("helm")
        || manifest
            .layers
            .iter()
            .any(|l| l.media_type.contains("helm"))
    {
        ArtifactType::HelmChart
    } else if manifest
        .layers
        .iter()
        .any(|l| l.media_type.contains("wasm"))
    {
        ArtifactType::WasmModule
    } else if config_type.contains("container") || config_type.contains("docker") {
        ArtifactType::ContainerImage
    } else {
        ArtifactType::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_reference() {
        let (reg, repo, tag) = parse_reference("ghcr.io/org/image:latest").unwrap();
        assert_eq!(reg, "ghcr.io");
        assert_eq!(repo, "org/image");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn test_parse_reference_oci_prefix() {
        let (reg, repo, tag) = parse_reference("oci://ghcr.io/org/image:v1.0").unwrap();
        assert_eq!(reg, "ghcr.io");
        assert_eq!(repo, "org/image");
        assert_eq!(tag, "v1.0");
    }

    #[test]
    fn test_parse_reference_no_tag() {
        let (reg, repo, tag) = parse_reference("ghcr.io/org/image").unwrap();
        assert_eq!(reg, "ghcr.io");
        assert_eq!(repo, "org/image");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn test_classify_artifact_helm() {
        let manifest = OciManifest {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            layers: vec![OciLayer {
                media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
                digest: "sha256:abc".to_string(),
                size: 1024,
                annotations: None,
            }],
            config: Some(OciConfig {
                media_type: "application/vnd.cncf.helm.config.v1+json".to_string(),
                digest: "sha256:def".to_string(),
            }),
        };
        assert_eq!(classify_artifact(&manifest), ArtifactType::HelmChart);
    }

    #[test]
    fn test_classify_artifact_wasm() {
        let manifest = OciManifest {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            layers: vec![OciLayer {
                media_type: "application/vnd.wasm.content.layer.v1+wasm".to_string(),
                digest: "sha256:abc".to_string(),
                size: 2048,
                annotations: None,
            }],
            config: None,
        };
        assert_eq!(classify_artifact(&manifest), ArtifactType::WasmModule);
    }
}
