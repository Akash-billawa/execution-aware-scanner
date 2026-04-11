use crate::config::IntelConfig;
use crate::error::ScannerError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Comprehensive threat intelligence state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntelState {
    /// CISA Known Exploited Vulnerabilities catalog
    pub kev: BTreeSet<String>,
    /// EPSS scores (0.0 - 1.0)
    pub epss: BTreeMap<String, f32>,
    /// EPSS percentiles (0.0 - 1.0)
    pub epss_percentiles: BTreeMap<String, f32>,
    /// CVE metadata from NVD
    pub cve_metadata: BTreeMap<String, CveMetadata>,
    /// Last successful refresh
    pub last_refresh: Option<DateTime<Utc>>,
    /// CVE first seen dates
    pub first_seen: BTreeMap<String, DateTime<Utc>>,
}

/// CVE metadata from threat intelligence sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveMetadata {
    pub id: String,
    pub description: Option<String>,
    pub cvss_v2_score: Option<f32>,
    pub cvss_v3_score: Option<f32>,
    pub published_date: Option<String>,
    pub last_modified: Option<String>,
    pub vendor_advisories: Vec<String>,
    pub exploit_pocs: Vec<String>,
    pub threat_actors: Vec<String>,
    pub malware_families: Vec<String>,
}

/// Enhanced threat intelligence feed
#[derive(Clone)]
pub struct IntelFeed {
    client: reqwest::Client,
    config: IntelConfig,
    state: Arc<RwLock<IntelState>>,
}

/// CISA KEV catalog structure
#[derive(Debug, Deserialize)]
struct KevCatalog {
    #[serde(rename = "catalogVersion")]
    version: String,
    #[serde(rename = "dateReleased")]
    date_released: String,
    count: i32,
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject")]
    vendor_project: String,
    #[serde(rename = "product")]
    product: String,
    #[serde(rename = "vulnerabilityName")]
    vulnerability_name: String,
    #[serde(rename = "dateAdded")]
    date_added: String,
    #[serde(rename = "dueDate")]
    due_date: String,
    #[serde(rename = "requiredAction")]
    required_action: String,
    notes: Option<String>,
}

/// EPSS API response
#[derive(Debug, Deserialize)]
struct EpssResponse {
    status: String,
    #[serde(rename = "status-code")]
    status_code: i32,
    version: String,
    #[serde(rename = "total")]
    total: i32,
    #[serde(rename = "offset")]
    offset: i32,
    #[serde(rename = "limit")]
    limit: i32,
    data: Vec<EpssEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct EpssEntry {
    cve: String,
    epss: String,
    percentile: String,
    #[serde(rename = "date")]
    date: String,
}

impl IntelFeed {
    pub fn new(config: IntelConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(10)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            config,
            state: Arc::new(RwLock::new(IntelState::default())),
        }
    }

    /// Refresh all threat intelligence feeds
    pub async fn refresh(&self) -> Result<(), ScannerError> {
        info!("Refreshing threat intelligence feeds...");

        // Fetch CISA KEV
        match self.fetch_kev().await {
            Ok(kev_data) => {
                let mut state = self.state.write().await;
                let new_kevs: Vec<_> = kev_data
                    .vulnerabilities
                    .iter()
                    .map(|v| v.cve_id.clone())
                    .filter(|cve| !state.kev.contains(cve))
                    .collect();
                
                state.kev = kev_data.vulnerabilities.into_iter().map(|v| v.cve_id).collect();
                state.last_refresh = Some(Utc::now());
                
                if !new_kevs.is_empty() {
                    info!("Updated CISA KEV: {} new CVEs, total {} CVEs", new_kevs.len(), state.kev.len());
                } else {
                    debug!("CISA KEV refreshed, no new CVEs");
                }
            }
            Err(e) => {
                warn!("Failed to fetch CISA KEV: {}", e);
            }
        }

        // Fetch EPSS scores
        match self.fetch_epss().await {
            Ok(epss_data) => {
                let mut state = self.state.write().await;
                for entry in epss_data.data {
                    if let Ok(score) = entry.epss.parse::<f32>() {
                        state.epss.insert(entry.cve.clone(), score);
                    }
                    if let Ok(percentile) = entry.percentile.parse::<f32>() {
                        state.epss_percentiles.insert(entry.cve, percentile);
                    }
                }
                info!("Updated EPSS scores: {} CVEs", state.epss.len());
            }
            Err(e) => {
                warn!("Failed to fetch EPSS: {}", e);
            }
        }

        info!("Threat intelligence refresh complete");
        Ok(())
    }

    /// Fetch CISA Known Exploited Vulnerabilities catalog
    async fn fetch_kev(&self) -> Result<KevCatalog, ScannerError> {
        debug!("Fetching CISA KEV from {}", self.config.kev_url);

        let response = self
            .client
            .get(&self.config.kev_url)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ScannerError::Http(
                reqwest::Error::from(response.error_for_status().unwrap_err())
            ));
        }

        let catalog = response.json::<KevCatalog>().await?;
        debug!("CISA KEV: version={}, count={}", catalog.version, catalog.count);
        
        Ok(catalog)
    }

    /// Fetch EPSS scores for CVEs
    async fn fetch_epss(&self) -> Result<EpssResponse, ScannerError> {
        debug!("Fetching EPSS scores from {}", self.config.epss_url);

        // EPSS API supports batch queries
        let response = self
            .client
            .get(&self.config.epss_url)
            .query(&[("scope", "epss")])
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ScannerError::Http(
                reqwest::Error::from(response.error_for_status().unwrap_err())
            ));
        }

        let data = response.json::<EpssResponse>().await?;
        debug!("EPSS: {} CVEs in response", data.data.len());
        
        Ok(data)
    }

    /// Fetch EPSS scores for specific CVEs (batch query)
    pub async fn fetch_epss_for_cves(&self, cves: &[String]) -> Result<BTreeMap<String, f32>, ScannerError> {
        if cves.is_empty() {
            return Ok(BTreeMap::new());
        }

        debug!("Fetching EPSS for {} CVEs", cves.len());

    let cve_list = cves.join(",");
    let response = self
        .client
        .get(&self.config.epss_url)
        .query(&[("cve", cve_list), ("scope", "epss".to_string())])
        .send()
        .await?;

        let data = response.json::<EpssResponse>().await?;
        
        let mut scores = BTreeMap::new();
        for entry in data.data {
            if let Ok(score) = entry.epss.parse::<f32>() {
                scores.insert(entry.cve, score);
            }
        }

        Ok(scores)
    }

    /// Check if CVE is in CISA KEV
    pub async fn is_kev(&self, cve_id: &str) -> bool {
        let state = self.state.read().await;
        state.kev.contains(cve_id)
    }

    /// Get EPSS score for CVE
    pub async fn get_epss(&self, cve_id: &str) -> Option<f32> {
        let state = self.state.read().await;
        state.epss.get(cve_id).copied()
    }

    /// Get EPSS percentile for CVE
    pub async fn get_epss_percentile(&self, cve_id: &str) -> Option<f32> {
        let state = self.state.read().await;
        state.epss_percentiles.get(cve_id).copied()
    }

    /// Get comprehensive risk assessment for CVE
    pub async fn assess_cve(&self, cve_id: &str) -> CveRiskAssessment {
        let state = self.state.read().await;
        
        CveRiskAssessment {
            cve_id: cve_id.to_string(),
            is_kev: state.kev.contains(cve_id),
            epss_score: state.epss.get(cve_id).copied().unwrap_or(0.0),
            epss_percentile: state.epss_percentiles.get(cve_id).copied().unwrap_or(0.0),
            intel_age: state.last_refresh.map(|t| Utc::now() - t),
        }
    }

    /// Get state reference
    pub fn state(&self) -> Arc<RwLock<IntelState>> {
        Arc::clone(&self.state)
    }

    /// Get refresh interval
    pub fn refresh_interval(&self) -> Duration {
        Duration::from_secs(self.config.refresh_interval_secs)
    }

    /// Export current state as JSON
    pub async fn export_state(&self) -> Result<String, ScannerError> {
        let state = self.state.read().await;
        serde_json::to_string(&*state).map_err(ScannerError::Json)
    }

    /// Import state from JSON (for testing/persistence)
    pub async fn import_state(&self, json: &str) -> Result<(), ScannerError> {
        let imported: IntelState = serde_json::from_str(json)?;
        let mut state = self.state.write().await;
        *state = imported;
        Ok(())
    }
}

/// Comprehensive CVE risk assessment
#[derive(Debug, Clone)]
pub struct CveRiskAssessment {
    pub cve_id: String,
    pub is_kev: bool,
    pub epss_score: f32,
    pub epss_percentile: f32,
    pub intel_age: Option<chrono::Duration>,
}

impl serde::Serialize for CveRiskAssessment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CveRiskAssessment", 5)?;
        state.serialize_field("cve_id", &self.cve_id)?;
        state.serialize_field("is_kev", &self.is_kev)?;
        state.serialize_field("epss_score", &self.epss_score)?;
        state.serialize_field("epss_percentile", &self.epss_percentile)?;
        state.serialize_field(
            "intel_age_hours",
            &self.intel_age.map(|d| d.num_hours()),
        )?;
        state.end()
    }
}

impl CveRiskAssessment {
    /// Combined threat score (0-100)
    pub fn threat_score(&self) -> f32 {
        let mut score = 0.0;

        // EPSS contributes up to 40 points
        score += self.epss_score * 40.0;

        // Percentile contributes up to 30 points
        score += self.epss_percentile * 30.0;

        // KEV bonus: 30 points
        if self.is_kev {
            score += 30.0;
        }

        score.min(100.0)
    }

    /// Check if intelligence is stale (>24 hours)
    pub fn is_stale(&self) -> bool {
        match self.intel_age {
            Some(age) => age.num_hours() > 24,
            None => true,
        }
    }
}

/// Webhook payload for finding export
#[derive(Debug, Clone, serde::Serialize)]
pub struct WebhookPayload {
    pub timestamp: DateTime<Utc>,
    pub finding: scanner_common::Finding,
    pub threat_assessment: Option<CveRiskAssessment>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_starts_empty() {
        let feed = IntelFeed::new(IntelConfig {
            kev_url: "https://example.com/kev.json".to_string(),
            epss_url: "https://example.com/epss.json".to_string(),
            refresh_interval_secs: 60,
        });
        
        let state = feed.state();
        let snapshot = state.read().await;
        assert!(snapshot.kev.is_empty());
        assert!(snapshot.epss.is_empty());
    }

    #[tokio::test]
    async fn test_cve_risk_assessment() {
        let assessment = CveRiskAssessment {
            cve_id: "CVE-2021-44228".to_string(),
            is_kev: true,
            epss_score: 0.95,
            epss_percentile: 0.99,
            intel_age: Some(chrono::Duration::hours(1)),
        };

        let score = assessment.threat_score();
        assert!(score > 90.0, "High threat score expected, got {}", score);
        assert!(!assessment.is_stale());

        let stale_assessment = CveRiskAssessment {
            cve_id: "CVE-2021-44228".to_string(),
            is_kev: true,
            epss_score: 0.95,
            epss_percentile: 0.99,
            intel_age: Some(chrono::Duration::hours(25)),
        };
        assert!(stale_assessment.is_stale());
    }
}
