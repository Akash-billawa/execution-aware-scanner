use crate::webhook::WebhookConfig;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub bpf: BpfConfig,
    pub metrics: MetricsConfig,
    pub intel: IntelConfig,
    pub risk: RiskConfig,
    pub runtime: RuntimeConfig,
    pub remediator: RemediatorConfig,
    pub webhook: WebhookConfig,
    pub export: ExportConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BpfConfig {
    pub object_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    pub bind_addr: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IntelConfig {
    pub kev_url: String,
    pub epss_url: String,
    pub refresh_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RiskConfig {
    pub minimum_cvss: f64,
    pub minimum_epss: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConfig {
    pub node_name: String,
    pub sbom_dir: String,
    pub seccomp_output_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemediatorConfig {
    pub enabled: bool,
    pub address: String,
    pub timeout_secs: u64,
    pub max_retries: u32,
    pub enforce_critical: bool,
    pub enforce_high: bool,
    pub auto_seccomp: bool,
    pub auto_quarantine: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExportConfig {
    pub enabled: bool,
    pub format: String,
    pub output_path: String,
    pub rotate_interval_secs: u64,
    pub compress: bool,
    pub endpoints: HashMap<String, WebhookConfig>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            bpf: BpfConfig {
                object_path: "./dist/scanner-ebpf.so".to_string(),
            },
            metrics: MetricsConfig {
                bind_addr: "0.0.0.0:9898".to_string(),
            },
            intel: IntelConfig {
                kev_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".to_string(),
                epss_url: "https://api.first.org/data/v1/epss".to_string(),
                refresh_interval_secs: 21_600,
            },
            risk: RiskConfig {
                minimum_cvss: 7.0,
                minimum_epss: 0.40,
            },
            runtime: RuntimeConfig {
                node_name: "unknown".to_string(),
                sbom_dir: "/var/lib/scanner/sboms".to_string(),
                seccomp_output_dir: "/var/lib/scanner/seccomp".to_string(),
            },
            remediator: RemediatorConfig {
                enabled: true,
                address: "localhost:50051".to_string(),
                timeout_secs: 30,
                max_retries: 3,
                enforce_critical: true,
                enforce_high: false,
                auto_seccomp: true,
                auto_quarantine: false,
            },
            webhook: WebhookConfig::default(),
            export: ExportConfig {
                enabled: true,
                format: "json".to_string(),
                output_path: "/var/lib/scanner/findings".to_string(),
                rotate_interval_secs: 3600,
                compress: true,
                endpoints: HashMap::new(),
            },
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, config::ConfigError> {
        let cfg: Self = config::Config::builder()
            .set_default("bpf.object_path", Self::default().bpf.object_path)?
            .set_default("metrics.bind_addr", Self::default().metrics.bind_addr)?
            .set_default("intel.kev_url", Self::default().intel.kev_url)?
            .set_default("intel.epss_url", Self::default().intel.epss_url)?
            .set_default(
                "intel.refresh_interval_secs",
                Self::default().intel.refresh_interval_secs,
            )?
            .set_default("risk.minimum_cvss", Self::default().risk.minimum_cvss)?
            .set_default("risk.minimum_epss", Self::default().risk.minimum_epss)?
            .set_default("runtime.node_name", Self::default().runtime.node_name)?
            .set_default("runtime.sbom_dir", Self::default().runtime.sbom_dir)?
            .set_default(
                "runtime.seccomp_output_dir",
                Self::default().runtime.seccomp_output_dir,
            )?
            .set_default("remediator.enabled", Self::default().remediator.enabled)?
            .set_default("remediator.address", Self::default().remediator.address)?
            .set_default(
                "remediator.timeout_secs",
                Self::default().remediator.timeout_secs,
            )?
            .set_default(
                "remediator.max_retries",
                Self::default().remediator.max_retries,
            )?
            .set_default(
                "remediator.enforce_critical",
                Self::default().remediator.enforce_critical,
            )?
            .set_default(
                "remediator.enforce_high",
                Self::default().remediator.enforce_high,
            )?
            .set_default(
                "remediator.auto_seccomp",
                Self::default().remediator.auto_seccomp,
            )?
            .set_default(
                "remediator.auto_quarantine",
                Self::default().remediator.auto_quarantine,
            )?
            .set_default("export.enabled", Self::default().export.enabled)?
            .set_default("export.format", Self::default().export.format)?
            .set_default("export.output_path", Self::default().export.output_path)?
            .set_default(
                "export.rotate_interval_secs",
                Self::default().export.rotate_interval_secs,
            )?
            .set_default("export.compress", Self::default().export.compress)?
            .add_source(config::Environment::with_prefix("SCANNER").separator("__"))
            .build()?
            .try_deserialize()?;

        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), config::ConfigError> {
        if self.risk.minimum_cvss < 0.0 || self.risk.minimum_cvss > 10.0 {
            return Err(config::ConfigError::Message(
                "SCANNER__RISK__MINIMUM_CVSS must be between 0.0 and 10.0".to_string(),
            ));
        }

        if self.risk.minimum_epss < 0.0 || self.risk.minimum_epss > 1.0 {
            return Err(config::ConfigError::Message(
                "SCANNER__RISK__MINIMUM_EPSS must be between 0.0 and 1.0".to_string(),
            ));
        }

        if self.metrics.bind_addr.parse::<std::net::SocketAddr>().is_err() {
            return Err(config::ConfigError::Message(
                "SCANNER__METRICS__BIND_ADDR must be a valid socket address (e.g. 0.0.0.0:9898)".to_string(),
            ));
        }

        #[cfg(all(feature = "ebpf", target_os = "linux"))]
        {
            if !std::path::Path::new(&self.bpf.object_path).exists() {
                return Err(config::ConfigError::Message(
                    format!("SCANNER__BPF__OBJECT_PATH does not exist: {}", self.bpf.object_path),
                ));
            }
        }

        Ok(())
    }
}

