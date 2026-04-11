use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("configuration error: {0}")]
    Config(#[from] config::ConfigError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("kubernetes error: {0}")]
    Kube(#[from] kube::Error),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("ebpf error: {0}")]
    Bpf(String),
}
