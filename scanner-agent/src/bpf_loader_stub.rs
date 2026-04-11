// Stub implementation for non-eBPF builds
use crate::error::ScannerError;

pub struct BpfLoader;

impl BpfLoader {
    pub fn new(_path: &str) -> Result<Self, ScannerError> {
        Err(ScannerError::Bpf("eBPF not available on this platform".to_string()))
    }
}

pub type EventConsumer = ();
