//! Stub implementation of tc_enforcer for non-eBPF builds

#[derive(Clone)]
pub struct TcEnforcer;

impl TcEnforcer {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Clone)]
pub struct ThreatIntelFeed;

impl ThreatIntelFeed {
    pub fn new() -> Self {
        Self
    }
}
