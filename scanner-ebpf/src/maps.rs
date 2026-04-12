use crate::events::SecurityEvent;
/// eBPF Maps - Ring Buffer for events, HashMaps for state
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, RingBuf};

/// Main event channel - Ring Buffer for all security events
/// Size: 1MB buffer
#[map(name = "EVENTS")]
pub static mut EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Allowlisted cgroups - skip monitoring
#[map(name = "ALLOWLIST")]
pub static mut ALLOWLIST: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

/// Denylisted cgroups - block operations
#[map(name = "DENYLIST")]
pub static mut DENYLIST: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

/// Blocked IPs (network security)
#[map(name = "BLOCKED_IPS")]
pub static mut BLOCKED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(10000, 0);

/// Threat intelligence IPs with scores
#[map(name = "THREAT_INTEL")]
pub static mut THREAT_INTEL: HashMap<u32, u32> = HashMap::with_max_entries(50000, 0);

/// Process parent tracking (PID -> PPID)
#[map(name = "PROCESS_PARENT")]
pub static mut PROCESS_PARENT: HashMap<u32, u32> = HashMap::with_max_entries(100000, 0);

/// Rate limiting: last event timestamp per key
#[map(name = "RATE_LIMIT")]
pub static mut RATE_LIMIT: HashMap<u64, u64> = HashMap::with_max_entries(10000, 0);

/// Constants
pub const RATE_LIMIT_NS: u64 = 1_000_000_000; // 1 second cooldown
