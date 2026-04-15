/// Network Intelligence Tracking
/// Production-grade eBPF with verifier-safe patterns
use aya_ebpf::{helpers::bpf_ktime_get_ns, macros::map, maps::HashMap};

/// Network activity per process
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NetworkActivity {
    pub pid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub first_seen_ns: u64,
    pub last_activity_ns: u64,
    pub protocol: u8,
}

/// Connection info
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ConnectionInfo {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub state: u8,
    pub created_ns: u64,
}

/// Process network stats: PID -> NetworkActivity
/// Verifier-safe: immutable static with explicit bounds
#[map(name = "PROCESS_NETWORK")]
static PROCESS_NETWORK: HashMap<u32, NetworkActivity> = HashMap::with_max_entries(10000, 0);

/// Active connections: conn_key -> ConnectionInfo
#[map(name = "CONNECTIONS")]
static CONNECTIONS: HashMap<u64, ConnectionInfo> = HashMap::with_max_entries(50000, 0);

/// Threat IP scores: IP -> threat_score
#[map(name = "THREAT_IPS")]
static THREAT_IPS: HashMap<u32, u32> = HashMap::with_max_entries(100000, 0);

/// Suspicious connections count
#[map(name = "SUSPICIOUS_CONNS")]
static SUSPICIOUS_CONNS: HashMap<u64, u32> = HashMap::with_max_entries(10000, 0);

/// Connection states
pub const CONN_STATE_NEW: u8 = 0;
pub const CONN_STATE_ESTABLISHED: u8 = 1;
pub const CONN_STATE_CLOSING: u8 = 2;

/// Generate connection key using XOR-shift for better distribution
/// SAFETY: This is a pure function, no side effects
#[inline(always)]
pub fn conn_key(saddr: u32, sport: u16, daddr: u32, dport: u16) -> u64 {
    // Use a hash that preserves some structure while avoiding collisions
    let saddr64 = (saddr as u64) << 32;
    let daddr64 = (daddr as u64) << 32;
    let sport64 = (sport as u64) << 16;
    let dport64 = dport as u64;

    saddr64 ^ sport64 ^ daddr64 ^ dport64
}

/// Track TCP connection establishment
/// SAFETY: All map operations are verified by the eBPF verifier
pub fn track_tcp_connect(pid: u32, saddr: u32, sport: u16, daddr: u32, dport: u16, protocol: u8) {
    let key = conn_key(saddr, sport, daddr, dport);
    let now = unsafe { bpf_ktime_get_ns() };

    let conn = ConnectionInfo {
        saddr,
        daddr,
        sport,
        dport,
        state: CONN_STATE_ESTABLISHED,
        created_ns: now,
    };

    // SAFETY: Verified-safe map insert
    // Ignore result - connection tracking is best-effort
    let _ = unsafe { CONNECTIONS.insert(&key, &conn, 0) };

    // Initialize process network activity
    let activity = NetworkActivity {
        pid,
        saddr,
        daddr,
        sport,
        dport,
        bytes_sent: 0,
        bytes_recv: 0,
        first_seen_ns: now,
        last_activity_ns: now,
        protocol,
    };

    // SAFETY: Verified-safe map insert
    let _ = unsafe { PROCESS_NETWORK.insert(&pid, &activity, 0) };
}

/// Update data transfer stats
/// SAFETY: Uses atomic map operations verified by the eBPF verifier
pub fn update_data_transfer(pid: u32, bytes: u64, is_send: bool) {
    // SAFETY: Map lookup and update are verified-safe
    if let Some(mut activity) = unsafe { PROCESS_NETWORK.get(&pid) }.copied() {
        activity.last_activity_ns = unsafe { bpf_ktime_get_ns() };
        if is_send {
            activity.bytes_sent = activity.bytes_sent.saturating_add(bytes);
        } else {
            activity.bytes_recv = activity.bytes_recv.saturating_add(bytes);
        }
        // SAFETY: Verified-safe map update
        let _ = unsafe { PROCESS_NETWORK.insert(&pid, &activity, 0) };
    }
}

/// Check for data exfiltration patterns
/// Uses safe arithmetic operations to prevent overflow
#[inline(always)]
pub fn check_exfiltration(pid: u32) -> bool {
    // SAFETY: Verified-safe map lookup
    if let Some(activity) = unsafe { PROCESS_NETWORK.get(&pid) } {
        let total_sent = activity.bytes_sent;
        let total_recv = activity.bytes_recv;

        // Use saturating operations to prevent arithmetic overflow
        const EXFIL_RATIO_THRESHOLD: u64 = 10;
        const EXFIL_BYTES_THRESHOLD: u64 = 10_000_000;
        const LARGE_TRANSFER_THRESHOLD: u64 = 100_000_000;

        // Check for high outbound ratio (>10:1)
        if total_recv > 0 {
            let ratio = total_sent.saturating_div(total_recv);
            if ratio > EXFIL_RATIO_THRESHOLD && total_sent > EXFIL_BYTES_THRESHOLD {
                return true;
            }
        }

        // Check for large outbound transfer
        if total_sent > LARGE_TRANSFER_THRESHOLD {
            return true;
        }
    }

    false
}

/// Check if IP is in threat intelligence
/// SAFETY: Verified-safe map lookup
#[inline(always)]
pub fn is_threat_ip(ip: u32) -> bool {
    // SAFETY: Verified-safe map lookup
    unsafe { THREAT_IPS.get(&ip) }.is_some()
}

/// Mark connection as suspicious
/// SAFETY: All map operations are verified by the eBPF verifier
pub fn mark_suspicious(saddr: u32, sport: u16, daddr: u32, dport: u16) {
    let key = conn_key(saddr, sport, daddr, dport);

    // SAFETY: Verified-safe map lookup and update
    let count = unsafe { SUSPICIOUS_CONNS.get(&key) }
        .map(|c| c.saturating_add(1))
        .unwrap_or(1);

    // SAFETY: Verified-safe map insert
    let _ = unsafe { SUSPICIOUS_CONNS.insert(&key, &count, 0) };
}
