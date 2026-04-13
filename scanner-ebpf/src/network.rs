/// Network Intelligence Tracking
/// Monitors connections, data transfers, and threat IPs
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
    },
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

/// Network activity per process
#[repr(C)]
#[derive(Clone, Copy)]
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

/// Process network stats: PID -> NetworkActivity
#[map(name = "PROCESS_NETWORK")]
static mut PROCESS_NETWORK: HashMap<u32, NetworkActivity> = HashMap::with_max_entries(10000, 0);

/// Active connections: conn_key -> ConnectionInfo
#[map(name = "CONNECTIONS")]
static mut CONNECTIONS: HashMap<u64, ConnectionInfo> = HashMap::with_max_entries(50000, 0);

/// Threat IP scores: IP -> threat_score
#[map(name = "THREAT_IPS")]
static mut THREAT_IPS: HashMap<u32, u32> = HashMap::with_max_entries(100000, 0);

/// Suspicious connections count
#[map(name = "SUSPICIOUS_CONNS")]
static mut SUSPICIOUS_CONNS: HashMap<u64, u32> = HashMap::with_max_entries(10000, 0);

/// Connection info
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectionInfo {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub state: u8,
    pub created_ns: u64,
}

// Connection states
pub const CONN_STATE_NEW: u8 = 0;
pub const CONN_STATE_ESTABLISHED: u8 = 1;
pub const CONN_STATE_CLOSING: u8 = 2;

/// Generate connection key
#[inline]
pub fn conn_key(saddr: u32, sport: u16, daddr: u32, dport: u16) -> u64 {
    ((saddr as u64) << 48) | ((sport as u64) << 32) | ((daddr as u64) << 16) | (dport as u64)
}

/// Track TCP connection establishment
pub unsafe fn track_tcp_connect(
    pid: u32,
    saddr: u32,
    sport: u16,
    daddr: u32,
    dport: u16,
    protocol: u8,
) {
    let key = conn_key(saddr, sport, daddr, dport);
    let key_ptr = &key;

    let conn = ConnectionInfo {
        saddr,
        daddr,
        sport,
        dport,
        state: CONN_STATE_ESTABLISHED,
        created_ns: bpf_ktime_get_ns(),
    };
    let conn_ptr = &conn;
    let _ = CONNECTIONS.insert(key_ptr, conn_ptr, 0);

    // Initialize or update process network activity
    let pid_ptr = &pid;
    if CONNECTIONS.get_ptr(key_ptr).is_none() {
        let activity = NetworkActivity {
            pid,
            saddr,
            daddr,
            sport,
            dport,
            bytes_sent: 0,
            bytes_recv: 0,
            first_seen_ns: bpf_ktime_get_ns(),
            last_activity_ns: bpf_ktime_get_ns(),
            protocol,
        };
        let activity_ptr = &activity;
        let _ = PROCESS_NETWORK.insert(pid_ptr, activity_ptr, 0);
    }
}

/// Update data transfer stats
pub unsafe fn update_data_transfer(pid: u32, bytes: u64, is_send: bool) {
    let pid_ptr = &pid;
    if let Some(ptr) = PROCESS_NETWORK.get_ptr_mut(pid_ptr) {
        (*ptr).last_activity_ns = bpf_ktime_get_ns();
        if is_send {
            (*ptr).bytes_sent += bytes;
        } else {
            (*ptr).bytes_recv += bytes;
        }
    }
}

/// Check for data exfiltration patterns
#[inline]
pub unsafe fn check_exfiltration(pid: u32) -> bool {
    let pid_ptr = &pid;
    if let Some(ptr) = PROCESS_NETWORK.get_ptr(pid_ptr) {
        let activity = *ptr;
        let total_sent = activity.bytes_sent;
        let total_recv = activity.bytes_recv;

        // High outbound ratio (>10:1) might indicate exfiltration
        if total_recv > 0 && total_sent / total_recv > 10 && total_sent > 10_000_000 {
            return true;
        }

        // Large outbound transfer (>100MB)
        if total_sent > 100_000_000 {
            return true;
        }
    }
    false
}

/// Check if IP is in threat intelligence
#[inline]
pub unsafe fn is_threat_ip(ip: u32) -> bool {
    let ip_ptr = &ip;
    THREAT_IPS.get_ptr(ip_ptr).is_some()
}

/// Mark connection as suspicious
pub unsafe fn mark_suspicious(saddr: u32, sport: u16, daddr: u32, dport: u16) {
    let key = conn_key(saddr, sport, daddr, dport);
    let key_ptr = &key;

    let count = if let Some(ptr) = SUSPICIOUS_CONNS.get_ptr_mut(key_ptr) {
        *ptr + 1
    } else {
        1
    };

    let count_ptr = &count;
    let _ = SUSPICIOUS_CONNS.insert(key_ptr, count_ptr, 0);
}
