// BPF Map definitions for advanced eBPF scanner

use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LruHashMap, PerfEventArray, RingBuf};

use crate::events::*;

// ═══════════════════════════════════════════════════════════════════════════
// EVENT RING BUFFERS (Userspace Communication)
// ═══════════════════════════════════════════════════════════════════════════

/// Process execution events (1MB)
#[map(name = "EXEC_EVENTS")]
pub static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// File operation events (1MB)
#[map(name = "FILE_EVENTS")]
pub static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// Network events (1MB)
#[map(name = "NET_EVENTS")]
pub static NET_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// Security alert events (512KB)
#[map(name = "SECURITY_EVENTS")]
pub static SECURITY_EVENTS: RingBuf = RingBuf::with_byte_size(512 << 10, 0);

// ═══════════════════════════════════════════════════════════════════════════
// CGROUP POLICIES (Allow/Deny Lists)
// ═══════════════════════════════════════════════════════════════════════════

/// Allowlisted cgroups (bypass monitoring)
#[map(name = "ALLOWLIST")]
pub static mut ALLOWLIST: HashMap<u64, u8> = HashMap::<u64, u8>::with_max_entries(8192, 0);

/// Denylisted cgroups (blocked)
#[map(name = "DENYLIST")]
pub static mut DENYLIST: HashMap<u64, u8> = HashMap::<u64, u8>::with_max_entries(1024, 0);

/// Seccomp-style syscall policy per cgroup
#[map(name = "CGROUP_SYSCALLS")]
pub static mut CGROUP_SYSCALLS: HashMap<u64, u64> = HashMap::<u64, u64>::with_max_entries(8192, 0);

// ═══════════════════════════════════════════════════════════════════════════
// NETWORK SECURITY
// ═══════════════════════════════════════════════════════════════════════════

/// Blocked IPs (network layer)
#[map(name = "BLOCKED_IPS")]
pub static mut BLOCKED_IPS: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(10000, 0);

/// Blocked IPs (XDP layer - high performance)
#[map(name = "XDP_BLOCKED_IPS")]
pub static mut XDP_BLOCKED_IPS: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(50000, 0);

/// Threat intelligence IPs (known malicious)
#[map(name = "THREAT_INTEL_IPS")]
pub static mut THREAT_INTEL_IPS: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(100000, 0);

/// Connection tracking (LRU for performance)
#[map(name = "CONNECTIONS")]
pub static mut CONNECTIONS: LruHashMap<u64, ConnectionEntry> =
    LruHashMap::<u64, ConnectionEntry>::with_max_entries(100000, 0);

// ═══════════════════════════════════════════════════════════════════════════
// FILE INTEGRITY & MONITORING
// ═══════════════════════════════════════════════════════════════════════════

/// File access cache (path hash → entry)
#[map(name = "FILE_CACHE")]
pub static mut FILE_CACHE: LruHashMap<u32, FileCacheEntry> =
    LruHashMap::<u32, FileCacheEntry>::with_max_entries(50000, 0);

/// Library mappings (PID → loaded libraries)
#[map(name = "LIBRARY_MAP")]
pub static mut LIBRARY_MAP: LruHashMap<u32, LibraryMapping> =
    LruHashMap::<u32, LibraryMapping>::with_max_entries(10000, 0);

// ═══════════════════════════════════════════════════════════════════════════
// STATISTICS & METRICS
// ═══════════════════════════════════════════════════════════════════════════

/// Per-cgroup statistics
#[map(name = "CGROUP_STATS")]
pub static mut CGROUP_STATS: HashMap<u64, CgroupStats> =
    HashMap::<u64, CgroupStats>::with_max_entries(10000, 0);

/// Process parent tracking (PID → PPID)
#[map(name = "PROCESS_PARENT")]
pub static mut PROCESS_PARENT: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(100000, 0);

/// Process tree (for ancestry tracking)
#[map(name = "PROCESS_TREE")]
pub static mut PROCESS_TREE: LruHashMap<u64, [u32; 10]> =
    LruHashMap::<u64, [u32; 10]>::with_max_entries(50000, 0);

// ═══════════════════════════════════════════════════════════════════════════
// RATE LIMITING & DEDUPLICATION
// ═══════════════════════════════════════════════════════════════════════════

/// Alert rate limiting (key → last timestamp)
#[map(name = "ALERT_TIMESTAMPS")]
pub static mut ALERT_TIMESTAMPS: LruHashMap<u64, u64> =
    LruHashMap::<u64, u64>::with_max_entries(10000, 0);

/// Event deduplication cache
#[map(name = "EVENT_DEDUP")]
pub static mut EVENT_DEDUP: LruHashMap<u64, u8> = LruHashMap::<u64, u8>::with_max_entries(10000, 0);

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

pub mod consts {
    // XDP actions
    pub const XDP_ABORTED: u32 = 0;
    pub const XDP_DROP: u32 = 1;
    pub const XDP_PASS: u32 = 2;
    pub const XDP_TX: u32 = 3;
    pub const XDP_REDIRECT: u32 = 4;

    // Connection states
    pub const CONN_SYN_SENT: u8 = 0;
    pub const CONN_ESTABLISHED: u8 = 1;
    pub const CONN_CLOSING: u8 = 2;
    pub const CONN_CLOSED: u8 = 3;

    // Syscall masks
    pub const SYSCALL_EXECVE: u64 = 1 << 0;
    pub const SYSCALL_EXECVEAT: u64 = 1 << 1;
    pub const SYSCALL_OPENAT: u64 = 1 << 2;
    pub const SYSCALL_OPENAT2: u64 = 1 << 3;
    pub const SYSCALL_MMAP: u64 = 1 << 4;
    pub const SYSCALL_MPROTECT: u64 = 1 << 5;
    pub const SYSCALL_CONNECT: u64 = 1 << 6;
    pub const SYSCALL_BIND: u64 = 1 << 7;
    pub const SYSCALL_SOCKET: u64 = 1 << 8;
    pub const SYSCALL_CLONE: u64 = 1 << 9;
    pub const SYSCALL_FORK: u64 = 1 << 10;
    pub const SYSCALL_VFORK: u64 = 1 << 11;

    // Rate limits (nanoseconds)
    pub const ALERT_COOLDOWN_NS: u64 = 1_000_000_000; // 1 second
    pub const DEDUP_TTL_NS: u64 = 10_000_000_000; // 10 seconds
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/// Get or create cgroup stats
pub unsafe fn get_cgroup_stats(cgroup_id: u64) -> Option<&mut CgroupStats> {
    CGROUP_STATS.get_mut(&cgroup_id)
}

/// Initialize cgroup stats if not exists
pub unsafe fn init_cgroup_stats(cgroup_id: u64) {
    if CGROUP_STATS.get(&cgroup_id).is_none() {
        let stats = CgroupStats {
            cgroup_id,
            exec_count: 0,
            file_open_count: 0,
            mmap_count: 0,
            connect_count: 0,
            bind_count: 0,
            first_seen_ns: bpf_ktime_get_ns(),
            last_seen_ns: 0,
        };
        let _ = CGROUP_STATS.insert(&cgroup_id, &stats, 0);
    }
}

/// Check if syscall is allowed for cgroup
pub unsafe fn is_syscall_allowed(cgroup_id: u64, syscall_mask: u64) -> bool {
    if let Some(allowed) = CGROUP_SYSCALLS.get(&cgroup_id) {
        (*allowed & syscall_mask) != 0
    } else {
        true // Default allow if no policy
    }
}

/// Rate limit check
pub unsafe fn check_rate_limit(key: u64, interval_ns: u64) -> bool {
    let now = bpf_ktime_get_ns();

    if let Some(last) = ALERT_TIMESTAMPS.get(&key) {
        if now - *last < interval_ns {
            return false; // Rate limited
        }
    }

    let _ = ALERT_TIMESTAMPS.insert(&key, &now, 0);
    true
}

/// Block an IP (add to both network and XDP maps)
pub unsafe fn block_ip(ip: u32, threat_score: u32) {
    let _ = BLOCKED_IPS.insert(&ip, &1u8, 0);
    let _ = XDP_BLOCKED_IPS.insert(&ip, &1u8, 0);
    let _ = THREAT_INTEL_IPS.insert(&ip, &threat_score, 0);
}

/// Unblock an IP
pub unsafe fn unblock_ip(ip: u32) {
    let _ = BLOCKED_IPS.remove(&ip);
    let _ = XDP_BLOCKED_IPS.remove(&ip);
    let _ = THREAT_INTEL_IPS.remove(&ip);
}

/// Generate connection key
pub fn conn_key(saddr: u32, sport: u16) -> u64 {
    ((saddr as u64) << 32) | (sport as u64)
}

/// Check if IP is private
pub fn is_private_ip(ip: u32) -> bool {
    let octets = [
        ((ip >> 24) & 0xFF) as u8,
        ((ip >> 16) & 0xFF) as u8,
        ((ip >> 8) & 0xFF) as u8,
        (ip & 0xFF) as u8,
    ];

    octets[0] == 10
        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
        || (octets[0] == 192 && octets[1] == 168)
        || octets[0] == 127
}
