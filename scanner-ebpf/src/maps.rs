// BPF Map definitions for the eBPF scanner

use aya_bpf::macros::map;
use aya_bpf::maps::{HashMap, LruHashMap, RingBuf};

use crate::events::*;

// Event output ring buffers (1MB each)
#[map(name = "EXEC_EVENTS")]
pub static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map(name = "FILE_EVENTS")]
pub static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map(name = "NET_EVENTS")]
pub static NET_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map(name = "SECURITY_EVENTS")]
pub static SECURITY_EVENTS: RingBuf = RingBuf::with_byte_size(512 << 10, 0);

// Cgroup allowlist/denylist
#[map(name = "ALLOWLIST")]
pub static mut ALLOWLIST: HashMap<u64, u8> = HashMap::<u64, u8>::with_max_entries(8192, 0);

#[map(name = "DENYLIST")]
pub static mut DENYLIST: HashMap<u64, u8> = HashMap::<u64, u8>::with_max_entries(1024, 0);

// IP-based blocking for network enforcement
#[map(name = "BLOCKED_IPS")]
pub static mut BLOCKED_IPS: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(10000, 0);

#[map(name = "XDP_BLOCKED_IPS")]
pub static mut XDP_BLOCKED_IPS: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(50000, 0);

// Connection tracking
#[map(name = "CONNECTIONS")]
pub static mut CONNECTIONS: LruHashMap<u64, ConnectionEntry> =
    LruHashMap::<u64, ConnectionEntry>::with_max_entries(100000, 0);

// File integrity monitoring cache
#[map(name = "FILE_CACHE")]
pub static mut FILE_CACHE: LruHashMap<u32, FileCacheEntry> =
    LruHashMap::<u32, FileCacheEntry>::with_max_entries(50000, 0);

// Cgroup statistics
#[map(name = "CGROUP_STATS")]
pub static mut CGROUP_STATS: HashMap<u64, CgroupStats> =
    HashMap::<u64, CgroupStats>::with_max_entries(10000, 0);

// Syscall allowlist per cgroup (for seccomp-style enforcement)
#[map(name = "CGROUP_SYSCALLS")]
pub static mut CGROUP_SYSCALLS: HashMap<u64, u64> = HashMap::<u64, u64>::with_max_entries(8192, 0);

// Process tracking
#[map(name = "PROCESS_PARENT")]
pub static mut PROCESS_PARENT: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(100000, 0);

// DNS cache for domain blocking
#[map(name = "DNS_CACHE")]
pub static mut DNS_CACHE: LruHashMap<u32, [u8; 256]> =
    LruHashMap::<u32, [u8; 256]>::with_max_entries(10000, 0);

// Alert rate limiting
#[map(name = "ALERT_TIMESTAMPS")]
pub static mut ALERT_TIMESTAMPS: LruHashMap<u64, u64> =
    LruHashMap::<u64, u64>::with_max_entries(10000, 0);

// Constants for BPF programs
pub mod consts {
    // XDP actions
    pub const XDP_ABORTED: u32 = 0;
    pub const XDP_DROP: u32 = 1;
    pub const XDP_PASS: u32 = 2;
    pub const XDP_TX: u32 = 3;
    pub const XDP_REDIRECT: u32 = 4;

    // Syscall bitmasks for CGROUP_SYSCALLS map
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

    // Connection states
    pub const CONN_SYN_SENT: u8 = 0;
    pub const CONN_ESTABLISHED: u8 = 1;
    pub const CONN_CLOSING: u8 = 2;
    pub const CONN_CLOSED: u8 = 3;
}

// Map helper functions
pub unsafe fn get_cgroup_stats(cgroup_id: u64) -> Option<&mut CgroupStats> {
    CGROUP_STATS.get_mut(&cgroup_id)
}

pub unsafe fn init_cgroup_stats(cgroup_id: u64) {
    if CGROUP_STATS.get(&cgroup_id).is_none() {
        let stats = CgroupStats {
            cgroup_id,
            exec_count: 0,
            file_open_count: 0,
            mmap_count: 0,
            connect_count: 0,
            bind_count: 0,
            first_seen_ns: aya_bpf::helpers::bpf_ktime_get_ns(),
            last_seen_ns: 0,
        };
        let _ = CGROUP_STATS.insert(&cgroup_id, &stats, 0);
    }
}

pub unsafe fn is_syscall_allowed(cgroup_id: u64, syscall_mask: u64) -> bool {
    if let Some(allowed) = CGROUP_SYSCALLS.get(&cgroup_id) {
        (allowed & syscall_mask) != 0
    } else {
        true // Default allow if no policy set
    }
}

pub unsafe fn check_rate_limit(key: u64, interval_ns: u64) -> bool {
    let now = aya_bpf::helpers::bpf_ktime_get_ns();

    if let Some(last) = ALERT_TIMESTAMPS.get(&key) {
        if now - *last < interval_ns {
            return false; // Rate limited
        }
    }

    let _ = ALERT_TIMESTAMPS.insert(&key, &now, 0);
    true
}

pub unsafe fn block_ip(ip: u32) {
    let _ = BLOCKED_IPS.insert(&ip, &1u8, 0);
    let _ = XDP_BLOCKED_IPS.insert(&ip, &1u8, 0);
}

pub unsafe fn unblock_ip(ip: u32) {
    let _ = BLOCKED_IPS.remove(&ip);
    let _ = XDP_BLOCKED_IPS.remove(&ip);
}
