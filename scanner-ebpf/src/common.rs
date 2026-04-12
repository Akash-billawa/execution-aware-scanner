use crate::events::EventType;
use crate::maps::*;
/// Common utilities and helpers for eBPF programs
use aya_ebpf::helpers::bpf_ktime_get_ns;

/// Make a composite key from pid and event type
#[inline]
pub fn make_key(pid: u32, event_type: u32) -> u64 {
    ((pid as u64) << 32) | (event_type as u64)
}

/// Check if an event is rate limited
#[inline]
pub unsafe fn is_rate_limited(key: u64) -> bool {
    let now = bpf_ktime_get_ns();

    if let Some(last_time) = RATE_LIMIT.get(&key) {
        if now - *last_time < RATE_LIMIT_NS {
            return true; // Rate limited
        }
    }

    // Update timestamp
    let _ = RATE_LIMIT.insert(&key, &now, 0);
    false
}

/// XDP action codes
pub const XDP_ABORTED: u32 = 0;
pub const XDP_DROP: u32 = 1;
pub const XDP_PASS: u32 = 2;
pub const XDP_TX: u32 = 3;
pub const XDP_REDIRECT: u32 = 4;

/// Check if IP is private (RFC1918)
#[inline]
pub fn is_private_ip(ip: u32) -> bool {
    let octet0 = (ip >> 24) as u8;
    let octet1 = ((ip >> 16) & 0xFF) as u8;

    // 10.0.0.0/8
    if octet0 == 10 {
        return true;
    }

    // 172.16.0.0/12
    if octet0 == 172 && octet1 >= 16 && octet1 <= 31 {
        return true;
    }

    // 192.168.0.0/16
    if octet0 == 192 && octet1 == 168 {
        return true;
    }

    // 127.0.0.0/8 (loopback)
    if octet0 == 127 {
        return true;
    }

    false
}
