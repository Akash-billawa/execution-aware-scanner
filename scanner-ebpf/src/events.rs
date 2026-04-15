//! Unified Security Event Schema
//! All eBPF events normalize to this single structure
//! Simplifies streaming, storage, and SIEM integration
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::map,
    maps::{HashMap, RingBuf},
};

/// Unified security event - single schema for all signals
/// Size: 168 bytes (fits in most ring buffers)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecurityEvent {
    /// Timestamp in nanoseconds (monotonic)
    pub ts: u64,

    /// Event type discriminator
    pub kind: EventKind,

    /// Process ID
    pub pid: u32,

    /// Thread group ID
    pub tgid: u32,

    /// User ID
    pub uid: u32,

    /// Group ID
    pub gid: u32,

    /// Cgroup ID (container context)
    pub cgroup_id: u64,

    /// Signal confidence (0-100)
    /// Kernel-side computed hint to reduce user-space work
    pub confidence: u8,

    /// Event-specific data
    pub data: EventData,

    /// Command name (first 16 bytes)
    pub comm: [u8; 16],
}

impl Default for SecurityEvent {
    fn default() -> Self {
        Self {
            ts: 0,
            kind: EventKind::Exec,
            pid: 0,
            tgid: 0,
            uid: 0,
            gid: 0,
            cgroup_id: 0,
            confidence: 50,
            data: EventData { raw: [0; 128] },
            comm: [0; 16],
        }
    }
}

/// Event type discriminator
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum EventKind {
    /// Process execution
    Exec = 0,
    /// File open/access
    File = 1,
    /// Memory map (library load)
    Mmap = 2,
    /// Network connection
    Connect = 3,
    /// Network data transfer
    NetTransfer = 4,
    /// DNS resolution
    Dns = 5,
    /// Process exit
    Exit = 6,
    /// Suspicious activity
    Suspicious = 7,
}

/// Event-specific data (128 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub union EventData {
    /// Exec event data
    pub exec: ExecData,
    /// File event data
    pub file: FileData,
    /// Network event data
    pub net: NetData,
    /// Generic data
    pub raw: [u8; 128],
}

impl Default for EventData {
    fn default() -> Self {
        Self { raw: [0; 128] }
    }
}

/// Exec event specific data
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecData {
    /// Parent PID
    pub ppid: u32,
    /// Is setuid binary
    pub is_setuid: u8,
    /// Padding
    pub _pad: [u8; 3],
    /// Command arguments (truncated)
    pub args: [u8; 120],
}

impl Default for ExecData {
    fn default() -> Self {
        Self {
            ppid: 0,
            is_setuid: 0,
            _pad: [0; 3],
            args: [0; 120],
        }
    }
}

/// File event specific data
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileData {
    /// File path (truncated)
    pub path: [u8; 96],
    /// Open flags
    pub flags: u32,
    /// Is sensitive path (calculated kernel-side)
    pub is_sensitive: u8,
    /// Padding
    pub _pad: [u8; 27],
}

impl Default for FileData {
    fn default() -> Self {
        Self {
            path: [0; 96],
            flags: 0,
            is_sensitive: 0,
            _pad: [0; 27],
        }
    }
}

/// Network event specific data
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetData {
    /// Source address (IPv4 or IPv6 first 4 bytes)
    pub saddr: u32,
    /// Destination address
    pub daddr: u32,
    /// Source port
    pub sport: u16,
    /// Destination port
    pub dport: u16,
    /// Bytes transferred
    pub bytes: u64,
    /// Protocol (TCP=6, UDP=17)
    pub protocol: u8,
    /// Is external connection
    pub is_external: u8,
    /// Is suspicious port
    pub is_suspicious_port: u8,
    /// Padding
    pub _pad: [u8; 101],
}

impl Default for NetData {
    fn default() -> Self {
        Self {
            saddr: 0,
            daddr: 0,
            sport: 0,
            dport: 0,
            bytes: 0,
            protocol: 0,
            is_external: 0,
            is_suspicious_port: 0,
            _pad: [0; 101],
        }
    }
}

impl EventKind {
    /// Convert to string for logging
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::Exec => "EXEC",
            EventKind::File => "FILE",
            EventKind::Mmap => "MMAP",
            EventKind::Connect => "CONNECT",
            EventKind::NetTransfer => "NET_TRANSFER",
            EventKind::Dns => "DNS",
            EventKind::Exit => "EXIT",
            EventKind::Suspicious => "SUSPICIOUS",
        }
    }
}

/// Ring buffer for unified security events (4096 * 168 bytes = ~688KB)
#[map(name = "SECURITY_EVENTS")]
pub static SECURITY_EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 168, 0);

/// Event counter per kind for rate tracking
#[map(name = "EVENT_COUNT_BY_KIND")]
pub static EVENT_COUNT_BY_KIND: HashMap<u8, u64> = HashMap::with_max_entries(8, 0);

/// Dropped events by kind
#[map(name = "DROPPED_BY_KIND")]
pub static DROPPED_BY_KIND: HashMap<u8, u64> = HashMap::with_max_entries(8, 0);

/// Create a base security event with all context pre-filled
/// This is the key function - attaches ALL context at kernel source
#[inline(always)]
pub fn create_base_event(kind: EventKind) -> SecurityEvent {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Get command name
    let mut comm = [0u8; 16];
    if let Ok(name) = unsafe { bpf_get_current_comm() } {
        let len = name.len().min(16);
        comm[..len].copy_from_slice(&name[..len]);
    }

    SecurityEvent {
        ts: unsafe { bpf_ktime_get_ns() },
        kind,
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        cgroup_id,
        confidence: 50, // Default confidence
        data: EventData { raw: [0; 128] },
        comm,
    }
}

/// Emit a security event to the ring buffer
/// Updates counters and tracks drops
#[inline(always)]
pub fn emit_event(event: SecurityEvent) {
    // Reserve space in ring buffer
    if let Some(entry) = unsafe { SECURITY_EVENTS.reserve(0) } {
        entry.write(event);
        unsafe { SECURITY_EVENTS.submit(entry, 0) };

        // Increment event counter by kind
        let kind_u8 = event.kind as u8;
        let count = unsafe { EVENT_COUNT_BY_KIND.get(&kind_u8) }
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        let _ = unsafe { EVENT_COUNT_BY_KIND.insert(&kind_u8, &count, 0) };
    } else {
        // Track dropped event
        let kind_u8 = event.kind as u8;
        let dropped = unsafe { DROPPED_BY_KIND.get(&kind_u8) }
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        let _ = unsafe { DROPPED_BY_KIND.insert(&kind_u8, &dropped, 0) };
    }
}

/// Calculate signal confidence based on multiple factors
/// This is the key value-add - kernel-side confidence scoring
#[inline(always)]
pub fn calculate_confidence(
    kind: EventKind,
    has_library: bool,
    has_network: bool,
    is_sensitive: bool,
) -> u8 {
    let mut confidence: u8 = 50; // Base confidence

    // Boost for library + network combo (attack path indicator)
    if has_library && has_network {
        confidence = confidence.saturating_add(30);
    }

    // Boost for sensitive paths
    if is_sensitive {
        confidence = confidence.saturating_add(20);
    }

    // Event-specific adjustments
    match kind {
        EventKind::Connect => {
            if has_network {
                confidence = confidence.saturating_add(10);
            }
        }
        EventKind::Exec => {
            // Setuid binaries are always high confidence
            confidence = confidence.saturating_add(10);
        }
        EventKind::Suspicious => {
            confidence = 90; // Suspicious events start high
        }
        _ => {}
    }

    // Cap at 100
    confidence.min(100)
}

/// Helper to check if path is sensitive (kernel-side)
#[inline(always)]
pub fn is_sensitive_path(path: &[u8]) -> bool {
    // Check for sensitive paths without allocation
    const SENSITIVE: &[&[u8]] = &[
        b"/etc/passwd",
        b"/etc/shadow",
        b"/etc/ssh",
        b"/.dockerenv",
        b"/.kube",
        b"/var/run/secrets",
    ];

    for sensitive in SENSITIVE {
        if path.starts_with(sensitive) {
            return true;
        }
    }
    false
}

/// Helper to check if port is suspicious
#[inline(always)]
pub fn is_suspicious_port(port: u16) -> bool {
    // Common C2 / malware ports
    matches!(port, 4444 | 5555 | 6666 | 8888 | 9999 | 31337)
}

/// Helper to check if IP is external (not private)
#[inline(always)]
pub fn is_external_ip(ip: u32) -> bool {
    // Convert to big-endian octets
    let octets = ip.to_be_bytes();

    // Check private ranges
    // 10.0.0.0/8
    if octets[0] == 10 {
        return false;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return false;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return false;
    }
    // 127.0.0.0/8 (loopback)
    if octets[0] == 127 {
        return false;
    }

    true
}
