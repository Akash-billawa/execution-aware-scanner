/// Tracepoint Programs - Syscall Monitoring
/// Production-grade eBPF with verifier-safe patterns
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};

/// Ring buffer for events (verifier-safe replacement for PerfEventArray)
#[map(name = "EVENTS")]
static EVENTS: RingBuf<ExecEvent> = RingBuf::with_max_entries(1024, 0);

/// Rate limiting: last event time per PID
/// Max 100k PIDs to prevent memory exhaustion
#[map(name = "LAST_EVENT")]
static LAST_EVENT: HashMap<u64, u64> = HashMap::with_max_entries(100000, 0);

/// Dropped events counter - critical for observability
#[map(name = "DROPPED_EVENTS")]
static DROPPED_EVENTS: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Event counter for rate tracking (key 0 = total events emitted)
#[map(name = "EVENT_COUNT")]
static EVENT_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Process execution event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub command: [u8; 16],
}

/// Process execution entry
/// Safe wrapper ensuring verifier compliance
#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn trace_enter_execve(ctx: TracePointContext) -> u32 {
    // Inline the logic to avoid fn ptr issues
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    // Rate limiting check
    let now = bpf_ktime_get_ns();
    let pid_u64 = pid as u64;

    // SAFETY: eBPF map operations require unsafe blocks
    // The verifier ensures these are safe at load time
    let should_emit = unsafe {
        match LAST_EVENT.get(&pid_u64) {
            Some(last) => now.saturating_sub(*last) > 1_000_000_000, // 1 second
            None => true,
        }
    };

    if !should_emit {
        return 0;
    }

    // Update rate limit timestamp
    // Ignore errors (map full is acceptable for rate limiting)
    let _ = unsafe { LAST_EVENT.insert(&pid_u64, &now, 0) };

    // Get command name with bounds checking
    let mut command = [0u8; 16];
    if let Ok(comm) = bpf_get_current_comm() {
        // Copy at most 16 bytes to prevent buffer overflow
        let len = comm.len().min(16);
        command[..len].copy_from_slice(&comm[..len]);
    }

    // Build event
    let event = ExecEvent {
        timestamp_ns: now,
        pid,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        cgroup_id,
        command,
    };

    // Reserve space in ring buffer with drop tracking
    // SAFETY: RingBuf::reserve is verified-safe
    if let Some(entry) = unsafe { EVENTS.reserve(0) } {
        entry.write(event);
        unsafe { EVENTS.submit(entry, 0) };

        // Increment event counter
        let key: u32 = 0;
        let count = unsafe { EVENT_COUNT.get(&key) }
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        let _ = unsafe { EVENT_COUNT.insert(&key, &count, 0) };
    } else {
        // Track dropped event
        let key: u32 = 0;
        let dropped = unsafe { DROPPED_EVENTS.get(&key) }
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        let _ = unsafe { DROPPED_EVENTS.insert(&key, &dropped, 0) };
    }

    0
}

/// File open - minimal stub for verifier compatibility
#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn trace_openat(_ctx: TracePointContext) -> u32 {
    // Stub: disabled for production to minimize overhead
    // Full implementation would track file access patterns
    0
}

/// Memory map - minimal stub for verifier compatibility
#[tracepoint(category = "syscalls", name = "sys_enter_mmap")]
pub fn trace_mmap(_ctx: TracePointContext) -> u32 {
    // Stub: disabled for production to minimize overhead
    // Full implementation would track library loading via mmap
    0
}

/// Memory protection - minimal stub for verifier compatibility
#[tracepoint(category = "syscalls", name = "sys_enter_mprotect")]
pub fn trace_mprotect(_ctx: TracePointContext) -> u32 {
    // Stub: disabled for production to minimize overhead
    0
}
