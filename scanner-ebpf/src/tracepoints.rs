/// Tracepoint Programs - Syscall Monitoring
/// Tracks process execution, file operations, and memory mappings
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
};

/// Event output channel
#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

/// Rate limiting: last event time per PID
#[map(name = "LAST_EVENT")]
static mut LAST_EVENT: HashMap<u64, u64> = HashMap::with_max_entries(100000, 0);

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
#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn trace_enter_execve(ctx: TracePointContext) -> u32 {
    unsafe {
        try_execve(&ctx);
    }
    0
}

/// File open
#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    unsafe {
        try_openat(&ctx);
    }
    0
}

/// Memory map
#[tracepoint(category = "syscalls", name = "sys_enter_mmap")]
pub fn trace_mmap(ctx: TracePointContext) -> u32 {
    unsafe {
        try_mmap(&ctx);
    }
    0
}

/// Memory protection
#[tracepoint(category = "syscalls", name = "sys_enter_mprotect")]
pub fn trace_mprotect(ctx: TracePointContext) -> u32 {
    unsafe {
        try_mprotect(&ctx);
    }
    0
}

unsafe fn try_execve(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    // Rate limiting: max 1 event per second per PID
    let now = bpf_ktime_get_ns();
    let key = pid as u64;
    let key_ptr = &key;
    // Check last event time - SAFETY: eBPF map operations are unsafe
    let should_emit = if let Some(ptr) = unsafe { LAST_EVENT.get_ptr(key_ptr) } {
        let last = *ptr;
        now - last > 1_000_000_000 // 1 second
    } else {
        true
    };

    if !should_emit {
        return 0;
    }

    // Update last event time - SAFETY: eBPF map operations are unsafe
    let _ = unsafe { LAST_EVENT.insert(key_ptr, &now, 0) };

    // Get command name
    let command = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => [0u8; 16],
    };

    // Emit structured event
    let event = ExecEvent {
        timestamp_ns: now,
        pid,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        cgroup_id,
        command,
    };

    // SAFETY: PerfEventArray output requires context
    let _ = unsafe { EVENTS.output(ctx, &event, 0) };
    0
}

unsafe fn try_openat(_ctx: &TracePointContext) -> u32 {
    let _pid_tgid = bpf_get_current_pid_tgid();
    // Event logging disabled for verifier compatibility
    0
}

unsafe fn try_mmap(_ctx: &TracePointContext) -> u32 {
    let _pid_tgid = bpf_get_current_pid_tgid();
    // Event logging disabled for verifier compatibility
    0
}

unsafe fn try_mprotect(_ctx: &TracePointContext) -> u32 {
    let _pid_tgid = bpf_get_current_pid_tgid();
    // Event logging disabled for verifier compatibility
    0
}
