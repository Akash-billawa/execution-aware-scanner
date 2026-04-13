/// Tracepoint Programs - Syscall Monitoring
/// Tracks process execution, file operations, and memory mappings
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

/// Process execution entry
#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn trace_enter_execve(ctx: TracePointContext) -> u32 {
    unsafe {
        try_execve(&ctx);
    }
    0
}

/// Process execution return
#[tracepoint(category = "syscalls", name = "sys_exit_execve")]
pub fn trace_exit_execve(ctx: TracePointContext) -> u32 {
    unsafe {
        try_execve_return(&ctx);
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

    // Get command name
    let command = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => [0u8; 16],
    };

    // Log process execution
    info!(ctx, "EXEC: pid={}", pid);
    0
}

unsafe fn try_execve_return(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    info!(ctx, "EXEC_RET: pid={}", pid);
    0
}

unsafe fn try_openat(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    info!(ctx, "OPEN: pid={}", pid);
    0
}

unsafe fn try_mmap(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    info!(ctx, "MMAP: pid={}", pid);
    0
}

unsafe fn try_mprotect(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    info!(ctx, "MPROTECT: pid={}", pid);
    0
}
