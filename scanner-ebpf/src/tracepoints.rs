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

use crate::common::*;
use crate::events::*;
use crate::maps::*;

/// Process execution entry
#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn trace_enter_execve(ctx: TracePointContext) -> u32 {
    unsafe { try_execve_entry(&ctx) };
    0
}

/// Process execution return
#[tracepoint(category = "syscalls", name = "sys_exit_execve")]
pub fn trace_exit_execve(ctx: TracePointContext) -> u32 {
    unsafe { try_execve_exit(&ctx) };
    0
}

/// File open
#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn trace_enter_openat(ctx: TracePointContext) -> u32 {
    unsafe { try_openat(&ctx) };
    0
}

/// File open return
#[tracepoint(category = "syscalls", name = "sys_exit_openat")]
pub fn trace_exit_openat(ctx: TracePointContext) -> u32 {
    0
}

/// Memory map
#[tracepoint(category = "syscalls", name = "sys_enter_mmap")]
pub fn trace_enter_mmap(ctx: TracePointContext) -> u32 {
    unsafe { try_mmap(&ctx) };
    0
}

/// Memory protection
#[tracepoint(category = "syscalls", name = "sys_enter_mprotect")]
pub fn trace_enter_mprotect(ctx: TracePointContext) -> u32 {
    unsafe { try_mprotect(&ctx) };
    0
}

unsafe fn try_execve_entry(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;

    // Skip if allowlisted
    if unsafe { ALLOWLIST.get(&cgroup_id) }.is_some() {
        return 0;
    }

    // Rate limiting
    let key = make_key(pid, EventType::ProcessExec as u32);
    if is_rate_limited(key) {
        return 0;
    }

    // Get command name
    let command = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => [0u8; 16],
    };

    let exec_data = ExecData {
        ppid: tgid,
        command,
    };

    let event = SecurityEvent::new(EventType::ProcessExec, pid, tgid, uid, gid, cgroup_id)
        .with_exec_data(&exec_data);

    // Submit event
    if let Some(mut entry) = unsafe { EVENTS.reserve::<SecurityEvent>(0) } {
        entry.write(event);
        entry.submit(0);
    }

    // Track parent
    let _ = unsafe { PROCESS_PARENT.insert(&pid, &tgid, 0) };

    info!(ctx, "EXEC: pid={} comm={}", pid, pid);
    0
}

unsafe fn try_execve_exit(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let cgroup_id = bpf_get_current_cgroup_id();

    if unsafe { ALLOWLIST.get(&cgroup_id) }.is_some() {
        return 0;
    }

    info!(ctx, "EXEC_RET: pid={}", pid);
    0
}

unsafe fn try_openat(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    if unsafe { ALLOWLIST.get(&cgroup_id) }.is_some() {
        return 0;
    }

    let file_data = FileData {
        fd: -1,
        flags: 0,
        path: [0u8; 240],
    };

    let event = SecurityEvent::new(
        EventType::FileOpen,
        pid,
        (pid_tgid >> 32) as u32,
        uid_gid as u32,
        (uid_gid >> 32) as u32,
        cgroup_id,
    )
    .with_file_data(&file_data);

    if let Some(mut entry) = unsafe { EVENTS.reserve::<SecurityEvent>(0) } {
        entry.write(event);
        entry.submit(0);
    }

    info!(ctx, "OPEN: pid={}", pid);
    0
}

unsafe fn try_mmap(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    if unsafe { ALLOWLIST.get(&cgroup_id) }.is_some() {
        return 0;
    }

    let mmap_data = MmapData {
        addr: 0,
        len: 0,
        prot: 0,
        flags: 0,
    };

    let event = SecurityEvent::new(
        EventType::FileMmap,
        pid,
        (pid_tgid >> 32) as u32,
        0,
        0,
        cgroup_id,
    )
    .with_mmap_data(&mmap_data);

    if let Some(mut entry) = unsafe { EVENTS.reserve::<SecurityEvent>(0) } {
        entry.write(event);
        entry.submit(0);
    }

    info!(ctx, "MMAP: pid={}", pid);
    0
}

unsafe fn try_mprotect(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    info!(ctx, "MPROTECT: pid={}", pid);
    0
}
