#![no_std]
#![no_main]

// Minimal eBPF Scanner for aya-ebpf 0.1.1
// Only tracepoints (simplest probe type)

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

// Simple event structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub command: [u8; 16],
}

// Tracepoint: execve syscall entry
#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn trace_enter_execve(ctx: TracePointContext) -> u32 {
    unsafe {
        try_execve(&ctx);
    }
    0
}

// Tracepoint: execve syscall exit
#[tracepoint(category = "syscalls", name = "sys_exit_execve")]
pub fn trace_exit_execve(ctx: TracePointContext) -> u32 {
    unsafe {
        try_execve_return(&ctx);
    }
    0
}

// Tracepoint: openat syscall
#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    unsafe {
        try_openat(&ctx);
    }
    0
}

// Tracepoint: mmap syscall
#[tracepoint(category = "syscalls", name = "sys_enter_mmap")]
pub fn trace_mmap(ctx: TracePointContext) -> u32 {
    unsafe {
        try_mmap(&ctx);
    }
    0
}

unsafe fn try_execve(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();

    // Get command name
    let command = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => [0u8; 16],
    };

    let event = Event {
        timestamp_ns: bpf_ktime_get_ns(),
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        command,
    };

    // Log to kernel trace pipe
    info!(ctx, "Process exec: pid={}, comm={}", event.pid, event.pid);

    0
}

unsafe fn try_execve_return(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    info!(ctx, "Process exec return: pid={}", pid_tgid as u32);
    0
}

unsafe fn try_openat(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    info!(ctx, "File open: pid={}", pid_tgid as u32);
    0
}

unsafe fn try_mmap(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    info!(ctx, "Memory map: pid={}", pid_tgid as u32);
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
