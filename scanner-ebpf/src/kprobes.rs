/// Kprobe Programs - Kernel Function Hooks
/// Tracks network connections and data transfers
use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

/// TCP connect (IPv4)
#[kprobe(function = "tcp_v4_connect")]
pub fn trace_tcp_v4_connect(ctx: ProbeContext) -> u32 {
    unsafe { try_tcp_connect(&ctx, 4) };
    0
}

/// TCP connect (IPv6)
#[kprobe(function = "tcp_v6_connect")]
pub fn trace_tcp_v6_connect(ctx: ProbeContext) -> u32 {
    unsafe { try_tcp_connect(&ctx, 6) };
    0
}

/// TCP close
#[kprobe(function = "tcp_close")]
pub fn trace_tcp_close(ctx: ProbeContext) -> u32 {
    unsafe { try_tcp_close(&ctx) };
    0
}

/// TCP send data
#[kprobe(function = "tcp_sendmsg")]
pub fn trace_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    unsafe { try_tcp_data(&ctx, true) };
    0
}

/// TCP receive data
#[kprobe(function = "tcp_recvmsg")]
pub fn trace_tcp_recvmsg(ctx: ProbeContext) -> u32 {
    unsafe { try_tcp_data(&ctx, false) };
    0
}

/// UDP send
#[kprobe(function = "udp_sendmsg")]
pub fn trace_udp_sendmsg(ctx: ProbeContext) -> u32 {
    unsafe { try_udp_data(&ctx, true) };
    0
}

/// UDP receive
#[kprobe(function = "udp_recvmsg")]
pub fn trace_udp_recvmsg(ctx: ProbeContext) -> u32 {
    unsafe { try_udp_data(&ctx, false) };
    0
}

unsafe fn try_tcp_connect(ctx: &ProbeContext, family: u16) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    info!(ctx, "TCP_CONNECT: pid={} family={}", pid, family);
    0
}

unsafe fn try_tcp_close(ctx: &ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    info!(ctx, "TCP_CLOSE: pid={}", pid);
    0
}

unsafe fn try_tcp_data(ctx: &ProbeContext, is_send: bool) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    // Get message size from arg2
    let size: usize = match ctx.arg(2) {
        Some(s) => s,
        None => 0,
    };

    // Alert on large transfers (>1MB)
    if size > 1024 * 1024 {
        let direction = if is_send { "SEND" } else { "RECV" };
        info!(
            ctx,
            "LARGE_TRANSFER: pid={} {} {} bytes", pid, direction, size
        );
    }

    0
}

unsafe fn try_udp_data(ctx: &ProbeContext, is_send: bool) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    if is_send {
        info!(ctx, "UDP_SEND: pid={}", pid);
    } else {
        info!(ctx, "UDP_RECV: pid={}", pid);
    }
    0
}
