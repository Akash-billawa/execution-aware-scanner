/// Kprobe Programs - Kernel Function Hooks
/// Tracks network connections and data transfers
use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::kprobe,
    programs::ProbeContext,
};

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

unsafe fn try_tcp_connect(_ctx: &ProbeContext, _family: u16) -> u32 {
    let _pid_tgid = bpf_get_current_pid_tgid();
    // Network event tracking disabled for verifier compatibility
    0
}

unsafe fn try_tcp_close(_ctx: &ProbeContext) -> u32 {
    let _pid_tgid = bpf_get_current_pid_tgid();
    // Network event tracking disabled for verifier compatibility
    0
}

unsafe fn try_tcp_data(_ctx: &ProbeContext, _is_send: bool) -> u32 {
    let _pid_tgid = bpf_get_current_pid_tgid();
    // Network data transfer tracking disabled for verifier compatibility
    0
}

unsafe fn try_udp_data(_ctx: &ProbeContext, _is_send: bool) -> u32 {
    let _pid_tgid = bpf_get_current_pid_tgid();
    // UDP tracking disabled for verifier compatibility
    0
}
