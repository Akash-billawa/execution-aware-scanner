/// Kprobe Programs - Kernel Function Hooks
/// Tracks network connections, data transfers, and kernel operations
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
    },
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

use crate::common::*;
use crate::events::*;
use crate::maps::*;

/// TCP connection (IPv4)
#[kprobe(function = "tcp_v4_connect")]
pub fn trace_tcp_v4_connect(ctx: ProbeContext) -> u32 {
    unsafe { try_tcp_connect(&ctx, 4) };
    0
}

/// TCP connection (IPv6)
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

/// Socket bind
#[kprobe(function = "inet_bind")]
pub fn trace_inet_bind(ctx: ProbeContext) -> u32 {
    unsafe { try_socket_bind(&ctx) };
    0
}

/// Memory mapping (do_mmap)
#[kprobe(function = "do_mmap")]
pub fn trace_do_mmap(ctx: ProbeContext) -> u32 {
    unsafe { try_do_mmap(&ctx) };
    0
}

unsafe fn try_tcp_connect(ctx: &ProbeContext, family: u16) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;
    
    // Skip if allowlisted
    if unsafe { ALLOWLIST.get(&cgroup_id) }.is_some() {
        return 0;
    }
    
    info!(ctx, "TCP_CONNECT: pid={} family={}", pid, family);
    0
}

    // Rate limiting
    let key = make_key(pid, EventType::NetConnect as u32);
    if is_rate_limited(key) {
        return 0;
    }

    // Get socket pointer from arg0
    let sock_ptr: *const sock = match ctx.arg(0) {
        Some(ptr) => ptr,
        None => return 0,
    };

    let sk_common = &(*sock_ptr).__sk_common;
    let daddr = sk_common.skc_daddr;

    // Check if destination is blocked
    if unsafe { BLOCKED_IPS.get(&daddr) }.is_some() {
        info!(ctx, "BLOCKED TCP connect: pid={} daddr={}", pid, daddr);
        return 1; // Block
    }

    let net_data = NetData {
        saddr: sk_common.skc_rcv_saddr,
        daddr,
        sport: sk_common.skc_num as u16,
        dport: u16::from_be(sk_common.skc_dport),
        family,
        protocol: 6, // TCP
    };

    let event = SecurityEvent::new(
        EventType::NetConnect,
        pid,
        tgid,
        uid_gid as u32,
        (uid_gid >> 32) as u32,
        cgroup_id,
    )
    .with_net_data(&net_data);

    if let Some(mut entry) = unsafe { EVENTS.reserve::<SecurityEvent>(0) } {
        entry.write(event);
        entry.submit(0);
    }

    info!(
        ctx,
        "TCP_CONNECT: pid={} {}:{} -> {}:{}",
        pid,
        net_data.saddr,
        net_data.sport,
        net_data.daddr,
        net_data.dport
    );
    0
}

unsafe fn try_tcp_close(ctx: &ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    if unsafe { ALLOWLIST.get(&cgroup_id) }.is_some() {
        return 0;
    }

    info!(ctx, "TCP_CLOSE: pid={}", pid);
    0
}

unsafe fn try_tcp_data(ctx: &ProbeContext, is_send: bool) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    if unsafe { ALLOWLIST.get(&cgroup_id) }.is_some() {
        return 0;
    }

    // Rate limiting for data events
    let key = make_key(
        pid,
        if is_send {
            EventType::NetSend as u32
        } else {
            EventType::NetRecv as u32
        },
    );
    if is_rate_limited(key) {
        return 0;
    }

    if is_send {
        info!(ctx, "TCP_SEND: pid={}", pid);
    } else {
        info!(ctx, "TCP_RECV: pid={}", pid);
    }
    0
}

unsafe fn try_udp_data(ctx: &ProbeContext, is_send: bool) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    if unsafe { ALLOWLIST.get(&cgroup_id) }.is_some() {
        return 0;
    }

    if is_send {
        info!(ctx, "UDP_SEND: pid={}", pid);
    } else {
        info!(ctx, "UDP_RECV: pid={}", pid);
    }
    0
}

unsafe fn try_socket_bind(ctx: &ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    if unsafe { ALLOWLIST.get(&cgroup_id) }.is_some() {
        return 0;
    }

    info!(ctx, "BIND: pid={}", pid);
    0
}

unsafe fn try_do_mmap(ctx: &ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    if unsafe { ALLOWLIST.get(&cgroup_id) }.is_some() {
        return 0;
    }

    info!(ctx, "DO_MMAP: pid={}", pid);
    0
}
