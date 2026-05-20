/// Kprobe Programs - Kernel Function Hooks
/// Production-grade eBPF with verifier-safe patterns
use crate::events::{
    calculate_confidence, create_base_event, emit_event, EventData, EventKind, NetData,
};
use crate::network::{check_exfiltration, track_tcp_connect, update_data_transfer};
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::kprobe,
    programs::ProbeContext,
};

/// Read a u16 from a kernel pointer at a given offset (verifier-safe)
#[inline(always)]
fn read_u16(ptr: *const u8, offset: usize) -> u16 {
    unsafe { bpf_probe_read_kernel(ptr.add(offset) as *const u16).unwrap_or(0) }
}

/// Read a u32 from a kernel pointer at a given offset (verifier-safe)
#[inline(always)]
fn read_u32(ptr: *const u8, offset: usize) -> u32 {
    unsafe { bpf_probe_read_kernel(ptr.add(offset) as *const u32).unwrap_or(0) }
}

/// Extract destination IP and port from a sockaddr_in pointer
/// sockaddr_in layout: family(2) + port(2) + addr(4)
#[inline(always)]
fn extract_dest(uaddr: *const u8) -> (u32, u16) {
    let dport = read_u16(uaddr, 2); // network byte order
    let daddr = read_u32(uaddr, 4); // network byte order
    (daddr, dport)
}

#[inline(always)]
fn emit_network_event(
    kind: EventKind,
    protocol: u8,
    saddr: u32,
    sport: u16,
    daddr: u32,
    dport: u16,
    bytes: u64,
    is_send: bool,
) {
    let pid = bpf_get_current_pid_tgid() as u32;
    let mut base = create_base_event(kind);
    base.confidence = calculate_confidence(kind, false, true, false);
    base.data = EventData {
        net: NetData {
            saddr,
            daddr,
            sport,
            dport,
            bytes,
            protocol,
            is_external: 0,
            is_suspicious_port: 0,
            _pad: [0; 101],
        },
    };
    emit_event(base);

    if bytes > 0 {
        update_data_transfer(pid, bytes, is_send);
        if check_exfiltration(pid) {
            let mut suspicious = create_base_event(EventKind::Suspicious);
            suspicious.confidence = 90;
            suspicious.data = base.data;
            emit_event(suspicious);
        }
    }
}

/// TCP connect (IPv4)
/// arg(0) = struct sock *sk, arg(1) = struct sockaddr *uaddr
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "tcp_v4_connect")]
pub fn trace_tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    let uaddr = ctx.arg::<*const u8>(1).unwrap_or(core::ptr::null());
    let (daddr, dport) = if !uaddr.is_null() {
        extract_dest(uaddr)
    } else {
        (0u32, 0u16)
    };
    track_tcp_connect(pid, 0, 0, daddr, dport, 6);
    emit_network_event(EventKind::Connect, 6, 0, 0, daddr, dport, 0, true);
    0
}

/// TCP connect (IPv6)
/// arg(0) = struct sock *sk, arg(1) = struct sockaddr *uaddr
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "tcp_v6_connect")]
pub fn trace_tcp_v6_connect(ctx: ProbeContext) -> u32 {
    let uaddr = ctx.arg::<*const u8>(1).unwrap_or(core::ptr::null());
    let (daddr, dport) = if !uaddr.is_null() {
        extract_dest(uaddr)
    } else {
        (0u32, 0u16)
    };
    emit_network_event(EventKind::Connect, 6, 0, 0, daddr, dport, 0, true);
    0
}

/// TCP close
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "tcp_close")]
pub fn trace_tcp_close(_ctx: ProbeContext) -> u32 {
    emit_network_event(EventKind::NetTransfer, 6, 0, 0, 0, 0, 0, false);
    0
}

/// TCP send data
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "tcp_sendmsg")]
pub fn trace_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    let bytes = ctx.arg::<usize>(2).unwrap_or(0) as u64;
    emit_network_event(EventKind::NetTransfer, 6, 0, 0, 0, 0, bytes, true);
    0
}

/// TCP receive data
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "tcp_recvmsg")]
pub fn trace_tcp_recvmsg(ctx: ProbeContext) -> u32 {
    let bytes = ctx.arg::<usize>(2).unwrap_or(0) as u64;
    emit_network_event(EventKind::NetTransfer, 6, 0, 0, 0, 0, bytes, false);
    0
}

/// UDP send
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "udp_sendmsg")]
pub fn trace_udp_sendmsg(ctx: ProbeContext) -> u32 {
    let bytes = ctx.arg::<usize>(2).unwrap_or(0) as u64;
    emit_network_event(EventKind::NetTransfer, 17, 0, 0, 0, 0, bytes, true);
    0
}

/// UDP receive
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "udp_recvmsg")]
pub fn trace_udp_recvmsg(ctx: ProbeContext) -> u32 {
    let bytes = ctx.arg::<usize>(2).unwrap_or(0) as u64;
    emit_network_event(EventKind::NetTransfer, 17, 0, 0, 0, 0, bytes, false);
    0
}
