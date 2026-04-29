/// Kprobe Programs - Kernel Function Hooks
/// Production-grade eBPF with verifier-safe patterns
use crate::events::{
    calculate_confidence, create_base_event, emit_event, EventData, EventKind, NetData,
};
use crate::network::{check_exfiltration, track_tcp_connect, update_data_transfer};
use aya_ebpf::{helpers::bpf_get_current_pid_tgid, macros::kprobe, programs::ProbeContext};

#[inline(always)]
fn emit_network_event(kind: EventKind, protocol: u8, bytes: u64, is_send: bool) {
    let pid = bpf_get_current_pid_tgid() as u32;
    let mut base = create_base_event(kind);
    base.confidence = calculate_confidence(kind, false, true, false);
    base.data = EventData {
        net: NetData {
            saddr: 0,
            daddr: 0,
            sport: 0,
            dport: 0,
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
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "tcp_v4_connect")]
pub fn trace_tcp_v4_connect(_ctx: ProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    track_tcp_connect(pid, 0, 0, 0, 0, 6);
    emit_network_event(EventKind::Connect, 6, 0, true);
    0
}

/// TCP connect (IPv6)
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "tcp_v6_connect")]
pub fn trace_tcp_v6_connect(_ctx: ProbeContext) -> u32 {
    emit_network_event(EventKind::Connect, 6, 0, true);
    0
}

/// TCP close
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "tcp_close")]
pub fn trace_tcp_close(_ctx: ProbeContext) -> u32 {
    emit_network_event(EventKind::NetTransfer, 6, 0, true);
    0
}

/// TCP send data
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "tcp_sendmsg")]
pub fn trace_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    let bytes = ctx.arg::<usize>(2).unwrap_or(0) as u64;
    emit_network_event(EventKind::NetTransfer, 6, bytes, true);
    0
}

/// TCP receive data
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "tcp_recvmsg")]
pub fn trace_tcp_recvmsg(ctx: ProbeContext) -> u32 {
    let bytes = ctx.arg::<usize>(2).unwrap_or(0) as u64;
    emit_network_event(EventKind::NetTransfer, 6, bytes, false);
    0
}

/// UDP send
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "udp_sendmsg")]
pub fn trace_udp_sendmsg(ctx: ProbeContext) -> u32 {
    let bytes = ctx.arg::<usize>(2).unwrap_or(0) as u64;
    emit_network_event(EventKind::NetTransfer, 17, bytes, true);
    0
}

/// UDP receive
/// SAFETY: kprobe handler verified by eBPF verifier
#[kprobe(function = "udp_recvmsg")]
pub fn trace_udp_recvmsg(ctx: ProbeContext) -> u32 {
    let bytes = ctx.arg::<usize>(2).unwrap_or(0) as u64;
    emit_network_event(EventKind::NetTransfer, 17, bytes, false);
    0
}
