#![no_std]
#![no_main]

mod events;
mod lsm;
mod maps;
mod xdp;

use aya_bpf::{
    bindings::sock,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{kprobe, lsm, map, tracepoint, xdp},
    maps::{HashMap, PerfEventArray, RingBuf},
    programs::{KProbeContext, LsmContext, TracePointContext, XdpContext},
};
use aya_log_ebpf::info;
use core::mem;
use events::{EventKind, ExecEvent, FileEvent, NetEvent, SecurityEvent, ARGS_LEN, PATH_LEN};
use maps::*;

// Tracepoint hooks for syscalls
#[tracepoint(name = "scanner_execve")]
pub fn scanner_execve(ctx: TracePointContext) -> u32 {
    match unsafe { try_execve(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_execve(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let cgroup_id = bpf_get_current_cgroup_id();

    // Check if cgroup is allowlisted
    if let Some(_) = ALLOWLIST.get(&cgroup_id) {
        return Ok(0);
    }

    let mut event = ExecEvent {
        timestamp_ns: bpf_ktime_get_ns(),
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        cgroup_id,
        ppid: 0,
        command: [0; 16],
        argv: [0; ARGS_LEN],
    };

    let _ = bpf_get_current_comm(&mut event.command);
    let _ = ctx.read_at(16, &mut event.argv);

    // Emit via perf buffer for lower latency
    if let Some(mut slot) = EXEC_EVENTS.reserve::<ExecEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }

    // Update cgroup stats
    if let Some(stats) = unsafe { CGROUP_STATS.get_mut(&cgroup_id) } {
        stats.exec_count += 1;
        stats.last_seen_ns = event.timestamp_ns;
    }

    Ok(0)
}

#[tracepoint(name = "scanner_execveat")]
pub fn scanner_execveat(ctx: TracePointContext) -> u32 {
    scanner_execve(ctx)
}

#[tracepoint(name = "scanner_openat")]
pub fn scanner_openat(ctx: TracePointContext) -> u32 {
    match unsafe { emit_file_event(&ctx, EventKind::Open) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint(name = "scanner_openat2")]
pub fn scanner_openat2(ctx: TracePointContext) -> u32 {
    scanner_openat(ctx)
}

#[tracepoint(name = "scanner_mmap")]
pub fn scanner_mmap(ctx: TracePointContext) -> u32 {
    match unsafe { emit_file_event(&ctx, EventKind::Mmap) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint(name = "scanner_mprotect")]
pub fn scanner_mprotect(ctx: TracePointContext) -> u32 {
    match unsafe { emit_file_event(&ctx, EventKind::Mprotect) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn emit_file_event(ctx: &TracePointContext, kind: EventKind) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();

    if let Some(_) = ALLOWLIST.get(&cgroup_id) {
        return Ok(0);
    }

    let mut event = FileEvent {
        timestamp_ns: bpf_ktime_get_ns(),
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        cgroup_id,
        command: [0; 16],
        path: [0; PATH_LEN],
        kind,
        prot: 0,
        flags: 0,
    };

    let _ = bpf_get_current_comm(&mut event.command);
    let _ = ctx.read_at(24, &mut event.path);

    if let Some(mut slot) = FILE_EVENTS.reserve::<FileEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }

    // Track file access for integrity monitoring
    let path_hash = hash_path(&event.path);
    if let Some(entry) = unsafe { FILE_CACHE.get_mut(&path_hash) } {
        entry.last_access_ns = event.timestamp_ns;
        entry.access_count += 1;
    }

    Ok(0)
}

#[kprobe(name = "scanner_tcp_connect")]
pub fn scanner_tcp_connect(ctx: KProbeContext) -> u32 {
    match unsafe { emit_connect(&ctx, EventKind::Connect) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kprobe(name = "scanner_tcp_connect_v6")]
pub fn scanner_tcp_connect_v6(ctx: KProbeContext) -> u32 {
    match unsafe { emit_connect_v6(&ctx, EventKind::Connect) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kprobe(name = "scanner_inet_bind")]
pub fn scanner_inet_bind(ctx: KProbeContext) -> u32 {
    match unsafe { emit_bind(&ctx, EventKind::Bind) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kprobe(name = "scanner_inet_bind_v6")]
pub fn scanner_inet_bind_v6(ctx: KProbeContext) -> u32 {
    match unsafe { emit_bind_v6(&ctx, EventKind::Bind) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kprobe(name = "scanner_tcp_close")]
pub fn scanner_tcp_close(ctx: KProbeContext) -> u32 {
    match unsafe { emit_net_event(&ctx, EventKind::Close) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kprobe(name = "scanner_udp_sendmsg")]
pub fn scanner_udp_sendmsg(ctx: KProbeContext) -> u32 {
    match unsafe { emit_net_event(&ctx, EventKind::UdpSend) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kprobe(name = "scanner_udp_recvmsg")]
pub fn scanner_udp_recvmsg(ctx: KProbeContext) -> u32 {
    match unsafe { emit_net_event(&ctx, EventKind::UdpRecv) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn emit_connect(ctx: &KProbeContext, kind: EventKind) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();

    if let Some(_) = ALLOWLIST.get(&cgroup_id) {
        return Ok(0);
    }

    let sock: *const sock = ctx.arg(0).ok_or(1i64)?;
    let sk_common = &(*sock).__bindgen_anon_1.__bindgen_anon_1;

    // Check against blocked IPs
    let daddr = sk_common.skc_daddr;
    if let Some(_) = BLOCKED_IPS.get(&daddr) {
        return Ok(1); // Block connection
    }

    let event = NetEvent {
        timestamp_ns: bpf_ktime_get_ns(),
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        cgroup_id,
        saddr: sk_common.skc_rcv_saddr,
        daddr,
        sport: sk_common.skc_num,
        dport: u16::from_be(sk_common.skc_dport),
        family: sk_common.skc_family,
        protocol: sk_common.skc_protocol,
        kind,
    };

    if let Some(mut slot) = NET_EVENTS.reserve::<NetEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }

    // Update connection tracking
    if let Some(conn) = unsafe { CONNECTIONS.get_mut(&conn_key(&event)) } {
        conn.state = 1; // ESTABLISHED
        conn.last_activity_ns = event.timestamp_ns;
    }

    Ok(0)
}

unsafe fn emit_connect_v6(ctx: &KProbeContext, kind: EventKind) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();

    if let Some(_) = ALLOWLIST.get(&cgroup_id) {
        return Ok(0);
    }

    let sock: *const sock = ctx.arg(0).ok_or(1i64)?;

    let event = NetEvent {
        timestamp_ns: bpf_ktime_get_ns(),
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        cgroup_id,
        saddr: 0, // IPv6 not fully supported in this version
        daddr: 0,
        sport: 0,
        dport: 0,
        family: 10,  // AF_INET6
        protocol: 6, // TCP
        kind,
    };

    if let Some(mut slot) = NET_EVENTS.reserve::<NetEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }

    Ok(0)
}

unsafe fn emit_bind(ctx: &KProbeContext, kind: EventKind) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();

    if let Some(_) = ALLOWLIST.get(&cgroup_id) {
        return Ok(0);
    }

    let sock: *const sock = ctx.arg(0).ok_or(1i64)?;
    let sk_common = &(*sock).__bindgen_anon_1.__bindgen_anon_1;

    let event = NetEvent {
        timestamp_ns: bpf_ktime_get_ns(),
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        cgroup_id,
        saddr: sk_common.skc_rcv_saddr,
        daddr: 0,
        sport: sk_common.skc_num,
        dport: 0,
        family: sk_common.skc_family,
        protocol: sk_common.skc_protocol,
        kind,
    };

    if let Some(mut slot) = NET_EVENTS.reserve::<NetEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }

    Ok(0)
}

unsafe fn emit_bind_v6(ctx: &KProbeContext, kind: EventKind) -> Result<u32, i64> {
    emit_connect_v6(ctx, kind)
}

unsafe fn emit_net_event(_ctx: &KProbeContext, kind: EventKind) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();

    if let Some(_) = ALLOWLIST.get(&cgroup_id) {
        return Ok(0);
    }

    let event = NetEvent {
        timestamp_ns: bpf_ktime_get_ns(),
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        cgroup_id,
        saddr: 0,
        daddr: 0,
        sport: 0,
        dport: 0,
        family: 2,
        protocol: 17, // UDP
        kind,
    };

    if let Some(mut slot) = NET_EVENTS.reserve::<NetEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }

    Ok(0)
}

// LSM hooks for security enforcement
#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match unsafe { try_bprm_check_security(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bprm_check_security(_ctx: &LsmContext) -> Result<i32, i32> {
    let cgroup_id = bpf_get_current_cgroup_id();

    // Check if cgroup is in denylist
    if let Some(_) = DENYLIST.get(&cgroup_id) {
        return Err(-1); // Permission denied
    }

    Ok(0)
}

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    match unsafe { try_socket_connect(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_socket_connect(_ctx: &LsmContext) -> Result<i32, i32> {
    let cgroup_id = bpf_get_current_cgroup_id();

    if let Some(_) = DENYLIST.get(&cgroup_id) {
        return Err(-1);
    }

    Ok(0)
}

#[lsm(hook = "socket_bind")]
pub fn socket_bind(ctx: LsmContext) -> i32 {
    match unsafe { try_socket_bind(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_socket_bind(_ctx: &LsmContext) -> Result<i32, i32> {
    let cgroup_id = bpf_get_current_cgroup_id();

    if let Some(_) = DENYLIST.get(&cgroup_id) {
        return Err(-1);
    }

    Ok(0)
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match unsafe { try_file_open(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_file_open(_ctx: &LsmContext) -> Result<i32, i32> {
    let cgroup_id = bpf_get_current_cgroup_id();

    if let Some(_) = DENYLIST.get(&cgroup_id) {
        return Err(-1);
    }

    Ok(0)
}

// XDP program for traffic filtering
#[xdp]
pub fn scanner_xdp_filter(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_filter(&ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp::XDP_PASS,
    }
}

unsafe fn try_xdp_filter(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + 20 > data_end {
        return Ok(xdp::XDP_PASS);
    }

    // Check IP header
    let ip_header = data as *const u8;
    let version_ihl = *ip_header;
    let version = version_ihl >> 4;

    if version != 4 {
        return Ok(xdp::XDP_PASS);
    }

    let src_ip = u32::from_be(*((ip_header as *const u32).add(3)));

    // Check if source IP is blocked
    if let Some(_) = XDP_BLOCKED_IPS.get(&src_ip) {
        return Ok(xdp::XDP_DROP);
    }

    Ok(xdp::XDP_PASS)
}

// Helper functions
unsafe fn hash_path(path: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for byte in path.iter() {
        if *byte == 0 {
            break;
        }
        hash = ((hash << 5) + hash) + (*byte as u32);
    }
    hash
}

fn conn_key(event: &NetEvent) -> u64 {
    ((event.saddr as u64) << 32) | (event.sport as u64)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
static LICENSE: &[u8] = b"GPL\0";
