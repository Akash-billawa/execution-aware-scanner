#![no_std]
#![no_main]

mod events;
mod maps;

use aya_ebpf::{
    bindings::sock,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns,
    },
    macros::{kprobe, lsm, map, tracepoint, xdp},
    maps::{HashMap, LruHashMap, RingBuf},
    programs::{KProbeContext, LsmContext, TracePointContext, XdpContext},
};
use aya_log_ebpf::{debug, info, warn};
use events::*;
use maps::*;

// ═══════════════════════════════════════════════════════════════════════════
// ADVANCED eBPF SCANNER - Comprehensive Runtime Security
// ═══════════════════════════════════════════════════════════════════════════

// ───────────────────────────────────────────────────────────────────────────
// 1. EXECUTION MONITORING (Tracepoints)
// ───────────────────────────────────────────────────────────────────────────

#[tracepoint(name = "sys_enter_execve")]
pub fn trace_execve(ctx: TracePointContext) -> u32 {
    match unsafe { try_execve(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint(name = "sys_enter_execveat")]
pub fn trace_execveat(ctx: TracePointContext) -> u32 {
    trace_execve(ctx)
}

unsafe fn try_execve(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let cgroup_id = bpf_get_current_cgroup_id();

    // Check allowlist
    if ALLOWLIST.get(&cgroup_id).is_some() {
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
        envp: [0; ENV_LEN],
    };

    // Capture command name
    let _ = bpf_get_current_comm(&mut event.command);

    // Read arguments from syscall (struct pt_regs offset)
    // arg1 = filename, arg2 = argv, arg3 = envp
    let _ = ctx.read_at(16, &mut event.argv);
    let _ = ctx.read_at(24, &mut event.envp);

    // Track process parent
    let _ = PROCESS_PARENT.insert(&(pid_tgid as u32), &((pid_tgid >> 32) as u32), 0);

    // Emit event
    if let Some(mut slot) = EXEC_EVENTS.reserve::<ExecEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }

    // Update cgroup stats
    update_cgroup_stats(cgroup_id, SyscallType::Exec);

    // Check for suspicious patterns
    if is_suspicious_command(&event.command) {
        log_security_event(cgroup_id, SecurityEventType::SuspiciousExec);
    }

    debug!("Process started");
    Ok(0)
}

// ───────────────────────────────────────────────────────────────────────────
// 2. FILE MONITORING (Tracepoints + LSM)
// ───────────────────────────────────────────────────────────────────────────

#[tracepoint(name = "sys_enter_openat")]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    match unsafe { try_file_event(&ctx, EventKind::Open) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint(name = "sys_enter_openat2")]
pub fn trace_openat2(ctx: TracePointContext) -> u32 {
    trace_openat(ctx)
}

#[tracepoint(name = "sys_enter_mmap")]
pub fn trace_mmap(ctx: TracePointContext) -> u32 {
    match unsafe { try_file_event(&ctx, EventKind::Mmap) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint(name = "sys_enter_mprotect")]
pub fn trace_mprotect(ctx: TracePointContext) -> u32 {
    match unsafe { try_file_event(&ctx, EventKind::Mprotect) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_file_event(ctx: &TracePointContext, kind: EventKind) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();

    if ALLOWLIST.get(&cgroup_id).is_some() {
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

    // Read filename (offset varies by syscall)
    let offset = match kind {
        EventKind::Open => 24,
        EventKind::Mmap => 16,
        EventKind::Mprotect => 16,
        _ => 16,
    };
    let _ = ctx.read_at(offset, &mut event.path);

  // Track library loading for vulnerability correlation
  if kind == EventKind::Mmap && is_shared_library(&event.path) {
    track_library_load(pid_tgid as u32, &event.path)?;
    log_security_event(cgroup_id, SecurityEventType::LibraryLoad);
  }

    // File integrity monitoring
    if should_monitor_file(&event.path) {
        update_file_cache(&event.path);
    }

    // Emit event
    if let Some(mut slot) = FILE_EVENTS.reserve::<FileEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }

    // Update stats
    update_cgroup_stats(cgroup_id, SyscallType::File);

    Ok(0)
}

// ───────────────────────────────────────────────────────────────────────────
// 3. NETWORK MONITORING (Kprobes)
// ───────────────────────────────────────────────────────────────────────────

#[kprobe(name = "tcp_v4_connect")]
pub fn trace_tcp_connect(ctx: KProbeContext) -> u32 {
  match unsafe { try_tcp_connect(&ctx) } {
    Ok(ret) => ret,
    Err(_) => 0,
  }
}

#[kprobe(name = "tcp_v6_connect")]
pub fn trace_tcp_connect_v6(ctx: KProbeContext) -> u32 {
  match unsafe { try_tcp_connect_v6(&ctx) } {
    Ok(ret) => ret,
    Err(_) => 0,
  }
}

#[kprobe(name = "tcp_close")]
pub fn trace_tcp_close(ctx: KProbeContext) -> u32 {
  match unsafe { try_tcp_close(&ctx) } {
    Ok(ret) => ret,
    Err(_) => 0,
  }
}

#[kprobe(name = "inet_bind")]
pub fn trace_bind(ctx: KProbeContext) -> u32 {
  match unsafe { try_bind(&ctx) } {
    Ok(ret) => ret,
    Err(_) => 0,
  }
}

#[kprobe(name = "udp_sendmsg")]
pub fn trace_udp_send(ctx: KProbeContext) -> u32 {
  match unsafe { try_udp(&ctx, EventKind::UdpSend) } {
    Ok(ret) => ret,
    Err(_) => 0,
  }
}

#[kprobe(name = "udp_recvmsg")]
pub fn trace_udp_recv(ctx: KProbeContext) -> u32 {
  match unsafe { try_udp(&ctx, EventKind::UdpRecv) } {
    Ok(ret) => ret,
    Err(_) => 0,
  }
}

// NEW: tcp_sendmsg for data exfiltration detection
#[kprobe(name = "tcp_sendmsg")]
pub fn trace_tcp_sendmsg(ctx: KProbeContext) -> u32 {
  match unsafe { try_tcp_sendmsg(&ctx) } {
    Ok(ret) => ret,
    Err(_) => 0,
  }
}

// NEW: tcp_recvmsg for C2 detection
#[kprobe(name = "tcp_recvmsg")]
pub fn trace_tcp_recvmsg(ctx: KProbeContext) -> u32 {
  match unsafe { try_tcp_recvmsg(&ctx) } {
    Ok(ret) => ret,
    Err(_) => 0,
  }
}

unsafe fn try_tcp_connect(ctx: &KProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();

    if ALLOWLIST.get(&cgroup_id).is_some() {
        return Ok(0);
    }

    let sock: *const sock = ctx.arg(0).ok_or(1i64)?;
    let sk_common = &(*sock).__sk_common;

    let daddr = sk_common.skc_daddr;

    // Check against threat intelligence IPs
    if THREAT_INTEL_IPS.get(&daddr).is_some() {
        warn!("Connection to malicious IP detected");
        log_security_event(cgroup_id, SecurityEventType::MaliciousConnection);
    }

    // Block if in denylist
    if BLOCKED_IPS.get(&daddr).is_some() {
        return Ok(1); // Block
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
        protocol: 6, // TCP
        kind: EventKind::Connect,
    data_size: 0,
    };

    // Track connection
    let conn_key = ((event.saddr as u64) << 32) | (event.sport as u64);
    let conn_entry = ConnectionEntry {
        saddr: event.saddr,
        daddr: event.daddr,
        sport: event.sport,
        dport: event.dport,
        state: CONN_ESTABLISHED,
        created_ns: event.timestamp_ns,
        last_activity_ns: event.timestamp_ns,
    };
    let _ = CONNECTIONS.insert(&conn_key, &conn_entry, 0);

    // Emit event
    if let Some(mut slot) = NET_EVENTS.reserve::<NetEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }

    update_cgroup_stats(cgroup_id, SyscallType::Network);
    Ok(0)
}

unsafe fn try_tcp_connect_v6(ctx: &KProbeContext) -> Result<u32, i64> {
    // IPv6 support (simplified - full impl would handle v6 addrs)
    try_tcp_connect(ctx)
}

unsafe fn try_tcp_close(ctx: &KProbeContext) -> Result<u32, i64> {
    // Cleanup connection tracking
    let sock: *const sock = ctx.arg(0).ok_or(1i64)?;
    let sk_common = &(*sock).__sk_common;

    let conn_key = ((sk_common.skc_rcv_saddr as u64) << 32) | (sk_common.skc_num as u64);
    let _ = CONNECTIONS.remove(&conn_key);

    Ok(0)
}

unsafe fn try_bind(ctx: &KProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let sock: *const sock = ctx.arg(0).ok_or(1i64)?;
    let sk_common = &(*sock).__sk_common;

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
    protocol: 6,
    kind: EventKind::Bind,
    data_size: 0,
  };

    if let Some(mut slot) = NET_EVENTS.reserve::<NetEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }

    Ok(0)
}

unsafe fn try_udp(ctx: &KProbeContext, kind: EventKind) -> Result<u32, i64> {
  let pid_tgid = bpf_get_current_pid_tgid();
  let cgroup_id = bpf_get_current_cgroup_id();

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
    data_size: 0,
  };

  if let Some(mut slot) = NET_EVENTS.reserve::<NetEvent>(0) {
    slot.write(event);
    slot.submit(0);
  }

  Ok(0)
}

// NEW: tcp_sendmsg handler for data exfiltration detection
unsafe fn try_tcp_sendmsg(ctx: &KProbeContext) -> Result<u32, i64> {
  let pid_tgid = bpf_get_current_pid_tgid();
  let cgroup_id = bpf_get_current_cgroup_id();

  if ALLOWLIST.get(&cgroup_id).is_some() {
    return Ok(0);
  }

  let sock: *const sock = ctx.arg(0).ok_or(1i64)?;
  let sk_common = &(*sock).__sk_common;
  let size: usize = ctx.arg(2).ok_or(1i64)?;

  // Look up existing connection
  let conn_key = ((sk_common.skc_rcv_saddr as u64) << 32) | (sk_common.skc_num as u64);

  // Emit TCP send event
  let event = NetEvent {
    timestamp_ns: bpf_ktime_get_ns(),
    pid: pid_tgid as u32,
    tgid: (pid_tgid >> 32) as u32,
    cgroup_id,
    saddr: sk_common.skc_rcv_saddr,
    daddr: sk_common.skc_daddr,
    sport: sk_common.skc_num,
    dport: u16::from_be(sk_common.skc_dport),
    family: sk_common.skc_family,
    protocol: 6, // TCP
    kind: EventKind::TcpSend,
    data_size: size as u32,
  };

  if let Some(mut slot) = NET_EVENTS.reserve::<NetEvent>(0) {
    slot.write(event);
    slot.submit(0);
  }

  // Track data transfer for behavioral analysis
  if size > 1024 {
    // Large data transfer - potential exfiltration
    log_security_event(cgroup_id, SecurityEventType::LargeDataTransfer);
  }

  update_cgroup_stats(cgroup_id, SyscallType::Network);
  Ok(0)
}

// NEW: tcp_recvmsg handler for C2 detection
unsafe fn try_tcp_recvmsg(ctx: &KProbeContext) -> Result<u32, i64> {
  let pid_tgid = bpf_get_current_pid_tgid();
  let cgroup_id = bpf_get_current_cgroup_id();

  if ALLOWLIST.get(&cgroup_id).is_some() {
    return Ok(0);
  }

  let sock: *const sock = ctx.arg(0).ok_or(1i64)?;
  let sk_common = &(*sock).__sk_common;

  // Check against threat intelligence IPs
  if THREAT_INTEL_IPS.get(&sk_common.skc_daddr).is_some() {
    warn!("Data received from malicious IP");
    log_security_event(cgroup_id, SecurityEventType::MaliciousConnection);
  }

  // Emit TCP receive event
  let event = NetEvent {
    timestamp_ns: bpf_ktime_get_ns(),
    pid: pid_tgid as u32,
    tgid: (pid_tgid >> 32) as u32,
    cgroup_id,
    saddr: sk_common.skc_rcv_saddr,
    daddr: sk_common.skc_daddr,
    sport: sk_common.skc_num,
    dport: u16::from_be(sk_common.skc_dport),
    family: sk_common.skc_family,
    protocol: 6, // TCP
    kind: EventKind::TcpRecv,
    data_size: 0, // Could be passed as argument in future
  };

  if let Some(mut slot) = NET_EVENTS.reserve::<NetEvent>(0) {
    slot.write(event);
    slot.submit(0);
  }

  update_cgroup_stats(cgroup_id, SyscallType::Network);
  Ok(0)
}

// ───────────────────────────────────────────────────────────────────────────
// 4. SECURITY ENFORCEMENT (LSM Hooks)
// ───────────────────────────────────────────────────────────────────────────

#[lsm(hook = "bprm_check_security")]
pub fn lprm_check_security(ctx: LsmContext) -> i32 {
    match unsafe { try_bprm_check(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "socket_connect")]
pub fn lsm_socket_connect(ctx: LsmContext) -> i32 {
    match unsafe { try_socket_connect_lsm(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "file_open")]
pub fn lsm_file_open(ctx: LsmContext) -> i32 {
    match unsafe { try_file_open_lsm(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bprm_check(_ctx: &LsmContext) -> Result<i32, i32> {
    let cgroup_id = bpf_get_current_cgroup_id();

    // Check denylist
    if DENYLIST.get(&cgroup_id).is_some() {
        return Err(-1); // EPERM
    }

    // Check seccomp-style policy
    if let Some(syscalls) = CGROUP_SYSCALLS.get(&cgroup_id) {
        if (*syscalls & SYSCALL_EXECVE) == 0 {
            return Err(-1); // exec not allowed
        }
    }

    Ok(0)
}

unsafe fn try_socket_connect_lsm(_ctx: &LsmContext) -> Result<i32, i32> {
    let cgroup_id = bpf_get_current_cgroup_id();

    if DENYLIST.get(&cgroup_id).is_some() {
        return Err(-1);
    }

    Ok(0)
}

unsafe fn try_file_open_lsm(_ctx: &LsmContext) -> Result<i32, i32> {
    let cgroup_id = bpf_get_current_cgroup_id();

    if DENYLIST.get(&cgroup_id).is_some() {
        return Err(-1);
    }

    Ok(0)
}

// ───────────────────────────────────────────────────────────────────────────
// 5. PACKET FILTERING (XDP)
// ───────────────────────────────────────────────────────────────────────────

#[xdp(name = "scanner_xdp")]
pub fn scanner_xdp(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp(&ctx) } {
        Ok(ret) => ret,
        Err(_) => XDP_PASS,
    }
}

unsafe fn try_xdp(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + 20 > data_end {
        return Ok(XDP_PASS);
    }

    let ip_header = data as *const u8;
    let version_ihl = *ip_header;
    let version = version_ihl >> 4;

    if version != 4 {
        return Ok(XDP_PASS);
    }

    // Parse IP header
    let ihl = (version_ihl & 0x0F) * 4;
    if data + ihl as usize > data_end {
        return Ok(XDP_PASS);
    }

    let src_ip = u32::from_be(*((ip_header as *const u32).add(3)));
    let _dst_ip = u32::from_be(*((ip_header as *const u32).add(4)));

    // Check blocked IPs
    if XDP_BLOCKED_IPS.get(&src_ip).is_some() {
        info!("XDP: Dropping packet from blocked IP");
        return Ok(XDP_DROP);
    }

    // Check threat intel
    if THREAT_INTEL_IPS.get(&src_ip).is_some() {
        warn!("XDP: Threat intel match");
        return Ok(XDP_DROP);
    }

    Ok(XDP_PASS)
}

// ───────────────────────────────────────────────────────────────────────────
// HELPER FUNCTIONS
// ───────────────────────────────────────────────────────────────────────────

unsafe fn is_shared_library(path: &[u8]) -> bool {
    let len = path_len(path);
    if len < 3 {
        return false;
    }
    // Check for .so
    path[len - 3] == b'.' && path[len - 2] == b's' && path[len - 1] == b'o'
}

unsafe fn path_len(path: &[u8]) -> usize {
    for (i, &byte) in path.iter().enumerate() {
        if byte == 0 {
            return i;
        }
    }
    path.len()
}

unsafe fn is_suspicious_command(cmd: &[u8]) -> bool {
  // Check for common attack patterns
  // Compare byte slices directly
  if starts_with(cmd, b"nc -e ") {
    return true;
  }
  if starts_with(cmd, b"bash -i") {
    return true;
  }
  if starts_with(cmd, b"python") {
    return true;
  }
  false
}
    }
    false
}

unsafe fn starts_with(s: &[u8], prefix: &[u8]) -> bool {
    for (i, &b) in prefix.iter().enumerate() {
        if b == 0 {
            break;
        }
        if i >= s.len() || s[i] != b {
            return false;
        }
    }
    true
}

unsafe fn should_monitor_file(path: &[u8]) -> bool {
  // Monitor sensitive paths
  let sensitive: &[&[u8]] = &[
    b"/etc/passwd",
    b"/etc/shadow",
    b"/etc/ssl",
    b"/usr/bin",
  ];

  for s in sensitive {
    if starts_with(path, s) {
      return true;
    }
  }
  false
}

unsafe fn update_file_cache(path: &[u8]) {
    let hash = hash_path(path);
    let now = bpf_ktime_get_ns();

    if let Some(entry) = FILE_CACHE.get_mut(&hash) {
        entry.last_access_ns = now;
        entry.access_count += 1;
    } else {
        let entry = FileCacheEntry {
            path_hash: hash,
            first_seen_ns: now,
            last_access_ns: now,
            access_count: 1,
            modified: 0,
        };
        let _ = FILE_CACHE.insert(&hash, &entry, 0);
    }
}

unsafe fn track_library_load(pid: u32, path: &[u8]) -> Result<(), i64> {
    let hash = hash_path(path);
    let entry = LibraryMapping {
        pid,
        lib_hash: hash,
        loaded_ns: bpf_ktime_get_ns(),
    };
    let _ = LIBRARY_MAP.insert(&pid, &entry, 0);
    Ok(())
}

unsafe fn update_cgroup_stats(cgroup_id: u64, syscall_type: SyscallType) {
    if let Some(stats) = CGROUP_STATS.get_mut(&cgroup_id) {
        stats.last_seen_ns = bpf_ktime_get_ns();
        match syscall_type {
            SyscallType::Exec => stats.exec_count += 1,
            SyscallType::File => stats.file_open_count += 1,
            SyscallType::Network => stats.connect_count += 1,
        }
    } else {
        let stats = CgroupStats {
            cgroup_id,
            exec_count: if syscall_type == SyscallType::Exec {
                1
            } else {
                0
            },
            file_open_count: if syscall_type == SyscallType::File {
                1
            } else {
                0
            },
            mmap_count: 0,
            connect_count: if syscall_type == SyscallType::Network {
                1
            } else {
                0
            },
            bind_count: 0,
            first_seen_ns: bpf_ktime_get_ns(),
            last_seen_ns: bpf_ktime_get_ns(),
        };
        let _ = CGROUP_STATS.insert(&cgroup_id, &stats, 0);
    }
}

unsafe fn log_security_event(cgroup_id: u64, event_type: SecurityEventType) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let event = SecurityEvent {
        timestamp_ns: bpf_ktime_get_ns(),
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        cgroup_id,
        event_type: event_type as u32,
        severity: 2, // High
    };

    if let Some(mut slot) = SECURITY_EVENTS.reserve::<SecurityEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }
}

unsafe fn hash_path(path: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in path.iter() {
        if byte == 0 {
            break;
        }
        hash = ((hash << 5) + hash) + (byte as u32);
    }
    hash
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyscallType {
    Exec,
    File,
    Network,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecurityEventType {
  SuspiciousExec = 1,
  MaliciousConnection = 2,
  FileTampering = 3,
  PolicyViolation = 4,
  LargeDataTransfer = 5,
  LibraryLoad = 6,
}

// Constants
const XDP_ABORTED: u32 = 0;
const XDP_DROP: u32 = 1;
const XDP_PASS: u32 = 2;
const XDP_TX: u32 = 3;
const XDP_REDIRECT: u32 = 4;

const CONN_ESTABLISHED: u8 = 1;

const SYSCALL_EXECVE: u64 = 1 << 0;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
static LICENSE: &[u8] = b"GPL\0";
