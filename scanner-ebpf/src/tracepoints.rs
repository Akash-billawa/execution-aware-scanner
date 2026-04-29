//! Tracepoint Programs - Unified Security Event Schema
//! All events normalize to SecurityEvent before emission
use crate::events::{
    calculate_confidence, create_base_event, emit_event, is_sensitive_path, is_suspicious_port,
    EventData, EventKind, ExecData, FileData, NetData, SecurityEvent,
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};

/// Rate limiting: last event time per PID
#[map(name = "LAST_EVENT")]
static LAST_EVENT: HashMap<u64, u64> = HashMap::with_max_entries(100000, 0);

const AF_INET: u16 = 2;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    _zero: [u8; 8],
}

#[inline(always)]
fn read_sockaddr_in(ptr: *const SockAddrIn) -> Option<SockAddrIn> {
    if ptr.is_null() {
        return None;
    }

    match unsafe { bpf_probe_read_user(ptr) } {
        Ok(addr) if addr.sin_family == AF_INET => Some(addr),
        _ => None,
    }
}

#[inline(always)]
fn emit_net_event(kind: EventKind, addr: Option<SockAddrIn>, protocol: u8, bytes: u64) {
    let daddr = addr.map(|a| a.sin_addr).unwrap_or(0);
    let dport = addr.map(|a| u16::from_be(a.sin_port)).unwrap_or(0);
    let is_external = crate::events::is_external_ip(daddr);
    let is_suspicious = is_suspicious_port(dport);

    let mut base = create_base_event(kind);
    base.confidence = if is_suspicious && is_external {
        90
    } else {
        calculate_confidence(kind, false, daddr != 0 || bytes > 0, false)
    };
    base.data = EventData {
        net: NetData {
            saddr: 0,
            daddr,
            sport: 0,
            dport,
            bytes,
            protocol,
            is_external: is_external as u8,
            is_suspicious_port: is_suspicious as u8,
            _pad: [0; 101],
        },
    };

    emit_event(base);
}

/// Process execution entry
/// Emits unified SecurityEvent with all context pre-filled
#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn trace_enter_execve(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let pid = pid_tgid as u32;

    // Rate limiting: max 1 event per second per PID
    let now = unsafe { bpf_ktime_get_ns() };
    let pid_u64 = pid as u64;

    let should_emit = unsafe {
        match LAST_EVENT.get(&pid_u64) {
            Some(last) => now.saturating_sub(*last) > 1_000_000_000, // 1 second
            None => true,
        }
    };

    if !should_emit {
        return 0;
    }

    // Update rate limit timestamp
    let _ = LAST_EVENT.insert(&pid_u64, &now, 0);

    // Get command name
    let mut comm = [0u8; 16];
    if let Ok(name) = bpf_get_current_comm() {
        let len = name.len().min(16);
        comm[..len].copy_from_slice(&name[..len]);
    }

    // Calculate confidence
    // For exec: base 50 + setuid check (simplified to 10 for now)
    let confidence = 60;

    let mut args = [0u8; 120];
    if let Ok(filename_ptr) = unsafe { _ctx.read_at::<*const u8>(16) } {
        if !filename_ptr.is_null() {
            let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut args) };
        }
    }

    // Create unified event
    let event = SecurityEvent {
        ts: now,
        kind: EventKind::Exec,
        pid,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        cgroup_id,
        confidence,
        data: EventData {
            exec: ExecData {
                ppid: 0,      // Would need parent PID lookup
                is_setuid: 0, // Would need stat check
                _pad: [0; 3],
                args,
            },
        },
        comm,
    };

    // Emit event with kernel-side confidence
    emit_event(event);
    0
}

/// File open event
/// Emits unified SecurityEvent with file context
#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn trace_openat(_ctx: TracePointContext) -> u32 {
    let filename_ptr = match unsafe { _ctx.read_at::<*const u8>(24) } {
        Ok(ptr) if !ptr.is_null() => ptr,
        _ => return 0,
    };

    let flags = unsafe { _ctx.read_at::<u32>(32) }.unwrap_or(0);
    let mut path = [0u8; 96];
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut path) };
    let is_sensitive = is_sensitive_path(&path);

    let mut base = create_base_event(EventKind::File);
    base.confidence = calculate_confidence(EventKind::File, false, false, is_sensitive);
    base.data = EventData {
        file: FileData {
            path,
            flags,
            is_sensitive: is_sensitive as u8,
            _pad: [0; 27],
        },
    };

    emit_event(base);
    0
}

/// Memory map event (library loading)
/// Emits unified SecurityEvent with mmap context
#[tracepoint(category = "syscalls", name = "sys_enter_mmap")]
pub fn trace_mmap(_ctx: TracePointContext) -> u32 {
    let mut base = create_base_event(EventKind::Mmap);
    base.confidence = calculate_confidence(EventKind::Mmap, true, false, false);
    base.data = EventData {
        file: FileData {
            path: [0; 96],
            flags: unsafe { _ctx.read_at::<u32>(40) }.unwrap_or(0),
            is_sensitive: 0,
            _pad: [0; 27],
        },
    };

    emit_event(base);
    0
}

/// Memory protection event
/// Emits unified SecurityEvent for mprotect
#[tracepoint(category = "syscalls", name = "sys_enter_mprotect")]
pub fn trace_mprotect(_ctx: TracePointContext) -> u32 {
    let prot = unsafe { _ctx.read_at::<u32>(32) }.unwrap_or(0);
    let writable = (prot & 0x2) != 0;
    let executable = (prot & 0x4) != 0;

    let mut base = create_base_event(if writable && executable {
        EventKind::Suspicious
    } else {
        EventKind::Mmap
    });
    base.confidence = if writable && executable { 90 } else { 55 };
    base.data = EventData {
        file: FileData {
            path: [0; 96],
            flags: prot,
            is_sensitive: (writable && executable) as u8,
            _pad: [0; 27],
        },
    };

    emit_event(base);
    0
}

/// Network connect event with IPv4 destination extraction.
#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn trace_connect(_ctx: TracePointContext) -> u32 {
    let sockaddr_ptr =
        unsafe { _ctx.read_at::<*const SockAddrIn>(24) }.unwrap_or(core::ptr::null());
    let addr = read_sockaddr_in(sockaddr_ptr);
    emit_net_event(EventKind::Connect, addr, IPPROTO_TCP, 0);
    0
}

/// Network send event from sendto with optional IPv4 destination.
#[tracepoint(category = "syscalls", name = "sys_enter_sendto")]
pub fn trace_sendto(_ctx: TracePointContext) -> u32 {
    let bytes = unsafe { _ctx.read_at::<usize>(32) }.unwrap_or(0) as u64;
    let sockaddr_ptr =
        unsafe { _ctx.read_at::<*const SockAddrIn>(48) }.unwrap_or(core::ptr::null());
    let addr = read_sockaddr_in(sockaddr_ptr);
    emit_net_event(EventKind::NetTransfer, addr, IPPROTO_UDP, bytes);
    0
}

/// Network receive event from recvfrom with optional IPv4 peer.
#[tracepoint(category = "syscalls", name = "sys_enter_recvfrom")]
pub fn trace_recvfrom(_ctx: TracePointContext) -> u32 {
    let bytes = unsafe { _ctx.read_at::<usize>(32) }.unwrap_or(0) as u64;
    let sockaddr_ptr =
        unsafe { _ctx.read_at::<*const SockAddrIn>(48) }.unwrap_or(core::ptr::null());
    let addr = read_sockaddr_in(sockaddr_ptr);
    emit_net_event(EventKind::NetTransfer, addr, IPPROTO_UDP, bytes);
    0
}

/// Example: How to emit a file event with full context
#[allow(dead_code)]
pub fn emit_file_event_example(path: &[u8], flags: u32) {
    let mut base = create_base_event(EventKind::File);

    // Calculate kernel-side confidence
    let is_sensitive = is_sensitive_path(path);
    base.confidence = calculate_confidence(EventKind::File, true, false, is_sensitive);

    // Populate file data
    let mut path_buf = [0u8; 96];
    let len = path.len().min(96);
    path_buf[..len].copy_from_slice(&path[..len]);

    base.data = EventData {
        file: FileData {
            path: path_buf,
            flags,
            is_sensitive: is_sensitive as u8,
            _pad: [0; 27],
        },
    };

    emit_event(base);
}

/// Example: How to emit a network event with full context
#[allow(dead_code)]
pub fn emit_network_event_example(saddr: u32, daddr: u32, sport: u16, dport: u16) {
    let mut base = create_base_event(EventKind::Connect);

    // Calculate kernel-side confidence
    let is_suspicious = is_suspicious_port(dport);
    let is_external = crate::events::is_external_ip(daddr);
    let confidence = if is_suspicious && is_external { 90 } else { 50 };
    base.confidence = confidence;

    // Populate network data
    base.data = EventData {
        net: NetData {
            saddr,
            daddr,
            sport,
            dport,
            bytes: 0,
            protocol: 6, // TCP
            is_external: is_external as u8,
            is_suspicious_port: is_suspicious as u8,
            _pad: [0; 101],
        },
    };

    emit_event(base);
}
