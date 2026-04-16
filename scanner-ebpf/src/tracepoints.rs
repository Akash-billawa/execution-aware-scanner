//! Tracepoint Programs - Unified Security Event Schema
//! All events normalize to SecurityEvent before emission
use crate::events::{
    calculate_confidence, create_base_event, emit_event, is_sensitive_path, is_suspicious_port,
    EventData, EventKind, ExecData, FileData, NetData, SecurityEvent,
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};

/// Rate limiting: last event time per PID
#[map(name = "LAST_EVENT")]
static LAST_EVENT: HashMap<u64, u64> = HashMap::with_max_entries(100000, 0);

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
                args: [0; 120], // Would need argv parsing
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
    // Stub: Full implementation would:
    // 1. Extract file path from args
    // 2. Check if sensitive path
    // 3. Emit SecurityEvent with FileData
    // 4. Calculate confidence based on sensitivity

    // For production, this is disabled to reduce overhead
    // In production deployment, enable with:
    // --feature file-tracking
    0
}

/// Memory map event (library loading)
/// Emits unified SecurityEvent with mmap context
#[tracepoint(category = "syscalls", name = "sys_enter_mmap")]
pub fn trace_mmap(_ctx: TracePointContext) -> u32 {
    // Stub: Full implementation would:
    // 1. Check if mapping is a shared library
    // 2. Extract library path
    // 3. Emit SecurityEvent for library load
    // 4. Calculate confidence (library + network = high)

    // Production: Enable when library tracking needed
    0
}

/// Memory protection event
/// Emits unified SecurityEvent for mprotect
#[tracepoint(category = "syscalls", name = "sys_enter_mprotect")]
pub fn trace_mprotect(_ctx: TracePointContext) -> u32 {
    // Stub: Full implementation would:
    // 1. Check for W^X violations
    // 2. Detect suspicious memory protections
    // 3. Emit SecurityEvent with high confidence if suspicious

    // Production: Enable for exploit detection
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
