//! USDT (User Statically-Defined Tracing) Probes
//!
//! Provides function-level tracing for user-space applications.
//! Targets high-value functions for security monitoring:
//! - libssl: SSL_write/SSL_read (encrypted exfiltration)
//! - libc: malloc/free (heap spray detection)
//! - libcurl: curl_easy_perform (HTTP C2 detection)

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_ktime_get_ns,
    },
    macros::uprobe,
    programs::ProbeContext,
};

use crate::events::{EventKind, SecurityEvent, SECURITY_EVENTS};

/// Helper to create a base security event
fn create_base_event(kind: EventKind) -> SecurityEvent {
    let mut event = SecurityEvent {
        ts: unsafe { bpf_ktime_get_ns() },
        kind,
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        tgid: bpf_get_current_pid_tgid() as u32,
        uid: 0,
        gid: 0,
        cgroup_id: bpf_get_current_cgroup_id(),
        confidence: 70, // Higher confidence for function-level traces
        data: crate::events::EventData { raw: [0; 128] },
        comm: [0; 16],
    };

    if let Ok(name) = bpf_get_current_comm() {
        let len = name.len().min(16);
        event.comm[..len].copy_from_slice(&name[..len]);
    }

    event
}

/// Helper to write bytes into a fixed-size byte array
fn write_bytes(dest: &mut [u8], src: &[u8]) {
    let len = dest.len().min(src.len());
    dest[..len].copy_from_slice(&src[..len]);
}

// ── SSL_write probe ─────────────────────────────────────────────────────────

/// Probe attached to libssl SSL_write
/// Detects encrypted data exfiltration
#[uprobe]
pub fn probe_ssl_write(ctx: ProbeContext) -> u32 {
    match try_probe_ssl_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_probe_ssl_write(ctx: ProbeContext) -> Result<u32, u32> {
    let mut event = create_base_event(EventKind::Exec);

    // Mark this as a function trace event
    // The kind will be interpreted by user-space based on the function name
    let func_name = b"SSL_write";
    // SAFETY: ExecData.args is at the same offset as the raw data
    let args = unsafe { &mut event.data.exec.args };
    write_bytes(args, func_name);

    // Get the length argument (arg1 = number of bytes to write)
    let len: u64 = ctx.arg(2).ok_or(0u32)?;
    event.confidence = if len > 1024 * 1024 {
        90 // > 1MB is suspicious
    } else if len > 64 * 1024 {
        80 // > 64KB is notable
    } else {
        60
    };

    SECURITY_EVENTS.output(&event, 0);
    Ok(0)
}

// ── SSL_read probe ──────────────────────────────────────────────────────────

/// Probe attached to libssl SSL_read
#[uprobe]
pub fn probe_ssl_read(ctx: ProbeContext) -> u32 {
    match try_probe_ssl_read(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_probe_ssl_read(_ctx: ProbeContext) -> Result<u32, u32> {
    let mut event = create_base_event(EventKind::Exec);

    let func_name = b"SSL_read";
    let args = unsafe { &mut event.data.exec.args };
    write_bytes(args, func_name);

    SECURITY_EVENTS.output(&event, 0);
    Ok(0)
}

// ── malloc probe (heap spray detection) ─────────────────────────────────────

/// Probe attached to libc malloc
/// Detects heap spray attacks (many large allocations)
#[uprobe]
pub fn probe_malloc(ctx: ProbeContext) -> u32 {
    match try_probe_malloc(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_probe_malloc(ctx: ProbeContext) -> Result<u32, u32> {
    let size: u64 = ctx.arg(0).ok_or(0u32)?;

    // Only trace large allocations (> 1MB)
    if size < 1024 * 1024 {
        return Ok(0);
    }

    let mut event = create_base_event(EventKind::Exec);

    let func_name = b"malloc";
    let args = unsafe { &mut event.data.exec.args };
    write_bytes(args, func_name);

    event.confidence = if size > 100 * 1024 * 1024 {
        95 // > 100MB is very suspicious
    } else if size > 10 * 1024 * 1024 {
        85 // > 10MB is notable
    } else {
        70
    };

    SECURITY_EVENTS.output(&event, 0);
    Ok(0)
}

// ── curl_easy_perform probe (HTTP C2 detection) ─────────────────────────────

/// Probe attached to libcurl curl_easy_perform
/// Detects HTTP-based C2 communication
#[uprobe]
pub fn probe_curl_easy_perform(ctx: ProbeContext) -> u32 {
    match try_probe_curl_easy_perform(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_probe_curl_easy_perform(_ctx: ProbeContext) -> Result<u32, u32> {
    let mut event = create_base_event(EventKind::Exec);

    let func_name = b"curl_easy_perform";
    let args = unsafe { &mut event.data.exec.args };
    write_bytes(args, func_name);

    // curl usage from a container is noteworthy
    event.confidence = 65;

    SECURITY_EVENTS.output(&event, 0);
    Ok(0)
}
