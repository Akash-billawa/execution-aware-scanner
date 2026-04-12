/// LSM (Linux Security Modules) Programs
/// Security hooks for access control decisions
use aya_ebpf::{macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;

use crate::common::*;
use crate::maps::*;

/// Socket connect hook
#[lsm(hook = "socket_connect")]
pub fn lsm_socket_connect(ctx: LsmContext) -> i32 {
    unsafe { try_socket_connect(&ctx) }
}

/// File open hook
#[lsm(hook = "file_open")]
pub fn lsm_file_open(ctx: LsmContext) -> i32 {
    unsafe { try_file_open(&ctx) }
}

/// Socket create hook
#[lsm(hook = "socket_create")]
pub fn lsm_socket_create(ctx: LsmContext) -> i32 {
    unsafe { try_socket_create(&ctx) }
}

unsafe fn try_socket_connect(ctx: &LsmContext) -> i32 {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    // Check denylist
    if unsafe { DENYLIST.get(&cgroup_id) }.is_some() {
        info!(ctx, "LSM: Denying socket connect for pid={}", pid);
        return -1; // Deny
    }

    0 // Allow
}

unsafe fn try_file_open(ctx: &LsmContext) -> i32 {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    if unsafe { DENYLIST.get(&cgroup_id) }.is_some() {
        info!(ctx, "LSM: Denying file open for pid={}", pid);
        return -1;
    }

    0
}

unsafe fn try_socket_create(ctx: &LsmContext) -> i32 {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    if unsafe { DENYLIST.get(&cgroup_id) }.is_some() {
        info!(ctx, "LSM: Denying socket create for pid={}", pid);
        return -1;
    }

    0
}
