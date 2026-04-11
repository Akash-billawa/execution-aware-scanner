// LSM (Linux Security Modules) hook helpers
// Note: LSM requires CONFIG_BPF_LSM=y in kernel config

// Security hook return values
pub const LSM_RET_ALLOW: i32 = 0;
pub const LSM_RET_DENY: i32 = -1;
pub const LSM_RET_NOOP: i32 = -2;

// Security events that can be triggered by LSM hooks
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum SecurityHook {
    FileOpen = 1,
    FilePermission = 2,
    SocketCreate = 3,
    SocketConnect = 4,
    SocketBind = 5,
    SocketListen = 6,
    SocketAccept = 7,
    SocketSendmsg = 8,
    SocketRecvmsg = 9,
    BprmCheckSecurity = 10,
    BprmCommittingCreds = 11,
    TaskAlloc = 12,
    TaskFree = 13,
    CredPrepare = 14,
    CredTransfer = 15,
    Sysctl = 16,
    IpcPermission = 17,
    MsgQueueAllocSecurity = 18,
    ShmAllocSecurity = 19,
}

// Security context flags
pub const SECCTX_FLAG_NEW_EXEC: u32 = 1 << 0;
pub const SECCTX_FLAG_FORK: u32 = 1 << 1;
pub const SECCTX_FLAG_CLONE: u32 = 1 << 2;
pub const SECCTX_FLAG_PRIVILEGED: u32 = 1 << 3;

// Helper to log security events
#[inline]
pub unsafe fn log_security_event(
    hook: SecurityHook,
    cgroup_id: u64,
    pid: u32,
    action: u8,
) {
    use crate::events::SecurityEvent;
    use crate::maps::SECURITY_EVENTS;
    use aya_bpf::helpers::bpf_ktime_get_ns;

    let event = SecurityEvent {
        timestamp_ns: bpf_ktime_get_ns(),
        pid,
        tgid: pid, // Simplified
        cgroup_id,
        kind: match hook {
            SecurityHook::BprmCheckSecurity => crate::events::EventKind::SecurityDeny,
            _ => crate::events::EventKind::SecurityAllow,
        },
        resource_id: hook as u64,
        action,
    };

    if let Some(mut slot) = SECURITY_EVENTS.reserve::<SecurityEvent>(0) {
        slot.write(event);
        slot.submit(0);
    }
}

// Check if LSM is supported
#[inline]
pub fn lsm_supported() -> bool {
    // This is checked at load time
    true
}

// Enforce policy based on cgroup allowlist/denylist
#[inline]
pub unsafe fn enforce_cgroup_policy(cgroup_id: u64, resource_id: u64) -> i32 {
    use crate::maps::{ALLOWLIST, DENYLIST};

    // Check denylist first (deny takes precedence)
    if DENYLIST.get(&cgroup_id).is_some() {
        return LSM_RET_DENY;
    }

    // Check allowlist
    if ALLOWLIST.get(&cgroup_id).is_some() {
        return LSM_RET_ALLOW;
    }

    // Default: allow if no policy set
    LSM_RET_ALLOW
}
