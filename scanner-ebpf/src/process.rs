/// Process Context Tracking
/// Stores rich process metadata for attack graph correlation
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::map,
    maps::HashMap,
};

/// Process metadata structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessInfo {
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub start_time_ns: u64,
    pub command: [u8; 16],
}

/// Process context map: PID -> ProcessInfo
#[map(name = "PROCESS_CONTEXT")]
static PROCESS_CONTEXT: HashMap<u32, ProcessInfo> = HashMap::with_max_entries(10240, 0);

/// Process parent tracking: PID -> Parent PID
#[map(name = "PROCESS_PARENT")]
static PROCESS_PARENT: HashMap<u32, u32> = HashMap::with_max_entries(10240, 0);

/// Track process creation with rich metadata
pub unsafe fn track_process(pid: u32, tgid: u32, ppid: u32) {
    let uid_gid = bpf_get_current_uid_gid();
    let cgroup_id = bpf_get_current_cgroup_id();

    // Get command name
    let command = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => [0u8; 16],
    };

    let info = ProcessInfo {
        pid,
        tgid,
        ppid,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        cgroup_id,
        start_time_ns: bpf_ktime_get_ns(),
        command,
    };

    // Store using pointer-safe pattern
    let key_ptr = &pid;
    let value_ptr = &info;
    let _ = PROCESS_CONTEXT.insert(key_ptr, value_ptr, 0);

    // Track parent relationship
    let ppid_ptr = &ppid;
    let _ = PROCESS_PARENT.insert(key_ptr, ppid_ptr, 0);
}

/// Get process info using pointer-safe pattern
pub unsafe fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    let key_ptr = &pid;
    PROCESS_CONTEXT.get_ptr(key_ptr).map(|ptr| *ptr)
}

/// Get parent PID
pub unsafe fn get_parent_pid(pid: u32) -> Option<u32> {
    let key_ptr = &pid;
    PROCESS_PARENT.get_ptr(key_ptr).map(|ptr| *ptr)
}

/// Get process ancestry (up to 3 levels)
/// Tracks visited PIDs to detect arbitrary cycles (e.g., A->B->A from PID recycling)
pub unsafe fn get_process_ancestry(pid: u32, ancestors: &mut [u32; 3]) -> u32 {
    let mut current = pid;
    let mut count = 0u32;
    let mut seen = [0u32; 4]; // track origin + up to 3 ancestors for cycle detection
    seen[0] = pid;

    for i in 0..3 {
        let key_ptr = &current;
        if let Some(ppid_ptr) = PROCESS_PARENT.get_ptr(key_ptr) {
            let ppid = *ppid_ptr;
            ancestors[i] = ppid;
            count += 1;
            current = ppid;

            // Stop at init or if we've already visited this PID (cycle)
            if ppid == 1 {
                break;
            }
            for j in 0..=i {
                if seen[j] == ppid {
                    return count;
                }
            }
            seen[i + 1] = ppid;
        } else {
            break;
        }
    }

    count
}
