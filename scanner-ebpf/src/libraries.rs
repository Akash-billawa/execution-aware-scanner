/// Library Loading Detection
/// Tracks shared library loads for CVE correlation
use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

/// Library load event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LibraryLoad {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub cgroup_id: u64,
    pub path_hash: u32,
}

/// Loaded libraries: composite_key -> LibraryLoad
/// Key: (pid << 32) | path_hash
#[map(name = "LOADED_LIBRARIES")]
static mut LOADED_LIBRARIES: HashMap<u64, LibraryLoad> = HashMap::with_max_entries(50000, 0);

/// Track unique libraries per process (deduplication)
#[map(name = "LIBRARY_SEEN")]
static mut LIBRARY_SEEN: HashMap<u64, u64> = HashMap::with_max_entries(100000, 0);

/// do_mmap hook for library detection via mmap
#[kprobe(function = "do_mmap")]
pub fn trace_do_mmap(ctx: ProbeContext) -> i32 {
    unsafe { try_mmap_library(&ctx) };
    0
}

unsafe fn try_mmap_library(ctx: &ProbeContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    // Track this as a potential library load
    let path_hash = 0u32; // Simplified - would hash actual path
    let key = ((pid as u64) << 32) | (path_hash as u64);

    // Check if we've seen this library for this process using pointer-safe pattern
    let key_ptr = &key;
    let seen_before = LIBRARY_SEEN.get_ptr(key_ptr).is_some();

    if !seen_before {
        // First time seeing this library
        let now = bpf_ktime_get_ns();
        let load = LibraryLoad {
            timestamp_ns: now,
            pid,
            cgroup_id,
            path_hash,
        };

        let load_ptr = &load;
        let time_ptr = &now;
        let _ = LIBRARY_SEEN.insert(key_ptr, time_ptr, 0);
        let _ = LOADED_LIBRARIES.insert(key_ptr, load_ptr, 0);

        info!(ctx, "LIBRARY_LOAD: pid={}", pid);
    }

    0
}

/// Get loaded libraries for a process
pub unsafe fn get_loaded_libraries(pid: u32) -> u32 {
    // Simplified - would iterate map
    0
}
