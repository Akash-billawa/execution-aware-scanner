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
pub static mut LOADED_LIBRARIES: HashMap<u64, LibraryLoad> = HashMap::with_max_entries(50000, 0);

/// Track unique libraries per process (deduplication)
#[map(name = "LIBRARY_SEEN")]
pub static mut LIBRARY_SEEN: HashMap<u64, u64> = HashMap::with_max_entries(100000, 0);

/// security_file_open hook - detects library loads
#[kprobe(function = "security_file_open")]
pub fn trace_security_file_open(ctx: ProbeContext) -> i32 {
    unsafe { try_file_open(&ctx) };
    0
}

/// do_mmap hook for library detection via mmap
#[kprobe(function = "do_mmap")]
pub fn trace_do_mmap(ctx: ProbeContext) -> i32 {
    unsafe { try_mmap_library(&ctx) };
    0
}

unsafe fn try_file_open(ctx: &ProbeContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    // For simplicity, we detect library loads by tracking mmap calls
    // In production, you'd parse the filename from struct file*
    info!(ctx, "FILE_OPEN: pid={}", pid);
    0
}

unsafe fn try_mmap_library(ctx: &ProbeContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = bpf_get_current_cgroup_id();
    let pid = pid_tgid as u32;

    // Track this as a potential library load
    let path_hash = 0u32; // Simplified - would hash actual path
    let key = ((pid as u64) << 32) | (path_hash as u64);

    // Check if we've seen this library for this process
    let now = bpf_ktime_get_ns();
    if unsafe { LIBRARY_SEEN.get(&key) }.is_none() {
        // First time seeing this library
        let load = LibraryLoad {
            timestamp_ns: now,
            pid,
            cgroup_id,
            path_hash,
        };

        let _ = unsafe { LOADED_LIBRARIES.insert(&key, &load, 0) };
        let _ = unsafe { LIBRARY_SEEN.insert(&key, &now, 0) };

        info!(ctx, "LIBRARY_LOAD: pid={}", pid);
    }

    0
}

/// Get loaded libraries for a process
pub unsafe fn get_loaded_libraries(pid: u32) -> u32 {
    let mut count = 0u32;
    // Simplified - would iterate map
    count
}
