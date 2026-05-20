/// Library Loading Detection
/// Production-grade eBPF with verifier-safe patterns
use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};

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
/// Max 50k entries to prevent memory exhaustion
#[map(name = "LOADED_LIBRARIES")]
static LOADED_LIBRARIES: HashMap<u64, LibraryLoad> = HashMap::with_max_entries(50000, 0);

/// Track unique libraries per process (deduplication)
/// Max 100k entries for deduplication tracking
#[map(name = "LIBRARY_SEEN")]
static LIBRARY_SEEN: HashMap<u64, u64> = HashMap::with_max_entries(100000, 0);

/// Per-PID library load count
#[map(name = "LIBRARY_COUNT")]
static LIBRARY_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(10240, 0);

/// do_mmap hook for library detection via mmap
/// SAFETY: All map operations are verified by the eBPF verifier
#[kprobe(function = "do_mmap")]
pub fn trace_do_mmap(ctx: ProbeContext) -> i32 {
    // Get process context
    let pid_tgid = bpf_get_current_pid_tgid();
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let pid = pid_tgid as u32;

    // Use mmap target address as a differentiator for library loads.
    // arg(0) = addr (requested start address). Different libraries map at
    // different addresses, giving us a per-load unique key within a process.
    let addr = ctx.arg::<usize>(0).unwrap_or(0);
    let path_hash = (addr & 0xFFFF_FFFF) as u32;

    let key = ((pid as u64) << 32) | (path_hash as u64);

    // Check if we've seen this library for this process
    // SAFETY: Map lookup is verified by the eBPF verifier
    let already_seen = unsafe { LIBRARY_SEEN.get(&key) }.is_some();

    if already_seen {
        return 0;
    }

    // First time seeing this library - record it
    let now = unsafe { bpf_ktime_get_ns() };

    // Create library load event
    let load = LibraryLoad {
        timestamp_ns: now,
        pid,
        cgroup_id,
        path_hash,
    };

    // SAFETY: Map inserts are verified by the eBPF verifier
    // These are best-effort - ignore errors if map is full
    let _ = LIBRARY_SEEN.insert(&key, &now, 0);
    let _ = LOADED_LIBRARIES.insert(&key, &load, 0);

    // Increment per-PID library count
    let count = unsafe { LIBRARY_COUNT.get(&pid) }
        .map(|c| c.wrapping_add(1))
        .unwrap_or(1);
    let _ = LIBRARY_COUNT.insert(&pid, &count, 0);

    0
}

/// Get loaded libraries for a process
/// Returns count of libraries for this PID from the per-PID counter map
#[inline(always)]
pub fn get_loaded_libraries(pid: u32) -> u32 {
    unsafe { LIBRARY_COUNT.get(&pid).copied().unwrap_or(0) }
}
