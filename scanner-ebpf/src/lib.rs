#![no_std]
#![no_main]

// Minimal eBPF scanner for aya-ebpf 0.1.1
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, map, tracepoint},
    maps::PerfEventArray,
    programs::{ProbeContext, TracePointContext},
};

// Simple event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub timestamp_ns: u64,
    pub pid: u32,
}

// Event output map
#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

// Tracepoint: execve syscall
#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn trace_execve(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();

    let event = Event {
        timestamp_ns: bpf_ktime_get_ns(),
        pid: pid_tgid as u32,
    };

    unsafe {
        EVENTS.output(&event, 0);
    }

    0
}

// Kprobe: TCP connect
#[kprobe(name = "tcp_v4_connect")]
pub fn trace_tcp_connect(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();

    let event = Event {
        timestamp_ns: bpf_ktime_get_ns(),
        pid: pid_tgid as u32,
    };

    unsafe {
        EVENTS.output(&event, 0);
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
