#![no_std]
#![no_main]

//! eBPF Scanner - Production-grade runtime security
//!
//! Architecture:
//! - tracepoints.rs: Syscall monitoring (execve, openat, mmap)
//! - kprobes.rs: Kernel function hooks (tcp_connect, socket operations)

// Module declarations
mod kprobes;
mod tracepoints;

// Re-export for use by probe handlers
pub use kprobes::*;
pub use tracepoints::*;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
