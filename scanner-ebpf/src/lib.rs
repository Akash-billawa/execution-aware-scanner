#![no_std]
#![no_main]

//! eBPF Scanner - Production-grade runtime security
//!
//! Architecture:
//! - events.rs: Unified SecurityEvent schema
//! - tracepoints.rs: Syscall monitoring (execve, openat, mmap, mprotect, network syscalls)
//! - kprobes.rs: Kernel function hooks (tcp_connect, socket operations)
//! - process.rs: Process context tracking (PID → metadata)
//! - libraries.rs: Library loading detection (.so tracking)
//! - network.rs: Network intelligence (connections, transfers)

// Module declarations
mod events;
mod kprobes;
mod libraries;
mod network;
mod process;
mod tracepoints;

// Re-export for use by probe handlers
pub use events::*;
pub use kprobes::*;
pub use libraries::*;
pub use network::*;
pub use process::*;
pub use tracepoints::*;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
