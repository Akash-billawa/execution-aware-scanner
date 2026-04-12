#![no_std]
#![no_main]

//! eBPF Scanner - Production-grade runtime security
//!
//! Architecture:
//! - tracepoints.rs: Syscall monitoring (execve, openat, mmap)
//! - kprobes.rs: Kernel function hooks (tcp_connect, socket operations)
//! - xdp.rs: Network packet filtering
//! - lsm.rs: Security module hooks
//! - maps.rs: eBPF maps (RingBuf for events, HashMaps for state)
//! - events.rs: Event types and structures
//! - common.rs: Shared utilities

// Module declarations
mod common;
mod events;
mod kprobes;
mod maps;
mod tracepoints;

// Re-export for use by probe handlers
pub use common::*;
pub use events::*;
pub use kprobes::*;
pub use maps::*;
pub use tracepoints::*;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
