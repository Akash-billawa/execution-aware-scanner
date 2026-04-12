#![allow(dead_code)]

/// Core security event types for the scanner
/// All events are #[repr(C)] for eBPF compatibility

/// Event classification
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    ProcessExec = 1,
    ProcessExit = 2,
    FileOpen = 3,
    FileMmap = 4,
    NetConnect = 5,
    NetSend = 6,
    NetRecv = 7,
    SecurityDeny = 8,
}

/// Unified security event structure
/// Fixed size, #[repr(C)] for eBPF compatibility
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecurityEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub event_type: u32,
    pub cgroup_id: u64,
    pub data: [u8; 256],
}

/// Process execution data
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecData {
    pub ppid: u32,
    pub command: [u8; 16],
}

/// File operation data
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileData {
    pub fd: i32,
    pub flags: u32,
    pub path: [u8; 240],
}

/// Network connection data
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetData {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub protocol: u8,
}

/// Memory mapping data
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MmapData {
    pub addr: u64,
    pub len: u64,
    pub prot: u32,
    pub flags: u32,
}

impl SecurityEvent {
    pub fn new(
        event_type: EventType,
        pid: u32,
        tgid: u32,
        uid: u32,
        gid: u32,
        cgroup_id: u64,
    ) -> Self {
        Self {
            timestamp_ns: 0,
            pid,
            tgid,
            uid,
            gid,
            event_type: event_type as u32,
            cgroup_id,
            data: [0; 256],
        }
    }

    pub fn with_exec_data(mut self, data: &ExecData) -> Self {
        self.data[..core::mem::size_of::<ExecData>()].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                data as *const _ as *const u8,
                core::mem::size_of::<ExecData>(),
            )
        });
        self
    }

    pub fn with_file_data(mut self, data: &FileData) -> Self {
        self.data[..core::mem::size_of::<FileData>()].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                data as *const _ as *const u8,
                core::mem::size_of::<FileData>(),
            )
        });
        self
    }

    pub fn with_net_data(mut self, data: &NetData) -> Self {
        self.data[..core::mem::size_of::<NetData>()].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                data as *const _ as *const u8,
                core::mem::size_of::<NetData>(),
            )
        });
        self
    }

    pub fn with_mmap_data(mut self, data: &MmapData) -> Self {
        self.data[..core::mem::size_of::<MmapData>()].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                data as *const _ as *const u8,
                core::mem::size_of::<MmapData>(),
            )
        });
        self
    }
}
