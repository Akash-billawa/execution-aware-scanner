// Event types shared between kernel and userspace

pub const ARGS_LEN: usize = 256;
pub const PATH_LEN: usize = 256;
pub const CMD_LEN: usize = 16;

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum EventKind {
    Exec = 1,
    Mmap = 2,
    Open = 3,
    Connect = 4,
    Bind = 5,
    Close = 6,
    UdpSend = 7,
    UdpRecv = 8,
    Mprotect = 9,
    SecurityDeny = 10,
    SecurityAllow = 11,
}

impl EventKind {
    pub fn is_network(&self) -> bool {
        matches!(
            self,
            EventKind::Connect | EventKind::Bind | EventKind::Close | EventKind::UdpSend | EventKind::UdpRecv
        )
    }

    pub fn is_file(&self) -> bool {
        matches!(self, EventKind::Open | EventKind::Mmap | EventKind::Mprotect)
    }

    pub fn is_exec(&self) -> bool {
        matches!(self, EventKind::Exec)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExecEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub ppid: u32,
    pub command: [u8; CMD_LEN],
    pub argv: [u8; ARGS_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub command: [u8; CMD_LEN],
    pub path: [u8; PATH_LEN],
    pub kind: EventKind,
    pub prot: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub protocol: u8,
    pub kind: EventKind,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SecurityEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub kind: EventKind,
    pub resource_id: u64,
    pub action: u8, // 0 = deny, 1 = allow
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileCacheEntry {
    pub path_hash: u32,
    pub first_seen_ns: u64,
    pub last_access_ns: u64,
    pub access_count: u64,
    pub modified: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectionEntry {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub state: u8, // 0 = SYN_SENT, 1 = ESTABLISHED, 2 = CLOSED
    pub created_ns: u64,
    pub last_activity_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CgroupStats {
    pub cgroup_id: u64,
    pub exec_count: u64,
    pub file_open_count: u64,
    pub mmap_count: u64,
    pub connect_count: u64,
    pub bind_count: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

// Helper functions for string operations in eBPF
pub unsafe fn copy_from_user_str(src: *const u8, dst: &mut [u8]) -> usize {
    let mut i = 0;
    while i < dst.len() {
        let byte = *src.add(i);
        dst[i] = byte;
        if byte == 0 {
            break;
        }
        i += 1;
    }
    i
}

pub fn cstring_len(s: &[u8]) -> usize {
    for (i, &byte) in s.iter().enumerate() {
        if byte == 0 {
            return i;
        }
    }
    s.len()
}

pub fn path_hash(path: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in path.iter() {
        if byte == 0 {
            break;
        }
        hash = ((hash << 5) + hash) + (byte as u32);
    }
    hash
}
