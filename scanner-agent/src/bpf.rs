use crate::error::ScannerError;
use aya::maps::RingBuf;
use aya::programs::{KProbe, TracePoint};
use aya::{Ebpf, EbpfLoader};
use bytes::BytesMut;
use scanner_common::{ExecEvent, FileEvent, NetEvent};

pub fn load_and_attach(path: &str) -> Result<Ebpf, ScannerError> {
    let mut bpf = EbpfLoader::new()
        .load_file(path)
        .map_err(|err| ScannerError::Bpf(err.to_string()))?;

    attach_tracepoint(&mut bpf, "scanner_execve", "syscalls", "sys_enter_execve")?;
    attach_tracepoint(&mut bpf, "scanner_openat", "syscalls", "sys_enter_openat")?;
    attach_tracepoint(&mut bpf, "scanner_mmap", "syscalls", "sys_enter_mmap")?;
    attach_kprobe(&mut bpf, "scanner_tcp_connect", "tcp_connect")?;
    attach_kprobe(&mut bpf, "scanner_inet_bind", "inet_bind")?;

    Ok(bpf)
}

fn attach_tracepoint(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<(), ScannerError> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| ScannerError::Bpf(format!("missing tracepoint program {program_name}")))?
        .try_into()
        .map_err(|err| ScannerError::Bpf(err.to_string()))?;
    program.load().map_err(|err| ScannerError::Bpf(err.to_string()))?;
    program
        .attach(category, name)
        .map_err(|err| ScannerError::Bpf(err.to_string()))?;
    Ok(())
}

fn attach_kprobe(bpf: &mut Ebpf, program_name: &str, fn_name: &str) -> Result<(), ScannerError> {
    let program: &mut KProbe = bpf
        .program_mut(program_name)
        .ok_or_else(|| ScannerError::Bpf(format!("missing kprobe program {program_name}")))?
        .try_into()
        .map_err(|err| ScannerError::Bpf(err.to_string()))?;
    program.load().map_err(|err| ScannerError::Bpf(err.to_string()))?;
    program
        .attach(fn_name, 0)
        .map_err(|err| ScannerError::Bpf(err.to_string()))?;
    Ok(())
}

pub struct EventConsumer {
    exec_rb: RingBuf<aya::maps::MapData>,
    file_rb: RingBuf<aya::maps::MapData>,
    net_rb: RingBuf<aya::maps::MapData>,
    exec_buf: BytesMut,
    file_buf: BytesMut,
    net_buf: BytesMut,
}

impl EventConsumer {
    pub fn new(bpf: &mut Ebpf) -> Result<Self, ScannerError> {
        let exec_rb = take_ringbuf(bpf, "EXEC_EVENTS")?;
        let file_rb = take_ringbuf(bpf, "FILE_EVENTS")?;
        let net_rb = take_ringbuf(bpf, "NET_EVENTS")?;
        Ok(Self {
            exec_rb,
            file_rb,
            net_rb,
            exec_buf: BytesMut::with_capacity(1024),
            file_buf: BytesMut::with_capacity(1024),
            net_buf: BytesMut::with_capacity(1024),
        })
    }

    pub fn consume_exec<F>(&mut self, mut callback: F) -> Result<usize, ScannerError>
    where
        F: FnMut(ExecEvent),
    {
        let mut count = 0;
        while let Some(item) = self.exec_rb.next() {
            if let Some(event) = self.try_parse_exec(&item) {
                callback(event);
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn consume_file<F>(&mut self, mut callback: F) -> Result<usize, ScannerError>
    where
        F: FnMut(FileEvent),
    {
        let mut count = 0;
        while let Some(item) = self.file_rb.next() {
            if let Some(event) = self.try_parse_file(&item) {
                callback(event);
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn consume_net<F>(&mut self, mut callback: F) -> Result<usize, ScannerError>
    where
        F: FnMut(NetEvent),
    {
        let mut count = 0;
        while let Some(item) = self.net_rb.next() {
            if let Some(event) = self.try_parse_net(&item) {
                callback(event);
                count += 1;
            }
        }
        Ok(count)
    }

    fn try_parse_exec(&self, data: &[u8]) -> Option<ExecEvent> {
        if data.len() < core::mem::size_of::<ExecEvent>() {
            return None;
        }
        unsafe { Some(std::ptr::read_unaligned(data.as_ptr() as *const ExecEvent)) }
    }

    fn try_parse_file(&self, data: &[u8]) -> Option<FileEvent> {
        if data.len() < core::mem::size_of::<FileEvent>() {
            return None;
        }
        // Validate EventKind discriminant before constructing to avoid UB.
        // FileEvent: kind is the last field at offset size_of - 1.
        let kind_offset = core::mem::size_of::<FileEvent>() - 1;
        if scanner_common::EventKind::try_from_u8(data[kind_offset]).is_none() {
            return None;
        }
        unsafe { Some(std::ptr::read_unaligned(data.as_ptr() as *const FileEvent)) }
    }

    fn try_parse_net(&self, data: &[u8]) -> Option<NetEvent> {
        if data.len() < core::mem::size_of::<NetEvent>() {
            return None;
        }
        // Validate EventKind discriminant before constructing to avoid UB.
        // NetEvent: kind is at offset 73 (after protocol:u8 at 72).
        // NOT at size_of-1, which would be inside data_size:u32 at offset 76.
        const NET_EVENT_KIND_OFFSET: usize = 73;
        if data.len() <= NET_EVENT_KIND_OFFSET {
            return None;
        }
        if scanner_common::EventKind::try_from_u8(data[NET_EVENT_KIND_OFFSET]).is_none() {
            return None;
        }
        unsafe { Some(std::ptr::read_unaligned(data.as_ptr() as *const NetEvent)) }
    }
}

fn take_ringbuf(bpf: &mut Ebpf, name: &str) -> Result<RingBuf<aya::maps::MapData>, ScannerError> {
    let map = bpf
        .take_map(name)
        .ok_or_else(|| ScannerError::Bpf(format!("missing map {name}")))?;
    RingBuf::try_from(map).map_err(|err| ScannerError::Bpf(err.to_string()))
}
