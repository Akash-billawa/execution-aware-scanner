#![cfg(feature = "ebpf")]

use crate::error::ScannerError;
use aya::maps::{MapData, RingBuf};
use aya::programs::{KProbe, Lsm, TracePoint, Xdp};
use aya::Ebpf;

pub struct BpfLoader {
    pub bpf: Ebpf,
}

impl BpfLoader {
    pub fn new(path: &str) -> Result<Self, ScannerError> {
        let bpf = Ebpf::load_file(path)
            .map_err(|e| ScannerError::Bpf(format!("Failed to load eBPF object: {}", e)))?;

        Ok(Self { bpf })
    }

    pub fn attach_tracepoints(&mut self) -> Result<(), ScannerError> {
        // Attach exec tracepoints
        self.attach_tracepoint("scanner_execve", "syscalls", "sys_enter_execve")?;
        self.attach_tracepoint("scanner_execveat", "syscalls", "sys_enter_execveat")?;

        // Attach file tracepoints
        self.attach_tracepoint("scanner_openat", "syscalls", "sys_enter_openat")?;
        self.attach_tracepoint("scanner_openat2", "syscalls", "sys_enter_openat2")?;
        self.attach_tracepoint("scanner_mmap", "syscalls", "sys_enter_mmap")?;
        self.attach_tracepoint("scanner_mprotect", "syscalls", "sys_enter_mprotect")?;

        Ok(())
    }

    pub fn attach_kprobes(&mut self) -> Result<(), ScannerError> {
        // Attach network kprobes
        self.attach_kprobe("scanner_tcp_connect", "tcp_connect")?;
        self.attach_kprobe("scanner_tcp_connect_v6", "tcp_v6_connect")?;
        self.attach_kprobe("scanner_inet_bind", "inet_bind")?;
        self.attach_kprobe("scanner_inet_bind_v6", "inet6_bind")?;
        self.attach_kprobe("scanner_tcp_close", "tcp_close")?;
        self.attach_kprobe("scanner_udp_sendmsg", "udp_sendmsg")?;
        self.attach_kprobe("scanner_udp_recvmsg", "udp_recvmsg")?;

        Ok(())
    }

    pub fn attach_lsm_hooks(&mut self) -> Result<(), ScannerError> {
        // Try to attach LSM hooks (requires CONFIG_BPF_LSM)
        if let Err(e) = self.attach_lsm("bprm_check_security") {
            tracing::warn!("Failed to attach LSM hook: {}", e);
        }
        if let Err(e) = self.attach_lsm("socket_connect") {
            tracing::warn!("Failed to attach LSM hook: {}", e);
        }
        if let Err(e) = self.attach_lsm("socket_bind") {
            tracing::warn!("Failed to attach LSM hook: {}", e);
        }
        if let Err(e) = self.attach_lsm("file_open") {
            tracing::warn!("Failed to attach LSM hook: {}", e);
        }

        Ok(())
    }

    pub fn attach_xdp(&mut self, iface: &str) -> Result<(), ScannerError> {
        let prog: &mut Xdp = self
            .bpf
            .program_mut("scanner_xdp_filter")
            .ok_or_else(|| ScannerError::Bpf("XDP program not found".to_string()))?
            .try_into()
            .map_err(|e| ScannerError::Bpf(format!("Failed to load XDP program: {}", e)))?;

        prog.load()
            .map_err(|e| ScannerError::Bpf(format!("Failed to load XDP: {}", e)))?;

        prog.attach(iface, aya::programs::xdp::XdpFlags::default())
            .map_err(|e| ScannerError::Bpf(format!("Failed to attach XDP: {}", e)))?;

        tracing::info!("XDP attached to {}", iface);
        Ok(())
    }

    pub fn open_ringbufs(
        &mut self,
    ) -> Result<(RingBuf<MapData>, RingBuf<MapData>, RingBuf<MapData>), ScannerError> {
        let exec_rb = self.take_ringbuf("EXEC_EVENTS")?;
        let file_rb = self.take_ringbuf("FILE_EVENTS")?;
        let net_rb = self.take_ringbuf("NET_EVENTS")?;

        Ok((exec_rb, file_rb, net_rb))
    }

    fn attach_tracepoint(
        &mut self,
        name: &str,
        category: &str,
        tracepoint: &str,
    ) -> Result<(), ScannerError> {
        let prog: &mut TracePoint = self
            .bpf
            .program_mut(name)
            .ok_or_else(|| ScannerError::Bpf(format!("Tracepoint {} not found", name)))?
            .try_into()
            .map_err(|e| ScannerError::Bpf(format!("Failed to load {}: {}", name, e)))?;

        prog.load()
            .map_err(|e| ScannerError::Bpf(format!("Failed to load {}: {}", name, e)))?;

        prog.attach(category, tracepoint)
            .map_err(|e| ScannerError::Bpf(format!("Failed to attach {}: {}", name, e)))?;

        tracing::info!("Attached tracepoint: {}", name);
        Ok(())
    }

    fn attach_kprobe(&mut self, name: &str, kernel_fn: &str) -> Result<(), ScannerError> {
        let prog: &mut KProbe = self
            .bpf
            .program_mut(name)
            .ok_or_else(|| ScannerError::Bpf(format!("Kprobe {} not found", name)))?
            .try_into()
            .map_err(|e| ScannerError::Bpf(format!("Failed to load {}: {}", name, e)))?;

        prog.load()
            .map_err(|e| ScannerError::Bpf(format!("Failed to load {}: {}", name, e)))?;

        prog.attach(kernel_fn, 0)
            .map_err(|e| ScannerError::Bpf(format!("Failed to attach {}: {}", name, e)))?;

        tracing::info!("Attached kprobe: {}", name);
        Ok(())
    }

    fn attach_lsm(&mut self, hook: &str) -> Result<(), ScannerError> {
        let prog_name = format!("scanner_lsm_{}", hook);
        let prog: &mut Lsm = self
            .bpf
            .program_mut(&prog_name)
            .ok_or_else(|| ScannerError::Bpf(format!("LSM program {} not found", prog_name)))?
            .try_into()
            .map_err(|e| ScannerError::Bpf(format!("Failed to load {}: {}", prog_name, e)))?;

        prog.load()
            .map_err(|e| ScannerError::Bpf(format!("Failed to load {}: {}", prog_name, e)))?;

        prog.attach(hook)
            .map_err(|e| ScannerError::Bpf(format!("Failed to attach {}: {}", prog_name, e)))?;

        tracing::info!("Attached LSM hook: {}", hook);
        Ok(())
    }

    fn take_ringbuf(&mut self, name: &str) -> Result<RingBuf<MapData>, ScannerError> {
        let map = self
            .bpf
            .take_map(name)
            .ok_or_else(|| ScannerError::Bpf(format!("Ring buffer {} not found", name)))?;

        RingBuf::try_from(map)
            .map_err(|e| ScannerError::Bpf(format!("Failed to open ring buffer {}: {}", name, e)))
    }
}
