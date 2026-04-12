/// XDP Programs - Network Packet Filtering
/// High-performance packet inspection at the network driver level
use aya_ebpf::{macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use crate::common::*;
use crate::maps::*;

/// Main XDP entry point
#[xdp]
pub fn scanner_xdp(ctx: XdpContext) -> u32 {
    unsafe {
        match try_xdp(&ctx) {
            Ok(action) => action,
            Err(_) => XDP_PASS,
        }
    }
}

unsafe fn try_xdp(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Ethernet header is 14 bytes
    if data + 14 > data_end {
        return Ok(XDP_PASS);
    }

    // Parse ethernet type (offset 12-13)
    let eth_type = (*(data + 12) as u16) | ((*(data + 13) as u16) << 8);

    // Only handle IPv4
    if eth_type != 0x0800 {
        return Ok(XDP_PASS);
    }

    // IPv4 header starts after ethernet header
    let ip_data = data + 14;

    // Minimum IPv4 header is 20 bytes
    if ip_data + 20 > data_end {
        return Ok(XDP_PASS);
    }

    // Extract source and destination IPs
    // IP header: src IP at offset 12-15, dst IP at offset 16-19
    let src_ip = read_u32_le(ip_data, 12)?;
    let dst_ip = read_u32_le(ip_data, 16)?;

    // Check if source is blocked
    if unsafe { BLOCKED_IPS.get(&src_ip) }.is_some() {
        info!(ctx, "XDP: Dropping packet from blocked source {}", src_ip);
        return Ok(XDP_DROP);
    }

    // Check if destination is blocked
    if unsafe { BLOCKED_IPS.get(&dst_ip) }.is_some() {
        info!(
            ctx,
            "XDP: Dropping packet to blocked destination {}", dst_ip
        );
        return Ok(XDP_DROP);
    }

    // Check threat intelligence
    if unsafe { THREAT_INTEL.get(&src_ip) }.is_some() {
        info!(ctx, "XDP: Threat match from {}", src_ip);
        // Could rate limit or alert here
    }

    Ok(XDP_PASS)
}

/// Read a u32 from a byte offset in little-endian format
#[inline]
unsafe fn read_u32_le(ptr: *const u8, offset: usize) -> Result<u32, i64> {
    let data = ptr.add(offset);
    Ok((*data) as u32
        | ((*data.add(1)) as u32) << 8
        | ((*data.add(2)) as u32) << 16
        | ((*data.add(3)) as u32) << 24)
}
