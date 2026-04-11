// XDP program constants and helpers

pub const XDP_ABORTED: u32 = 0;
pub const XDP_DROP: u32 = 1;
pub const XDP_PASS: u32 = 2;
pub const XDP_TX: u32 = 3;
pub const XDP_REDIRECT: u32 = 4;

// Ethernet header structure
#[repr(C)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: u16,
}

// IPv4 header structure
#[repr(C)]
pub struct IpHdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

// TCP header structure
#[repr(C)]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub doff_flags: u16,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

// UDP header structure
#[repr(C)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

impl IpHdr {
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    pub fn header_len(&self) -> usize {
        (self.ihl() as usize) * 4
    }
}

impl TcpHdr {
    pub fn doff(&self) -> u8 {
        (self.doff_flags >> 12) as u8
    }

    pub fn header_len(&self) -> usize {
        (self.doff() as usize) * 4
    }
}

// Protocol numbers
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMP: u8 = 1;

// Ethernet protocol types
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
