#![no_std]

pub const STATS_MAP_NAME: &str = "STATS";

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketStats {
    pub bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketStats {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WatchedFunction {
    TcpSendmsg = 0,
    TcpRecvmsg = 1,
    UdpSendmsg = 2,
    UdpRecvmsg = 3,
}

impl WatchedFunction {
    pub const COUNT: u32 = 4;

    pub const fn function_name(&self) -> &'static str {
        match self {
            WatchedFunction::TcpSendmsg => "tcp_sendmsg",
            WatchedFunction::TcpRecvmsg => "tcp_recvmsg",
            WatchedFunction::UdpSendmsg => "udp_sendmsg",
            WatchedFunction::UdpRecvmsg => "udp_recvmsg",
        }
    }

    /// These names must match the function names defined in the eBPF program
    pub const fn probe_name(&self) -> &'static str {
        match self {
            WatchedFunction::TcpSendmsg => "tcp_sendmsg_probe",
            WatchedFunction::TcpRecvmsg => "tcp_recvmsg_probe",
            WatchedFunction::UdpSendmsg => "udp_sendmsg_probe",
            WatchedFunction::UdpRecvmsg => "udp_recvmsg_probe",
        }
    }

    pub const fn all() -> &'static [WatchedFunction] {
        &[
            WatchedFunction::TcpSendmsg,
            WatchedFunction::TcpRecvmsg,
            WatchedFunction::UdpSendmsg,
            WatchedFunction::UdpRecvmsg,
        ]
    }
}
