#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kretprobe, map},
    maps::PerCpuArray,
    programs::RetProbeContext,
};
use aya_log_ebpf::error;
use packet_watcher_rs_common::{PacketStats, WatchedFunction};

#[map(name = "STATS")]
static STATS: PerCpuArray<PacketStats> = PerCpuArray::with_max_entries(WatchedFunction::COUNT, 0);

#[kretprobe]
pub fn tcp_sendmsg_probe(ctx: RetProbeContext) -> u32 {
    match try_packet_watcher_rs(&ctx, WatchedFunction::TcpSendmsg as u32) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in tcp_sendmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

#[kretprobe]
pub fn tcp_recvmsg_probe(ctx: RetProbeContext) -> u32 {
    match try_packet_watcher_rs(&ctx, WatchedFunction::TcpRecvmsg as u32) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in tcp_recvmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

#[kretprobe]
pub fn udp_sendmsg_probe(ctx: RetProbeContext) -> u32 {
    match try_packet_watcher_rs(&ctx, WatchedFunction::UdpSendmsg as u32) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in udp_sendmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

#[kretprobe]
pub fn udp_recvmsg_probe(ctx: RetProbeContext) -> u32 {
    match try_packet_watcher_rs(&ctx, WatchedFunction::UdpRecvmsg as u32) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in udp_recvmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

fn try_packet_watcher_rs(ctx: &RetProbeContext, index: u32) -> Result<u32, u32> {
    let bytes = ctx.ret::<i32>();
    if bytes <= 0 {
        return Ok(0); // Expected for non-blocking socket
    }
    put_bytes(index, bytes as u64).map_err(|()| 1u32)?;
    Ok(0)
}

fn put_bytes(index: u32, new_bytes: u64) -> Result<(), ()> {
    let stats = STATS.get_ptr_mut(index).ok_or(())?;
    unsafe { (*stats).bytes += new_bytes };
    Ok(())
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
