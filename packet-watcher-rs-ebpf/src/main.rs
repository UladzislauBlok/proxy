#![no_std]
#![no_main]

use aya_ebpf::{macros::kretprobe, programs::RetProbeContext};
use aya_log_ebpf::info;

#[kretprobe]
pub fn packet_watcher_rs(ctx: RetProbeContext) -> u32 {
    match try_packet_watcher_rs(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_packet_watcher_rs(ctx: RetProbeContext) -> Result<u32, u32> {
    let bytes = ctx.ret::<i32>();
    if bytes == -11 {
        // -11 means no data for non-blocking socket
        return Ok(0);
    }
    info!(&ctx, "Read {} bytes from socket", ctx.ret::<i32>());
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
