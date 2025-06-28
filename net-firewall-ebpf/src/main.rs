#![no_std]
#![no_main]
 
 
use aya_ebpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    maps::HashMap,
    programs::XdpContext,
};

use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use core::mem;

#[xdp]
pub fn net_firewall(ctx: XdpContext) -> u32 {
    match try_net_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[map(name = "BLOCKLIST")]  
static mut BLOCKLIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);
  

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(ptr)
}
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}
fn try_net_firewall(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");

    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0).map_err(|_| xdp_action::XDP_ABORTED)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN).map_err(|_| xdp_action::XDP_ABORTED)? };

 
 
 
    // let ip = unsafe { (*ipv4hdr).src_addr };
    // info!(&ctx, "source IP: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);

    let ipv4hdr: *const Ipv4Hdr = unsafe {
       ptr_at(&ctx, EthHdr::LEN).map_err(|_| xdp_action::XDP_ABORTED)?
    };

    let ip_bytes = unsafe { (*ipv4hdr).src_addr };
    let source_ip = u32::from_be_bytes(ip_bytes);
    
    let octets = source_ip.to_be_bytes();
    info!(&ctx, "src ip: {}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);


    let action = if block_ip(source_ip) {
        info!(&ctx, "packet dropped!!!: {}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };


    Ok(action)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
