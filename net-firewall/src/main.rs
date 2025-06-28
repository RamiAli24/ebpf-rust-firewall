use std::net::Ipv4Addr;
use anyhow::{anyhow, Context as _};
use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use clap::Parser;
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("Failed to remove memlock limit, ret = {}", ret);
    }

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/net-firewall"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let Opt { iface } = opt;

    let program: &mut Xdp = bpf
        .program_mut("net_firewall")
        .ok_or_else(|| anyhow!("program 'net_firewall' not found"))?
        .try_into()?;

    program.load()?;
    program.attach(&iface, XdpFlags::SKB_MODE)
        .context("Failed to attach XDP program")?;

    let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(
        bpf.map_mut("BLOCKLIST")
            .ok_or_else(|| anyhow!("map 'BLOCKLIST' not found"))?,
    )?;
    let ip_to_block = u32::from(Ipv4Addr::new(1, 1, 1, 1)).to_be();
    blocklist.insert(ip_to_block, 0, 0)?;
    println!("Blocked IP: {}", Ipv4Addr::from(ip_to_block));

    println!("Program loaded. Press Ctrl-C to exit.");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
