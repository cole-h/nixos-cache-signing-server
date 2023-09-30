mod instrumentation;
mod logger;

use clap::Parser;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

#[derive(Parser)]
pub struct Cli {
    #[clap(long, default_value_t = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 8080))]
    pub bind: SocketAddr,

    #[clap(flatten)]
    pub instrumentation: instrumentation::Instrumentation,
}
