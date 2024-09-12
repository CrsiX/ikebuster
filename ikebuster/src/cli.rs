use std::net::IpAddr;

use clap::Parser;

/// The cli of ikebuster
#[derive(Debug, Parser)]
#[clap(author, version)]
pub struct Cli {
    /// The IP to scan
    pub ip: IpAddr,

    /// The port to connect to
    #[clap(short, default_value_t = 500)]
    pub port: u16,
}
