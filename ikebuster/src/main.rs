use std::env;
use std::net::IpAddr;
use std::process::exit;

use clap::Parser;
use ikebuster::ScanOptions;
use tracing::error;

/// The cli of ikebuster
#[derive(Debug, Parser)]
#[clap(author, version)]
pub struct Cli {
    /// The IP to scan
    pub ip: IpAddr,

    /// The port to connect to
    #[clap(short, default_value_t = 500)]
    pub port: u16,

    /// The interval in milliseconds in which the messages should be sent
    #[clap(short, long, default_value_t = 500)]
    pub interval: usize,

    /// The number of transforms to send in a proposal
    #[clap(long, default_value_t = 20)]
    pub transforms: usize,

    /// Output the results in a json file
    #[clap(long)]
    pub json: bool,

    /// The path to write output to. Only used in combination with --json
    #[clap(short, long, default_value_t = String::from("./output_ikebuster.json"))]
    pub output: String,
}

#[tokio::main]
async fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let opts = ScanOptions {
        ip: cli.ip,
        port: cli.port,
        interval: cli.interval,
        transform_no: cli.transforms,
    };

    let res = match ikebuster::scan(opts).await {
        Ok(res) => res,
        Err(err) => {
            error!("{err}");
            exit(1);
        }
    };
}
