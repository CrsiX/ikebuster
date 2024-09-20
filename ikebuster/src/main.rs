use std::env;
use std::net::IpAddr;
use std::process::exit;
use std::time::Duration;

use clap::ArgAction;
use clap::Parser;
use ikebuster::ScanOptions;
use tracing::error;
use tracing::info;

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
    pub interval: u64,

    /// The number of transforms to send in a proposal
    #[clap(long, default_value_t = 20)]
    pub transforms: usize,

    /// Output the results in a json file
    #[clap(long)]
    pub json: bool,

    /// The sleep time (in seconds) after a valid transform is found.
    ///
    /// Some servers limit new requests when there are half-open connections
    #[clap(long, default_value_t = 45)]
    pub sleep_on_transform_found: u64,

    /// The path to write output to. Only used in combination with --json
    #[clap(short, long, default_value_t = String::from("./output_ikebuster.json"))]
    pub output: String,

    /// Set the verbosity of the output
    #[clap(short, long, action = ArgAction::Count)]
    pub verbose: u8,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.verbose > 0 {
        match cli.verbose {
            1 => env::set_var("RUST_LOG", "ikebuster=debug"),
            _ => env::set_var("RUST_LOG", "ikebuster=trace"),
        }
    } else if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    let opts = ScanOptions {
        ip: cli.ip,
        port: cli.port,
        interval: cli.interval,
        transform_no: cli.transforms,
        sleep_on_transform_found: Duration::new(cli.sleep_on_transform_found, 0),
    };

    let res = match ikebuster::scan(opts).await {
        Ok(res) => res,
        Err(err) => {
            error!("{err}");
            exit(1);
        }
    };

    for valid in res.valid_transforms {
        info!(
            "ENC={} HASH={} AUTH={} GROUP={}",
            if let Some(key_len) = valid.key_size {
                format!("{}/{key_len}", valid.encryption_algorithm)
            } else {
                valid.encryption_algorithm.to_string()
            },
            valid.hash_algorithm,
            valid.authentication_method,
            valid.group_description,
        );
    }
}
