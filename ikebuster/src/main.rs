use std::env;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::process::exit;
use std::time::Duration;

use clap::ArgAction;
use clap::Parser;
use ikebuster::ScanError;
use ikebuster::ScanOptions;
use isakmp::v1::generator::Transform;
use owo_colors::OwoColorize;
use serde::Serialize;

const BANNER: &str = r#"
Welcome to
  _ _        _               _
 (_) | _____| |__  _   _ ___| |_ ___ _ __
 | | |/ / _ \ '_ \| | | / __| __/ _ \ '__|
 | |   <  __/ |_) | |_| \__ \ ||  __/ |
 |_|_|\_\___|_.__/ \__,_|___/\__\___|_|

"#;

macro_rules! owo_println {
    ($input:expr) => {
        println!("{} {}", "[ikebuster]".purple().bold(), $input);
    };
}

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
    pub json: Option<String>,

    /// The sleep time (in seconds) after a valid transform is found.
    ///
    /// Some servers limit new requests when there are half-open connections
    #[clap(long, default_value_t = 45)]
    pub sleep_on_transform_found: u64,

    /// Set the verbosity of the output
    #[clap(short, long, action = ArgAction::Count)]
    pub verbose: u8,
}

/// container struct for json output
#[derive(Serialize)]
pub struct DataOutput {
    /// The target that was scanned
    pub target: SocketAddr,
    /// All found valid transforms
    pub valid_transforms: Vec<Transform>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    println!("{}", BANNER.blue().bold());

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
            match err {
                ScanError::CouldNotBind(e) => {
                    owo_println!("---------------");
                    owo_println!("Could not bind to local port 500".red().bold());
                    owo_println!(format!("\t{e}").red().bold());
                    owo_println!("---------------");
                    owo_println!("Possible solutions:");
                    owo_println!(format!("\tsudo {}", env::current_exe()?.display()).bright_black());
                    owo_println!(format!(
                        "\tsetcap 'cap_net_bind_service=+ep' {}",
                        env::current_exe()?.display()
                    )
                    .bright_black());
                    owo_println!("---------------");
                }
                _ => {
                    owo_println!(format!("{err}").red().bold());
                }
            }
            exit(1);
        }
    };

    owo_println!("---------------");

    if res.valid_transforms.is_empty() {
        owo_println!("No valid transforms found :(".yellow());
    } else {
        owo_println!("Found transforms:");
    }

    for valid in &res.valid_transforms {
        owo_println!(format!(
            "\t{}{} {}{} {}{} {}{}",
            "ENC=".bright_black(),
            if let Some(key_len) = valid.key_size {
                format!("{}/{key_len}", valid.encryption_algorithm)
            } else {
                valid.encryption_algorithm.to_string()
            },
            "HASH=".bright_black(),
            valid.hash_algorithm,
            "AUTH=".bright_black(),
            valid.authentication_method,
            "GROUP=".bright_black(),
            valid.group_description,
        ));
    }
    if let Some(target) = cli.json {
        owo_println!("---------------");
        let Ok(serialized) = serde_json::to_string_pretty(&DataOutput {
            target: SocketAddr::new(cli.ip, cli.port),
            valid_transforms: res.valid_transforms,
        }) else {
            owo_println!("Error serializing results".bright_red());
            exit(1);
        };

        let mut file = match File::create(&target) {
            Ok(file) => file,
            Err(err) => {
                owo_println!(format!("Error creating json file: {err}").bright_red());
                exit(1);
            }
        };

        write!(file, "{serialized}")?;
        file.flush()?;

        owo_println!(format!(
            "{} {}",
            "Written json output to".bright_black(),
            target.default_color()
        ));
    }

    owo_println!("---------------");
    owo_println!("See you soon! :)".blue());

    Ok(())
}
