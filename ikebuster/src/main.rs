//! # ikebuster
//!
//! A little utility to scan your IKE servers for insecure ciphers

#![warn(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use clap::Parser;

use crate::cli::Cli;

mod cli;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
}
