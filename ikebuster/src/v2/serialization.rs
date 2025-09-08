use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use isakmp::v2::definitions::Proposal;
use serde::Serialize;

use crate::v2::Statistics;

#[derive(Debug, Serialize)]
pub struct ScannerSerialization {
    pub target: IpAddr,
    pub target_port: u16,
    pub retry_len: usize,
    pub statistics: Statistics,
    /// UNIX timestamp when the scan was started
    pub scan_started: u64,
    /// Elapsed scan time in milliseconds
    pub elapsed_ms: u64,
    /// UNIX timestamp when this file was created
    pub save_created: u64,
    pub open: HashMap<u64, Vec<Proposal>>,
    pub accepted: Vec<Proposal>,
    pub rejected: Vec<Proposal>,
    pub invalid_syntax: Vec<Proposal>,
    pub todo: VecDeque<Proposal>,
    pub vendor_ids: Vec<Vec<u8>>,
}
