use std::net::IpAddr;
use std::time::Instant;

use crate::v2_utils::finding::{Finding, FindingResult};
use isakmp::v2::definitions::{IKEv2, Proposal};
use serde::Serialize;

pub mod finding;
pub mod gen_proposals;
pub(crate) mod receiver;
pub mod scanner;
pub mod scanner2;
pub(crate) mod sender;

/// Options to "configure" the scanner v2
#[derive(Debug, Clone)]
pub struct ScanOptionsV2 {
    /// Target IP
    pub ip: IpAddr,
    /// Target port
    pub port: u16,
    /// Local listen port
    pub listen_port: u16,
    /// Interval between each sent message
    pub interval: u64,
    /// Number of transforms to send in a single proposal
    pub transform_no: usize,
    /// Optional save file to store scanner state in JSON
    pub json_state: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanResultOutputFormat {
    pub target: IpAddr,
    pub target_port: u16,
    pub completed: bool,
    pub statistics: Statistics,
    pub rejected: usize,
    pub invalid_syntax: usize,
    pub accepted: Vec<Proposal>,
    pub vendor_ids: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Statistics {
    pub errors: u64,
    pub sent_bytes: u64,
    pub sent_packets: u64,
    pub recv_bytes: u64,
    pub recv_packets: u64,
    pub total_checks: usize,
}

#[derive(Debug, Default)]
pub struct Results {
    pub accepted: Vec<Proposal>,
    pub rejected: Vec<Proposal>,
    pub invalid_syntax: Vec<Proposal>,
    pub vendor_ids: Vec<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct Open {
    /// List of sent [IKEv2] packets and the timestamp when they were sent; the ordering
    /// is not important and may be arbitrary due to retry and timeout logic.
    sent: Vec<(IKEv2, Instant)>,
    /// List of packets that need to be retried to send; they may be modified (e.g. for Cookie
    /// payloads), and they also include other payloads (e.g. the Delete packet).
    retry: Vec<IKEv2>,
    /// List of vectors of [Proposal]s that should be sent again in a new packet soon to
    /// verify them; the ordering is not important. Note that [Proposal]s in this list may
    /// have been sent to the responder already in a larger bulk but needed to be split up again.
    verify: Vec<Vec<Proposal>>,
}

impl Results {
    /// Create a list of findings from the results
    pub fn to_findings(&self) -> Vec<Finding> {
        let mut findings = vec![];

        #[inline]
        fn to_finding(proposal: &Proposal, result: FindingResult) -> Finding {
            Finding {
                encryption: proposal.encryption_algorithms.get(0).unwrap().0,
                key_size: proposal.encryption_algorithms.get(0).unwrap().1,
                is_aead: proposal
                    .encryption_algorithms
                    .get(0)
                    .unwrap()
                    .0
                    .is_aead_cipher(),
                prf: proposal.pseudo_random_functions.get(0).unwrap().clone(),
                integrity: proposal.integrity_algorithms.first().cloned(),
                kex: proposal.key_exchange_methods.first().cloned().unwrap(),
                result,
            }
        }

        for i in self.accepted.iter() {
            findings.push(to_finding(i, FindingResult::Accepted));
        }
        for i in self.rejected.iter() {
            findings.push(to_finding(i, FindingResult::Rejected));
        }
        for i in self.invalid_syntax.iter() {
            findings.push(to_finding(i, FindingResult::InvalidSyntax));
        }

        findings
    }
}
