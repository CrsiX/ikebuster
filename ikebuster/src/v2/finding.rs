use std::fmt::Write;

use isakmp::strum::Display;
use isakmp::v2::definitions::params::{
    EncryptionAlgorithm, IntegrityAlgorithm, KeyExchangeMethod, PseudorandomFunction,
};
use isakmp::v2::definitions::Proposal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Display, PartialEq, Serialize, Deserialize)]
pub enum FindingResult {
    Accepted,
    InvalidSyntax,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub encryption: EncryptionAlgorithm,
    pub key_size: Option<u16>,
    pub is_aead: bool,
    pub prf: PseudorandomFunction,
    pub integrity: Option<IntegrityAlgorithm>,
    pub kex: KeyExchangeMethod,
    pub result: FindingResult,
}

pub fn format_to_csv(findings: &Vec<Finding>) -> Result<String, std::fmt::Error> {
    let mut result =
        "\"number\";\"encryption\";\"key_size\";\"is_aead\";\"prf\";\"integrity\";\"key_exchange\";\"result\"\n"
            .to_string();

    for (i, f) in findings.iter().enumerate() {
        result.write_fmt(format_args!(
            "\"{}\";\"{}\";\"{}\";\"{}\";\"{}\";\"{}\";\"{}\";\"{}\"\n",
            i + 1,
            f.encryption,
            if let Some(s) = f.key_size {
                s.to_string()
            } else {
                "".to_string()
            },
            f.is_aead,
            f.prf,
            if let Some(integrity) = f.integrity {
                integrity.to_string()
            } else {
                "".to_string()
            },
            f.kex,
            f.result
        ))?
    }
    Ok(result)
}

impl Finding {
    /// Create a [Finding] from a [Proposal] and the result of the proposal scan
    ///
    /// Note that this finding only uses the very first of each of the proposal's
    /// values. If the proposal contains multiple transforms for a single
    /// transform type, only the first will be used. If a mandatory transform
    /// is omitted, `None` will be returned.
    pub fn from_proposal(proposal: &Proposal, result: FindingResult) -> Option<Self> {
        if let Some((encryption, key_size)) = proposal.encryption_algorithms.first() {
            if let Some(kex) = proposal.key_exchange_methods.first() {
                if let Some(prf) = proposal.pseudo_random_functions.first() {
                    return Some(Finding {
                        encryption: *encryption,
                        key_size: *key_size,
                        is_aead: encryption.is_aead_cipher(),
                        prf: *prf,
                        integrity: proposal.integrity_algorithms.first().copied(),
                        kex: *kex,
                        result,
                    });
                }
            }
        }
        None
    }
}
