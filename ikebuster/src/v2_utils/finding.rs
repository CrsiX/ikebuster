use std::fmt::Write;

use isakmp::strum::Display;
use isakmp::v2::definitions::params::{
    EncryptionAlgorithm, IntegrityAlgorithm, KeyExchangeMethod, PseudorandomFunction,
};

#[derive(Debug, Display)]
pub enum FindingResult {
    Accepted,
    InvalidSyntax,
    Rejected,
}

#[derive(Debug)]
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
