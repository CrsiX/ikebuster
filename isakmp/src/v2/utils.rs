//! Various utilities for IKEv2

use crate::v2::definitions::Proposal;

/// Create a `Vec<u8>` filled with random bytes
///
/// These bytes are not guaranteed to be cryptographically safe.
pub fn get_random_vec(len: usize) -> Vec<u8> {
    rand::random_iter().take(len).collect()
}

/// Format a list of [Proposal]s into a serialized CSV interpretation
pub fn format_to_csv(proposals: Vec<Proposal>) -> Result<String, std::fmt::Error> {
    let mut counter = 0;
    let mut result =
        "\"number\";\"proposal\";\"encryption\";\"prf\";\"integrity\";\"key_exchange\"\n"
            .to_string();

    for (i, p) in proposals.iter().enumerate() {
        use std::fmt::Write;
        for (e, key_len) in p.encryption_algorithms.iter() {
            let encryption = if let Some(key_len) = key_len {
                format!("{e}_{key_len}")
            } else {
                e.to_string()
            };
            for prf in p.pseudo_random_functions.iter() {
                for kex in p.key_exchange_methods.iter() {
                    if p.integrity_algorithms.is_empty() {
                        counter += 1;
                        result.write_fmt(format_args!(
                            "\"{}\";\"{}\";\"{}\";\"{}\";\"{}\";\"{}\"\n",
                            counter,
                            i + 1,
                            encryption,
                            prf,
                            "",
                            kex
                        ))?
                    }
                    for integrity in p.integrity_algorithms.iter() {
                        counter += 1;
                        result.write_fmt(format_args!(
                            "\"{}\";\"{}\";\"{}\";\"{}\";\"{}\";\"{}\"\n",
                            counter,
                            i + 1,
                            encryption,
                            prf,
                            integrity,
                            kex
                        ))?
                    }
                }
            }
        }
    }
    Ok(result)
}
