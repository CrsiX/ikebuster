//! Parser functionality to convert network-level bytes into [IKEv2] structs
//!
//! Use the [IKEv2::try_parse] associated function as an entrypoint.

mod notification;
mod packet;
mod proposal;
mod security_association;

use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::UnparseableParameter;
use thiserror::Error;

/// Failure while parsing an [IKEv2] packet from network-level byte representation
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum ParserError {
    #[error("Buffer too small to parse the packet")]
    BufferTooSmall,
    #[error("Wrong protocol, expected IKEv2")]
    WrongProtocol,
    #[error("Parameter could not be parsed: {0:#?}")]
    UnparseableParameter(UnparseableParameter),
    #[error("Proposal numbering doesn't start at 1")]
    InvalidProposalNumberingStart,
    #[error("Proposal numbering doesn't increment by 1")]
    InvalidProposalNumbering,
}

impl From<UnparseableParameter> for ParserError {
    fn from(value: UnparseableParameter) -> Self {
        Self::UnparseableParameter(value)
    }
}

/// Simple type alias for results of parser functions
///
/// The `Ok` tuple contains the resulting payload, the size it
/// consumed in bytes and the next payload type
pub type ParserResult<T> = Result<(T, usize, PayloadType), ParserError>;
