//! The errors of the parsers

use thiserror::Error;

use crate::v1::definitions::AttributeTypeOther;
use crate::v1::definitions::CertificateEncodingOther;
use crate::v1::definitions::ExchangeTypeOther;
use crate::v1::definitions::InvalidDomainOfInterpretation;
use crate::v1::definitions::NotifyMessageTypeOther;
use crate::v1::definitions::PayloadTypeOther;

/// The errors that can occur while parsing an ISAKMP message
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum IsakmpParseError {
    #[error("Buffer is too small to parse the packet")]
    BufferTooSmall,

    #[error("Unexpected payload type")]
    UnexpectedPayload,

    #[error("Encountered unparsable enum variant")]
    UnparsableVariant,

    #[error("Informational payload")]
    Informational,
}

impl From<PayloadTypeOther> for IsakmpParseError {
    fn from(_value: PayloadTypeOther) -> Self {
        Self::UnparsableVariant
    }
}

impl From<NotifyMessageTypeOther> for IsakmpParseError {
    fn from(_value: NotifyMessageTypeOther) -> Self {
        Self::UnparsableVariant
    }
}

impl From<CertificateEncodingOther> for IsakmpParseError {
    fn from(_value: CertificateEncodingOther) -> Self {
        Self::UnparsableVariant
    }
}

impl From<ExchangeTypeOther> for IsakmpParseError {
    fn from(_value: ExchangeTypeOther) -> Self {
        Self::UnparsableVariant
    }
}

impl From<InvalidDomainOfInterpretation> for IsakmpParseError {
    fn from(_value: InvalidDomainOfInterpretation) -> Self {
        Self::UnparsableVariant
    }
}

impl From<AttributeTypeOther> for IsakmpParseError {
    fn from(_value: AttributeTypeOther) -> Self {
        Self::UnparsableVariant
    }
}
