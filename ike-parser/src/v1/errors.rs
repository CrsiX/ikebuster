//! The errors of the parsers

use isakmp::v1::AttributeTypeOther;
use isakmp::v1::CertificateEncodingOther;
use isakmp::v1::ExchangeTypeOther;
use isakmp::v1::InvalidDomainOfInterpretation;
use isakmp::v1::NotifyMessageTypeOther;
use isakmp::v1::PayloadTypeOther;
use thiserror::Error;

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
