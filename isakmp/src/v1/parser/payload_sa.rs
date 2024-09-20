//! Parsers of the security association payload

use zerocopy::FromBytes;

use crate::v1::definitions::DomainOfInterpretation;
use crate::v1::definitions::PayloadType;
use crate::v1::definitions::StaticSecurityAssociationPayload;
use crate::v1::parser::definitions::SecurityAssociationPayload;
use crate::v1::parser::errors::IsakmpParseError;
use crate::v1::parser::payload_proposal::parse_proposal;

/// Parse a security association payload
pub fn parse_security_association(
    buf: &[u8],
) -> Result<SecurityAssociationPayload, IsakmpParseError> {
    let static_part = StaticSecurityAssociationPayload::ref_from_prefix(buf)
        .ok_or(IsakmpParseError::BufferTooSmall)?;

    if static_part.generic_payload_header.reserved != 0 {
        return Err(IsakmpParseError::UnexpectedPayload);
    }

    let mut security_association = SecurityAssociationPayload {
        next_payload: PayloadType::try_from(static_part.generic_payload_header.next_payload)?,
        length: static_part.generic_payload_header.payload_length.get(),
        domain_of_interpretation: DomainOfInterpretation::try_from(static_part.doi.get())?,
        situation: vec![],
        proposal_payload: vec![],
    };

    let static_size = size_of::<StaticSecurityAssociationPayload>();

    // Defined by https://www.rfc-editor.org/rfc/rfc2407.html#section-4.2
    let [a, b, c, d] = buf[static_size..]
        .get(..4)
        .ok_or(IsakmpParseError::BufferTooSmall)?
    else {
        return Err(IsakmpParseError::BufferTooSmall);
    };
    security_association.situation.extend([a, b, c, d]);

    let remaining = &buf[static_size + 4..security_association.length as usize];
    let mut start = 0;
    while start < remaining.len() {
        let payload = parse_proposal(&remaining[start..])?;
        start += payload.length as usize;
        security_association.proposal_payload.push(payload);
    }

    Ok(security_association)
}
