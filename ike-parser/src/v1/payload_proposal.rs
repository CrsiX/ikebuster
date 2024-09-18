//! Parser of the proposal payload

use isakmp::v1::PayloadType;
use isakmp::zerocopy::FromBytes;

use crate::v1::definitions::ProposalPayload;
use crate::v1::errors::IsakmpParseError;
use crate::v1::payload_transform::parse_transform;

/// Parse a proposal payload
pub fn parse_proposal(buf: &[u8]) -> Result<ProposalPayload, IsakmpParseError> {
    let static_part = isakmp::v1::StaticProposalPayload::ref_from_prefix(buf)
        .ok_or(IsakmpParseError::BufferTooSmall)?;

    if static_part.generic_payload_header.reserved != 0 {
        return Err(IsakmpParseError::UnexpectedPayload);
    }

    let static_size = size_of::<isakmp::v1::StaticProposalPayload>();

    let spi = buf
        .get(static_size..static_size + static_part.spi_size as usize)
        .ok_or(IsakmpParseError::BufferTooSmall)?
        .to_vec();

    let mut proposal = ProposalPayload {
        next_payload: PayloadType::try_from(static_part.generic_payload_header.next_payload)?,
        length: static_part.generic_payload_header.payload_length.get(),
        proposal_no: static_part.proposal_no,
        protocol_id: static_part.protocol_id,
        spi_size: static_part.spi_size,
        no_of_transforms: static_part.no_of_transforms,
        spi,
        transforms: vec![],
    };

    let remaining = &buf[static_size + static_part.spi_size as usize..];

    let mut start = 0;
    while start < remaining.len() {
        let transform = parse_transform(&remaining[start..])?;
        start += transform.length as usize;
        proposal.transforms.push(transform);
    }

    if proposal.transforms.len() != proposal.no_of_transforms as usize {
        return Err(IsakmpParseError::UnexpectedPayload);
    }

    Ok(proposal)
}
