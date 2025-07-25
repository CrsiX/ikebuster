use crate::v2::definitions::header::ProposalHeader;
use crate::v2::definitions::params::FLAG_MORE_FOLLOWING_PROPOSALS;
use crate::v2::definitions::{Proposal, SecurityAssociation};
use crate::v2::parser::ParserError;
use zerocopy::FromBytes;

impl SecurityAssociation {
    /// Parses a buffer into a [SecurityAssociation]. The buffer must not contain the
    /// generic payload header, it should only contain the list of proposals. The buffer
    /// length is not checked, but will yield an error if too small. Larger buffers
    /// than necessary are ignored. The buffer must not be empty, and must contain
    /// at least one proposal. If the SA has no proposals
    pub(crate) fn try_parse(buf: &[u8]) -> Result<Self, ParserError> {
        let mut offset = 0;
        let mut proposals = vec![];
        let mut proposal_header =
            ProposalHeader::ref_from_prefix(buf).ok_or(ParserError::BufferTooSmall)?;
        if proposal_header.proposal_num != 1 {
            return Err(ParserError::InvalidProposalNumberingStart);
        }
        let mut more_proposals = proposal_header.last_substruct == FLAG_MORE_FOLLOWING_PROPOSALS;

        while more_proposals {
            offset += size_of::<ProposalHeader>();

            let body_len =
                proposal_header.proposal_length.get() as usize - size_of::<ProposalHeader>();
            let proposal = Proposal::try_parse(&buf[offset..offset + body_len])?;
            proposals.push(proposal);
            offset += body_len;

            let next_proposal_header = ProposalHeader::ref_from_prefix(&buf[offset..])
                .ok_or(ParserError::BufferTooSmall)?;
            if next_proposal_header.proposal_num != 1 + proposal_header.proposal_num {
                return Err(ParserError::InvalidProposalNumbering);
            }
            proposal_header = next_proposal_header;
            more_proposals = proposal_header.last_substruct == FLAG_MORE_FOLLOWING_PROPOSALS;
        }
        Ok(Self { proposals })
    }
}
