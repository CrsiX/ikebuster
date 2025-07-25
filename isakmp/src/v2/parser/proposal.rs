use crate::v2::definitions::header::ProposalHeader;
use crate::v2::definitions::params::SecurityProtocol;
use crate::v2::definitions::Proposal;
use crate::v2::parser::ParserError;

impl Proposal {
    pub(crate) fn try_parse(header: &ProposalHeader, buf: &[u8]) -> Result<Self, ParserError> {
        let header_len = size_of::<ProposalHeader>();
        let spi_len = header.spi_size as usize;
        let body_len = header.proposal_length.get() as usize - header_len - spi_len;
        let spi = Vec::from(&buf[header_len..header_len + spi_len]);
        let protocol = SecurityProtocol::try_from(header.protocol_id)?;

        let body = &buf[header_len + spi_len..header_len + spi_len + body_len];
        let mut encryption_algorithms = vec![];
        let mut pseudo_random_functions = vec![];
        let mut integrity_algorithms = vec![];
        let mut key_exchange_methods = vec![];
        let mut sequence_numbers = vec![];

        // TODO: parse body

        Ok(Self {
            protocol,
            spi,
            encryption_algorithms,
            pseudo_random_functions,
            integrity_algorithms,
            key_exchange_methods,
            sequence_numbers,
        })
    }
}
