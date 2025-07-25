use crate::v2::definitions::Proposal;
use crate::v2::parser::ParserError;

impl Proposal {
    pub(crate) fn try_parse(buf: &[u8]) -> Result<Self, ParserError> {
        todo!()
    }
}
