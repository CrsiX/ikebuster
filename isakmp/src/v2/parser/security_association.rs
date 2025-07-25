use crate::v2::definitions::SecurityAssociation;
use crate::v2::parser::ParserError;

impl SecurityAssociation {
    /// Parses a buffer into a [SecurityAssociation]. The buffer must not contain the
    /// generic payload header, it should only contain the list of proposals. The buffer
    /// length is not checked, but will yield an error if too small. Larger buffers
    /// than necessary are ignored.
    pub(crate) fn try_parse(buf: &[u8]) -> Result<Self, ParserError> {
        todo!()
    }
}
