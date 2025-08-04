use crate::v2::definitions::Notification;
use crate::v2::parser::ParserError;

impl<'a> Notification<'a> {
    pub(crate) fn try_parse(p0: &[u8]) -> Result<Self, ParserError> {
        todo!()
    }
}
