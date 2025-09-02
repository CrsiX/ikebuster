//! Parsers of the header

use zerocopy::FromBytes;

use crate::v1::definitions::ExchangeType;
use crate::v1::definitions::PayloadType;
use crate::v1::parser::definitions::Header;
use crate::v1::parser::errors::IsakmpParseError;

/// Parse the header
pub fn parse_header(buf: &[u8]) -> Result<Header, IsakmpParseError> {
    let header = crate::v1::definitions::Header::ref_from_prefix(buf)
        .ok_or(IsakmpParseError::BufferTooSmall)?;

    Ok(Header {
        initiator_cookie: header.initiator_cookie.get(),
        responder_cookie: header.responder_cookie.get(),
        major_version: header.version >> 4,
        minor_version: header.version & 0b1111,
        flags: header.flags,
        exchange_mode: ExchangeType::try_from(header.exchange_type)?,
        length: header.length.get(),
        message_id: header.message_id.get(),
        next_payload: PayloadType::try_from(header.next_payload)?,
    })
}
