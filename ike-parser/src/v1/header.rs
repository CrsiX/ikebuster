//! Parsers of the header

use isakmp::v1::ExchangeType;
use isakmp::v1::PayloadType;
use isakmp::zerocopy::FromBytes;

use crate::v1::definitions::Header;
use crate::v1::errors::IsakmpParseError;

/// Parse the header
pub fn parse_header(buf: &[u8]) -> Result<Header, IsakmpParseError> {
    const HEADER_SIZE: usize = size_of::<isakmp::v1::Header>();

    let header = isakmp::v1::Header::ref_from_prefix(&buf[..HEADER_SIZE])
        .ok_or(IsakmpParseError::BufferTooSmall)?;

    Ok(Header {
        initiator_cookie: header.initiator_cookie.get(),
        responder_cookie: header.responder_cookie.get(),
        major_version: header.version >> 4,
        minor_version: header.version << 4,
        flags: header.flags,
        exchange_mode: ExchangeType::try_from(header.exchange_type)?,
        length: header.length.get(),
        message_id: header.message_id.get(),
        next_payload: PayloadType::try_from(header.next_payload)?,
    })
}
