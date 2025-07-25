use crate::v1::definitions::{GenericPayloadHeader, Header};
use crate::v2::definitions::params::{ExchangeType, PayloadType};
use crate::v2::definitions::SecurityAssociation;
use crate::v2::definitions::{IKEv2, Payload};
use crate::v2::parser::ParserError;
use crate::v2::IKE_2_VERSION_VALUE;
use log::warn;
use zerocopy::FromBytes;

impl IKEv2<'_> {
    /// Parse a byte slice into an [IKEv2] packet, if possible
    pub fn try_parse(buf: &[u8]) -> Result<Self, ParserError> {
        let header = Header::ref_from_prefix(buf).ok_or(ParserError::BufferTooSmall)?;
        if header.version != IKE_2_VERSION_VALUE {
            return Err(ParserError::WrongProtocol);
        }

        let mut offset = size_of::<Header>();
        let mut next_payload = PayloadType::try_from(header.next_payload)?;
        let mut payloads = vec![];

        loop {
            let (decoded_payload, current_size) = match next_payload {
                PayloadType::NoNextPayload => {
                    break;
                }
                PayloadType::SecurityAssociation => {
                    let (v, l, n) = SecurityAssociation::try_parse(&buf[offset..])?;
                    next_payload = n;
                    (Payload::SecurityAssociation(v), l)
                }
                //PayloadType::KeyExchange => Payload::KeyExchange(KeyExchange::try_parse(buf)?),
                PayloadType::Nonce => {
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    next_payload = n;
                    (Payload::Nonce(v), l)
                }
                //PayloadType::Notify => Payload::Notify(Notification::try_parse(buf)?),
                //PayloadType::Delete => {}
                PayloadType::VendorID => {
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    next_payload = n;
                    (Payload::VendorID(v), l)
                }
                PayloadType::EncryptedAndAuthenticated => {
                    let (v, l, n) = try_parse_generic(&buf[offset..])?;
                    // The encrypted payload must be the last payload of a packet,
                    // everything after it is ignored
                    if n != PayloadType::NoNextPayload {
                        warn!("Found a payload after Encrypted payload, which is illegal: {n:#?}");
                    }
                    next_payload = PayloadType::NoNextPayload;
                    (Payload::EncryptedAndAuthenticated(v), l)
                }
                _ => {
                    warn!("Unknown payload type ignored: {next_payload:#?}");
                    continue;
                }
            };
            offset += current_size;
            payloads.push(decoded_payload);
        }

        Ok(Self {
            initiator_cookie: header.initiator_cookie.get(),
            responder_cookie: header.responder_cookie.get(),
            exchange_type: ExchangeType::try_from(header.exchange_type)?,
            initiator: false, // TODO
            response: false,  // TODO
            message_id: header.message_id.get(),
            payloads,
        })
    }
}

/// Helper to parse all packets that only have a generic header
fn try_parse_generic(buf: &[u8]) -> Result<(Vec<u8>, usize, PayloadType), ParserError> {
    let header = GenericPayloadHeader::ref_from_prefix(buf).ok_or(ParserError::BufferTooSmall)?;
    let consumed = header.payload_length.get() as usize;
    Ok((
        buf[size_of::<GenericPayloadHeader>()..consumed].to_vec(),
        consumed,
        PayloadType::try_from(header.next_payload)?,
    ))
}
