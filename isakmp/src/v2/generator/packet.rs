use crate::v2::definitions::params::{PayloadType, FLAG_INITIATOR, FLAG_RESPONSE};
use crate::v2::definitions::{Header, IKEv2};
use crate::v2::generator::{GeneratorError, ESTIMATED_PAYLOAD_LENGTH};
use zerocopy::network_endian::{U32, U64};
use zerocopy::AsBytes;

impl IKEv2<'_> {
    fn try_build(&self) -> Result<Vec<u8>, GeneratorError> {
        if self.payloads.len() >= 255 {
            return Err(GeneratorError::TooManyPayloads);
        }
        let mut payloads = Vec::with_capacity(ESTIMATED_PAYLOAD_LENGTH * self.payloads.len());
        for (i, payload) in self.payloads.iter().enumerate() {
            payloads.extend(payload.try_build(match self.payloads.get(i + 1) {
                None => PayloadType::NoNextPayload,
                Some(next) => next.into(),
            })?);
        }

        let packet_length = 28 + payloads.len() as u32;
        let header = Header {
            initiator_cookie: U64::from(self.initiator_cookie),
            responder_cookie: U64::from(self.responder_cookie),
            next_payload: match self.payloads.first() {
                None => PayloadType::NoNextPayload,
                Some(t) => t.into(),
            } as u8,
            version: 0b00100000, // IKEv2
            exchange_type: self.exchange_type as u8,
            flags: (if self.initiator { FLAG_INITIATOR } else { 0 })
                | (if self.response { FLAG_RESPONSE } else { 0 }),
            message_id: U32::from(self.message_id),
            length: U32::from(packet_length),
        };

        let mut packet = Vec::with_capacity(packet_length as usize);
        packet.extend_from_slice(header.as_bytes());
        packet.extend(payloads);
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::ExchangeType;
    use crate::v2::definitions::IKEv2;

    #[test]
    fn empty() {
        assert_eq!(
            IKEv2 {
                initiator_cookie: 1337133713371337,
                responder_cookie: 301030307,
                exchange_type: ExchangeType::IkeSaInit,
                initiator: true,
                response: false,
                message_id: 999999999,
                payloads: vec![],
            }
            .try_build()
            .unwrap(),
            vec![
                0x00, 0x04, 0xc0, 0x1d, 0xb4, 0x00, 0xb0, 0xc9, // initiator
                0x00, 0x00, 0x00, 0x00, 0x11, 0xf1, 0x5b, 0xa3, // responder
                0x00, // next payload
                0x20, // version
                0x22, // exchange type
                0x08, // flags
                0x3b, 0x9a, 0xc9, 0xff, // message ID
                0x00, 0x00, 0x00, 0x1c // length
            ]
        )
    }
}
