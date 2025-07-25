//! Implementation of parsers, definitions and message generation for IKEv2

pub mod definitions;
pub mod generator;
pub mod parser;

/// Constant value for IKEv2 in ISAKMP packets, as <major>.<minor> in 4 bits each,
/// where the <major> is 2 and the <minor> is zero.
pub const IKE_2_VERSION_VALUE: u8 = 0b00100000;

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::{
        EncryptionAlgorithm, ExchangeType, IntegrityAlgorithm, KeyExchangeMethod, PayloadType,
        PseudorandomFunction, SecurityProtocol,
    };
    use crate::v2::definitions::{IKEv2, Payload, Proposal, SecurityAssociation, Transform};

    #[test]
    #[allow(clippy::unwrap_used)]
    fn generate_and_parse_sa() {
        let mut p = Proposal::new_empty(
            SecurityProtocol::InternetKeyExchange,
            Some(vec![0x13, 0x37]),
        );
        p.add(vec![Transform::Encryption(
            EncryptionAlgorithm::Blowfish,
            Some(128),
        )]);
        let sa = SecurityAssociation { proposals: vec![p] };
        let generated_sa = sa.try_build(PayloadType::NoNextPayload).unwrap();
        let parsed_sa = SecurityAssociation::try_parse(generated_sa.as_slice()).unwrap();
        assert_eq!(sa, parsed_sa);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn generate_and_parse_full_sa() {
        let mut p = Proposal::new_empty(SecurityProtocol::InternetKeyExchange, Some(vec![]));
        p.add(vec![
            Transform::Integrity(IntegrityAlgorithm::HmacSha2_256_128),
            Transform::Integrity(IntegrityAlgorithm::HmacSha2_512_256),
            Transform::PseudoRandomFunction(PseudorandomFunction::HmacSha2_256),
            Transform::PseudoRandomFunction(PseudorandomFunction::HmacSha2_384),
            Transform::PseudoRandomFunction(PseudorandomFunction::HmacSha2_512),
            Transform::KeyExchange(KeyExchangeMethod::Curve448),
            Transform::KeyExchange(KeyExchangeMethod::Curve25519),
            Transform::Encryption(EncryptionAlgorithm::AesGcm12, Some(31337)),
        ]);
        let sa = SecurityAssociation { proposals: vec![p] };
        let sa_repr = sa.try_build(PayloadType::KeyExchange).unwrap();
        let buff = vec![
            0x22, 0x00, 0x00, 0x50, // Security Association header
            0x00, 0x00, 0x00, 0x4c, 0x01, 0x01, 0x00, 0x08, // Proposal header
            0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x13, // Transform 1, encryption
            0x80, 0x0e, 0x7a, 0x69, // Transform 1, encryption, attributes
            0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, // Transform 2, PRF 1
            0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x06, // Transform 3, PRF 2
            0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x07, // Transform 4, PRF 3
            0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c, // Transform 5, integrity 1
            0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0e, // Transform 6, integrity 2
            0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x20, // Transform 7, KE 1
            0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1f, // Transform 8, KE 2
        ];
        assert_eq!(sa_repr, buff);
        let parsed_sa = SecurityAssociation::try_parse(&buff[4..]).unwrap();
        assert_eq!(sa, parsed_sa);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn generate_and_parse_sa_with_many_empty_proposals() {
        let mut sa = SecurityAssociation { proposals: vec![] };
        for i in 0..100 {
            sa.proposals.push(Proposal::new_empty(
                SecurityProtocol::InternetKeyExchange,
                Some(vec![i]),
            ));
        }
        let generated_sa = sa.try_build(PayloadType::NoNextPayload).unwrap();
        let parsed_sa = SecurityAssociation::try_parse(generated_sa.as_slice()).unwrap();
        assert_eq!(sa, parsed_sa);
        assert_eq!(sa.proposals.len(), 100);
        for i in 0..100 {
            assert_eq!(sa.proposals[i].spi[0], i as u8);
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn generate_and_parse_packet() {
        let nonce = vec![
            0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, //
            0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
        ];
        let ike = IKEv2 {
            initiator_cookie: 0x48cfb887c03b2e7f, // random data
            responder_cookie: 0x55bf4a6acd91535e, // random data
            exchange_type: ExchangeType::IkeSaInit,
            initiator: true,
            response: false,
            message_id: 0x661cf0d4, // random data
            payloads: vec![
                Payload::VendorID(vec![0x42]),
                Payload::Nonce(nonce.clone()),
                Payload::SecurityAssociation(SecurityAssociation { proposals: vec![] }),
                Payload::EncryptedAndAuthenticated(vec![0x54, 0x65, 0x73, 0x74]), // "Test"
            ],
        };
        let generated_packet = ike.try_build().unwrap();
        let parsed_ike = IKEv2::try_parse(generated_packet.as_slice()).unwrap();
        assert_eq!(ike, parsed_ike);
        assert_eq!(ike.payloads.len(), 4);
        assert_eq!(ike.payloads[0], Payload::VendorID(vec![0x42]));
        assert_eq!(ike.payloads[1], Payload::Nonce(nonce));
    }
}
