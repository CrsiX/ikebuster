use crate::v2::definitions::params::{
    EncryptionAlgorithm, ExchangeType, IntegrityAlgorithm, KeyExchangeMethod, NotifyErrorMessage,
    NotifyStatusMessage, PayloadType, PseudorandomFunction, SecurityProtocol,
};
use crate::v2::definitions::{
    GenericPayloadHeader, IKEv2, Notification, NotificationType, Payload, Proposal,
    SecurityAssociation, Transform,
};

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
    let parsed_sa = SecurityAssociation::try_parse(
        generated_sa.as_slice()[size_of::<GenericPayloadHeader>()..]
            .iter()
            .as_slice(),
    )
    .unwrap();
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
    let parsed_sa =
        SecurityAssociation::try_parse(&buff[size_of::<GenericPayloadHeader>()..]).unwrap();
    assert_eq!(sa, parsed_sa);
}

#[test]
#[allow(clippy::unwrap_used)]
fn generate_and_parse_sa_with_many_empty_proposals() {
    let mut sa = SecurityAssociation { proposals: vec![] };
    for i in 0..100 {
        sa.proposals.push(Proposal::new_empty(
            SecurityProtocol::InternetKeyExchange,
            Some(vec![i + 1]),
        ));
    }
    let generated_sa = sa.try_build(PayloadType::NoNextPayload).unwrap();
    let parsed_sa = SecurityAssociation::try_parse(
        generated_sa.as_slice()[size_of::<GenericPayloadHeader>()..]
            .iter()
            .as_slice(),
    )
    .unwrap();
    assert_eq!(sa, parsed_sa);
    assert_eq!(sa.proposals.len(), 100);
    for i in 0..100 {
        assert_eq!(sa.proposals[i].spi[0], 1 + i as u8);
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn generate_and_parse_notify() {
    let spi = [0x00, 0x01, 0x02, 0x03];
    let notify = Notification {
        variant: NotificationType::Error(NotifyErrorMessage::InvalidSpi),
        data: vec![0x13, 0x37],
        protocol: SecurityProtocol::EncapsulatingSecurityPayload,
        spi: Some(spi.to_vec()),
    };
    let generated_notify = notify.try_build(PayloadType::NoNextPayload).unwrap();
    let expected_result = vec![
        0x00, 0x00, 0x00, 0x0e, // Generic Payload Header
        0x03, 0x04, 0x00, 0x0b, // Notification header
        0x00, 0x01, 0x02, 0x03, // SPI
        0x13, 0x37, // Data
    ];
    assert_eq!(generated_notify, expected_result);
    let parsed_notify =
        Notification::try_parse(expected_result.as_slice()[4..].iter().as_slice()).unwrap();
    assert_eq!(notify, parsed_notify);
}

#[test]
#[allow(clippy::unwrap_used)]
fn generate_and_parse_notify2() {
    let notification = Notification {
        variant: NotificationType::Status(NotifyStatusMessage::SignatureHashAlgorithms),
        // Data meaning:
        //   Supported Signature Hash Algorithm: SHA2-256 (2)
        //   Supported Signature Hash Algorithm: SHA2-384 (3)
        //   Supported Signature Hash Algorithm: SHA2-512 (4)
        data: vec![0x00, 0x02, 0x00, 0x03, 0x00, 0x04],
        protocol: SecurityProtocol::Reserved,
        spi: None,
    };
    let generated_notify = notification.try_build(PayloadType::Notify).unwrap();
    let expected_result = vec![
        0x29, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x40, 0x2f, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
    ];
    assert_eq!(generated_notify, expected_result);
    let parsed_notify =
        Notification::try_parse(expected_result.as_slice()[4..].iter().as_slice()).unwrap();
    assert_eq!(notification, parsed_notify);
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
