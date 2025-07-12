use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::{GenericPayloadHeader, SecurityAssociation};
use zerocopy::AsBytes;

impl SecurityAssociation {
    pub fn build(&self, next_payload: PayloadType) -> Vec<u8> {
        let mut proposals = Vec::with_capacity(256 * self.proposals.len());
        assert!(self.proposals.len() <= 254);
        for (i, proposal) in self.proposals.iter().enumerate() {
            proposals.extend(proposal.build(i as u8 + 1, i == self.proposals.len() - 1));
        }

        let packet_length = 4 + proposals.len() as u16;
        let header = GenericPayloadHeader {
            next_payload: next_payload as u8,
            reserved: 0,
            payload_length: packet_length.into(),
        };
        let mut packet = Vec::with_capacity(packet_length.into());
        packet.extend_from_slice(header.as_bytes());
        packet.extend(proposals);
        packet
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::{
        EncryptionAlgorithm, IntegrityAlgorithm, KeyExchangeMethod, PayloadType,
        PseudorandomFunction, SecurityProtocol,
    };
    use crate::v2::definitions::{Proposal, SecurityAssociation, Transform};

    #[test]
    fn empty() {
        assert_eq!(
            SecurityAssociation { proposals: vec![] }.build(PayloadType::NoNextPayload),
            vec![0x00, 0x00, 0x00, 0x04]
        )
    }

    #[test]
    fn empty_bodies() {
        assert_eq!(
            SecurityAssociation {
                proposals: vec![
                    Proposal {
                        protocol: SecurityProtocol::InternetKeyExchange,
                        spi: vec![],
                        transforms: vec![],
                    },
                    Proposal {
                        protocol: SecurityProtocol::InternetKeyExchange,
                        spi: vec![],
                        transforms: vec![],
                    },
                    Proposal {
                        protocol: SecurityProtocol::AuthenticationHeader,
                        spi: vec![],
                        transforms: vec![],
                    },
                    Proposal {
                        protocol: SecurityProtocol::EncapsulatingSecurityPayload,
                        spi: vec![0x13, 0x37],
                        transforms: vec![],
                    }
                ]
            }
            .build(PayloadType::NoNextPayload),
            vec![
                0x00, 0x00, 0x00, 0x26, // Security Association
                0x02, 0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, // Proposal 1
                0x02, 0x00, 0x00, 0x08, 0x02, 0x01, 0x00, 0x00, // Proposal 2
                0x02, 0x00, 0x00, 0x08, 0x03, 0x02, 0x00, 0x00, // Proposal 3
                0x00, 0x00, 0x00, 0x0a, 0x04, 0x03, 0x02, 0x00, 0x13, 0x37 // Proposal 4
            ]
        )
    }

    #[test]
    fn simple_full() {
        assert_eq!(
            SecurityAssociation {
                proposals: vec![Proposal {
                    protocol: SecurityProtocol::InternetKeyExchange,
                    spi: vec![0x42],
                    transforms: vec![
                        Transform::Encryption(EncryptionAlgorithm::AesGcm16, Some(256)),
                        Transform::Integrity(IntegrityAlgorithm::HmacSha2_256_128),
                        Transform::PseudoRandomFunction(PseudorandomFunction::HmacSha2_256),
                        Transform::KeyExchange(KeyExchangeMethod::Curve448)
                    ],
                }]
            }
            .build(PayloadType::KeyExchange),
            vec![
                0x22, 0x00, 0x00, 0x31, // Security Association header
                0x00, 0x00, 0x00, 0x2d, 0x01, 0x01, 0x01, 0x04, // Proposal header
                0x42, // SPI
                0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x14, // Transform 1
                0x80, 0x0e, 0x01, 0x00, // Transform 1 attributes
                0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c, // Transform 2
                0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, // Transform 3
                0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x20 // Transform 4
            ]
        )
    }
}
