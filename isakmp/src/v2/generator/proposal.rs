use crate::v2::definitions::header::ProposalHeader;
use crate::v2::definitions::Proposal;
use zerocopy::network_endian::U16;
use zerocopy::AsBytes;

impl Proposal {
    /// Convert a [Proposal] into a network-level vector of bytes
    ///
    /// The argument `num` defines the number of the proposal in the list of
    /// proposals in a Security Association.
    ///
    /// The argument `last` defines if any proposal is following this proposal (false)
    /// or if this proposal is the last proposal in the Security Association payload (true).
    pub fn build(&self, num: u8, last: bool) -> Vec<u8> {
        let mut transforms = Vec::with_capacity(12 * self.transforms.len());
        for (i, transform) in self.transforms.iter().enumerate() {
            transforms.extend(transform.build(i == self.transforms.len() - 1));
        }

        let packet_length = 8 + self.spi.len() as u16 + transforms.len() as u16;
        let header = ProposalHeader {
            last_substruct: if last { 0 } else { 2 },
            reserved: 0,
            proposal_length: U16::from(packet_length),
            proposal_num: num,
            protocol_id: self.protocol as u8,
            spi_size: self.spi.len() as u8,
            num_transforms: self.transforms.len() as u8,
        };

        let mut packet = Vec::with_capacity(packet_length as usize);
        packet.extend_from_slice(header.as_bytes());
        packet.extend(self.spi.clone());
        packet.extend(transforms);
        packet
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::{
        EncryptionAlgorithm, IntegrityAlgorithm, PseudorandomFunction,
    };
    use crate::v2::definitions::params::{KeyExchangeMethod, SecurityProtocol};
    use crate::v2::definitions::{Proposal, Transform};

    #[test]
    fn empty() {
        assert_eq!(
            Proposal {
                protocol: SecurityProtocol::InternetKeyExchange,
                spi: vec![],
                transforms: vec![]
            }
            .build(1, true),
            vec![0x00, 0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00]
        );
        assert_eq!(
            Proposal {
                protocol: SecurityProtocol::AuthenticationHeader,
                spi: vec![],
                transforms: vec![]
            }
            .build(0x42, false),
            vec![0x02, 0x00, 0x00, 0x08, 0x42, 0x02, 0x00, 0x00]
        );
        assert_eq!(
            Proposal {
                protocol: SecurityProtocol::InternetKeyExchange,
                spi: vec![0x13, 0x37],
                transforms: vec![]
            }
            .build(1, true),
            vec![0x00, 0x00, 0x00, 0x0a, 0x01, 0x01, 0x02, 0x00, 0x13, 0x37]
        );
    }

    #[test]
    fn single() {
        assert_eq!(
            Proposal {
                protocol: SecurityProtocol::InternetKeyExchange,
                spi: vec![],
                transforms: vec![Transform::KeyExchange(KeyExchangeMethod::Curve448)]
            }
            .build(1, true),
            vec![
                0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x04, 0x00,
                0x00, 0x20
            ]
        );
    }

    #[test]
    fn full() {
        assert_eq!(
            Proposal {
                protocol: SecurityProtocol::InternetKeyExchange,
                spi: vec![],
                transforms: vec![
                    Transform::Encryption((EncryptionAlgorithm::AesCbc, Some(256))),
                    Transform::Integrity(IntegrityAlgorithm::HmacSha2_256_128),
                    Transform::PseudoRandomFunction(PseudorandomFunction::HmacSha2_256),
                    Transform::KeyExchange(KeyExchangeMethod::Curve25519)
                ],
            }
            .build(4, true),
            vec![
                0x00, 0x00, 0x00, 0x2c, 0x04, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x00,
                0x00, 0x0c, 0x80, 0x0e, 0x01, 0x00, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c,
                0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x04, 0x00,
                0x00, 0x1f
            ]
        );
    }
}
