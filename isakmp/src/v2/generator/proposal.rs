use crate::v2::definitions::header::ProposalHeader;
use crate::v2::definitions::{Proposal, Transform};
use crate::v2::generator::EXPECTED_TRANSFORM_LENGTH;
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
        let mut transforms = Vec::with_capacity(EXPECTED_TRANSFORM_LENGTH * self.len());
        let chain_iterator = self
            .encryption_algorithms
            .iter()
            .cloned()
            .map(|(e, o)| Transform::Encryption(e, o))
            .chain(
                self.pseudo_random_functions
                    .iter()
                    .cloned()
                    .map(Transform::PseudoRandomFunction),
            )
            .chain(
                self.integrity_algorithms
                    .iter()
                    .cloned()
                    .map(Transform::Integrity),
            )
            .chain(
                self.key_exchange_methods
                    .iter()
                    .cloned()
                    .map(Transform::KeyExchange),
            )
            .chain(
                self.sequence_numbers
                    .iter()
                    .cloned()
                    .map(Transform::SequenceNumber),
            );
        for (i, transform) in chain_iterator.enumerate() {
            transforms.extend(transform.build(i == self.len() - 1));
        }

        let packet_length = 8 + self.spi.len() as u16 + transforms.len() as u16;
        let header = ProposalHeader {
            last_substruct: if last { 0 } else { 2 },
            reserved: 0,
            proposal_length: U16::from(packet_length),
            proposal_num: num,
            protocol_id: self.protocol as u8,
            spi_size: self.spi.len() as u8,
            num_transforms: self.len() as u8,
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
    use crate::v2::definitions::Proposal;

    #[test]
    fn empty() {
        assert_eq!(
            Proposal::new_empty(SecurityProtocol::InternetKeyExchange, None).build(1, true),
            vec![0x00, 0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00]
        );
        assert_eq!(
            Proposal::new_empty(SecurityProtocol::AuthenticationHeader, None).build(0x42, false),
            vec![0x02, 0x00, 0x00, 0x08, 0x42, 0x02, 0x00, 0x00]
        );
        assert_eq!(
            Proposal::new_empty(
                SecurityProtocol::InternetKeyExchange,
                Some(vec![0x13, 0x37])
            )
            .build(1, true),
            vec![0x00, 0x00, 0x00, 0x0a, 0x01, 0x01, 0x02, 0x00, 0x13, 0x37]
        );
    }

    #[test]
    fn single() {
        let mut p = Proposal::new_empty(SecurityProtocol::InternetKeyExchange, None);
        p.key_exchange_methods.push(KeyExchangeMethod::Curve448);
        assert_eq!(
            p.build(1, true),
            vec![
                0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x04, 0x00,
                0x00, 0x20
            ]
        );
    }

    #[test]
    fn full() {
        let mut p = Proposal::new_empty(SecurityProtocol::InternetKeyExchange, None);
        p.encryption_algorithms
            .push((EncryptionAlgorithm::AesCbc, Some(256)));
        p.pseudo_random_functions
            .push(PseudorandomFunction::HmacSha2_256);
        p.integrity_algorithms
            .push(IntegrityAlgorithm::HmacSha2_256_128);
        p.key_exchange_methods.push(KeyExchangeMethod::Curve25519);
        assert_eq!(
            p.build(4, true),
            vec![
                0x00, 0x00, 0x00, 0x2c, 0x04, 0x01, 0x00, 0x04, // proposal header
                0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0c, // encryption header
                0x80, 0x0e, 0x01, 0x00, // encryption payload
                0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, // integrity
                0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c, // PRF
                0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1f // KE
            ]
        );
    }
}
