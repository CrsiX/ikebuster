use crate::v2::definitions::params::TransformType;
use crate::v2::definitions::Transform;
use zerocopy::network_endian::U16;
use zerocopy::AsBytes;

impl Transform {
    /// Convert a [Transform] into a network-level vector of bytes
    ///
    /// The argument `last` defines if any transform is following this transform (false)
    /// or if this transform is the last transform in the proposal payload (true).
    pub fn build(&self, last: bool) -> Vec<u8> {
        let (t_type, t_id, attributes) = match self {
            Transform::Encryption((algorithm, attribute)) => (
                TransformType::EncryptionAlgorithm,
                U16::new(*algorithm as u16),
                match attribute {
                    None => vec![],
                    Some(v) => v.build(),
                },
            ),
            Transform::PseudoRandomFunction(function) => (
                TransformType::PseudoRandomFunction,
                U16::new(*function as u16),
                vec![],
            ),
            Transform::Integrity(integrity) => (
                TransformType::IntegrityAlgorithm,
                U16::new(*integrity as u16),
                vec![],
            ),
            Transform::KeyExchange(exchange_method) => (
                TransformType::KeyExchangeMethod,
                U16::new(*exchange_method as u16),
                vec![],
            ),
            Transform::SequenceNumber(sequence_number) => (
                TransformType::SequenceNumber,
                U16::new(*sequence_number as u16),
                vec![],
            ),
        };

        let packet_length = 8 + attributes.len() as u16;
        let mut packet = Vec::with_capacity(packet_length as usize);
        packet.push(if last { 0 } else { 3 });
        packet.push(0);
        packet.extend_from_slice(U16::from(packet_length).as_bytes());
        packet.push(t_type as u8);
        packet.push(0);
        packet.extend_from_slice(t_id.as_bytes());
        packet.extend(attributes);
        packet
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::params::EncryptionAlgorithm;
    use crate::v2::definitions::params::KeyExchangeMethod;
    use crate::v2::definitions::{Attribute, Transform};

    #[test]
    fn key_exchange() {
        assert_eq!(
            Transform::KeyExchange(KeyExchangeMethod::Curve25519).build(true),
            vec![0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1f]
        );
        assert_eq!(
            Transform::KeyExchange(KeyExchangeMethod::Curve25519).build(false),
            vec![0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1f]
        );
    }

    #[test]
    fn encryption() {
        assert_eq!(
            Transform::Encryption((
                EncryptionAlgorithm::CamelliaCtr,
                Some(Attribute::KeyLength(192))
            ))
            .build(true),
            vec![0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x18, 0x80, 0x0e, 0x00, 0xc0]
        );
        assert_eq!(
            Transform::Encryption((EncryptionAlgorithm::AesCbc, Some(Attribute::KeyLength(128))))
                .build(false),
            vec![0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0c, 0x80, 0x0e, 0x00, 0x80]
        )
    }
}
