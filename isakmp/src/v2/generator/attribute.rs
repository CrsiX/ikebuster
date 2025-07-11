use crate::v2::definitions::header::AttributeHeaderTV;
use crate::v2::definitions::params::AttributeType;
use crate::v2::definitions::Attribute;
use zerocopy::network_endian::U16;
use zerocopy::AsBytes;

impl Attribute {
    fn build(&self) -> Vec<u8> {
        match self {
            Attribute::KeyLength(length) => Vec::from(
                AttributeHeaderTV {
                    attribute_type: U16::new(AttributeType::KeyLength as u16 + 0x8000),
                    attribute_value: U16::new(*length),
                }
                .as_bytes(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::v2::definitions::Attribute;

    #[test]
    fn test() {
        assert_eq!(
            Attribute::KeyLength(0).build(),
            vec![0x80, 0x0e, 0x00, 0x00]
        );
        assert_eq!(
            Attribute::KeyLength(128).build(),
            vec![0x80, 0x0e, 0x00, 0x80]
        );
        assert_eq!(
            Attribute::KeyLength(255).build(),
            vec![0x80, 0x0e, 0x00, 0xff]
        );
        assert_eq!(
            Attribute::KeyLength(256).build(),
            vec![0x80, 0x0e, 0x01, 0x00]
        );
        assert_eq!(
            Attribute::KeyLength(1337).build(),
            vec![0x80, 0x0e, 0x05, 0x39]
        );
    }
}
