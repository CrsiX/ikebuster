//! Parser of a Data Attribute

use zerocopy::FromBytes;

use crate::v1::definitions::AttributeType;
use crate::v1::parser::definitions::DataAttribute;
use crate::v1::parser::definitions::DataAttributeLong;
use crate::v1::parser::definitions::DataAttributeShort;
use crate::v1::parser::errors::IsakmpParseError;

/// Parse a data attribute
pub fn parse_data_attribute(buf: &[u8]) -> Result<(DataAttribute, usize), IsakmpParseError> {
    // Look at significant bit to determine whether to parse a short or long attribute
    let first = buf.first().ok_or(IsakmpParseError::BufferTooSmall)? >> 7;

    match first {
        // Long
        0 => {
            let attribute = crate::v1::definitions::StaticDataAttributeLong::ref_from_prefix(buf)
                .ok_or(IsakmpParseError::BufferTooSmall)?;

            let da_size = size_of::<crate::v1::definitions::StaticDataAttributeLong>();
            let attribute_size = da_size + attribute.attribute_length.get() as usize;

            let attribute_value = buf
                .get(da_size..attribute_size)
                .ok_or(IsakmpParseError::BufferTooSmall)?
                .to_vec();

            Ok((
                DataAttribute::DataAttributeLong(DataAttributeLong {
                    attribute_type: AttributeType::try_from(attribute.attribute_type.get())?,
                    attribute_value,
                }),
                attribute_size,
            ))
        }
        // Short
        1 => {
            let attribute = crate::v1::definitions::DataAttributeShort::ref_from_prefix(buf)
                .ok_or(IsakmpParseError::BufferTooSmall)?;

            Ok((
                DataAttribute::DataAttributeShort(DataAttributeShort {
                    // strip most significant bit
                    attribute_type: AttributeType::try_from(
                        attribute.attribute_type.get() & 0b0111_1111_1111_1111,
                    )?,
                    attribute_value: attribute.attribute_value.get(),
                }),
                size_of::<crate::v1::definitions::DataAttributeShort>(),
            ))
        }
        _ => unreachable!(),
    }
}
