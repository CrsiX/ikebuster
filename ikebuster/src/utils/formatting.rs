//! Formatting helpers

use isakmp::v1::definitions::AttributeType;
use isakmp::v1::definitions::AuthenticationMethod;
use isakmp::v1::definitions::EncryptionAlgorithm;
use isakmp::v1::definitions::GroupDescription;
use isakmp::v1::definitions::GroupType;
use isakmp::v1::definitions::HashAlgorithm;
use isakmp::v1::definitions::LifeType;
use isakmp::v1::parser::definitions::DataAttribute;

fn format_attribute_value_short(attribute_type: &AttributeType, attribute_value: u16) -> String {
    match attribute_type {
        AttributeType::Reserved => attribute_value.to_string(),
        AttributeType::EncryptionAlgorithm => EncryptionAlgorithm::try_from(attribute_value)
            .map_or_else(|x| format!("{x:?}"), |x| format!("{x:?}")),
        AttributeType::HashAlgorithm => HashAlgorithm::try_from(attribute_value)
            .map_or_else(|x| format!("{x:?}"), |x| format!("{x:?}")),
        AttributeType::AuthenticationMethod => AuthenticationMethod::try_from(attribute_value)
            .map_or_else(|x| format!("{x:?}"), |x| format!("{x:?}")),
        AttributeType::GroupDescription => GroupDescription::try_from(attribute_value)
            .map_or_else(|x| format!("{x:?}"), |x| format!("{x:?}")),
        AttributeType::GroupType => GroupType::try_from(attribute_value)
            .map_or_else(|x| format!("{x:?}"), |x| format!("{x:?}")),
        AttributeType::LifeType => LifeType::try_from(attribute_value)
            .map_or_else(|x| format!("{x:?}"), |x| format!("{x:?}")),
        _ => format!("{attribute_value}"),
    }
}

/// Format a given data attribute
pub fn format_attribute(attribute: &DataAttribute) -> String {
    match attribute {
        DataAttribute::DataAttributeShort(attr) => {
            format!(
                "{}={}",
                attr.attribute_type,
                format_attribute_value_short(&attr.attribute_type, attr.attribute_value)
            )
        }
        DataAttribute::DataAttributeLong(attr) => {
            format!("{}={:?}", attr.attribute_type, attr.attribute_value)
        }
    }
}
