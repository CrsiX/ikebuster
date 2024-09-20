//! Helper functions

use ike_parser::v1::definitions::DataAttribute;
use isakmp::v1::AttributeType;
use isakmp::v1::AuthenticationMethod;
use isakmp::v1::EncryptionAlgorithm;
use isakmp::v1::GroupDescription;
use isakmp::v1::GroupType;
use isakmp::v1::HashAlgorithm;
use isakmp::v1::LifeType;

fn format_attribute_type(attribute_type: &AttributeType) -> &'static str {
    match attribute_type {
        AttributeType::Reserved => "Reserved",
        AttributeType::EncryptionAlgorithm => "EncryptionAlgorithm",
        AttributeType::HashAlgorithm => "HashAlgorithm",
        AttributeType::AuthenticationMethod => "AuthenticationMethod",
        AttributeType::GroupDescription => "GroupDescription",
        AttributeType::GroupType => "GroupType",
        AttributeType::GroupPrime => "GroupPrime",
        AttributeType::GroupGeneratorOne => "GroupGeneratorOne",
        AttributeType::GroupGeneratorTwo => "GroupGeneratorTwo",
        AttributeType::GroupCurveA => "GroupCurveA",
        AttributeType::GroupCurveB => "GroupCurveB",
        AttributeType::LifeType => "Lifetime",
        AttributeType::LifeDuration => "LifeDuration",
        AttributeType::PRF => "PRF",
        AttributeType::KeyLength => "KeyLength",
        AttributeType::FieldSize => "FieldSize",
        AttributeType::GroupOrder => "GroupOrder",
    }
}

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
                format_attribute_type(&attr.attribute_type),
                format_attribute_value_short(&attr.attribute_type, attr.attribute_value)
            )
        }
        DataAttribute::DataAttributeLong(attr) => {
            format!(
                "{}={:?}",
                format_attribute_type(&attr.attribute_type),
                attr.attribute_value
            )
        }
    }
}
