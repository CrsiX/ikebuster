//! Convert payloads to transforms

use isakmp::v1::definitions::AttributeType;
use isakmp::v1::definitions::AuthenticationMethod;
use isakmp::v1::definitions::EncryptionAlgorithm;
use isakmp::v1::definitions::GroupDescription;
use isakmp::v1::definitions::HashAlgorithm;
use isakmp::v1::generator::Transform;
use isakmp::v1::parser::definitions::DataAttribute;
use isakmp::v1::parser::definitions::ProposalPayload;
use thiserror::Error;

/// Could not retrieve full transform
#[derive(Debug, Error)]
#[error("Invalid transform")]
pub struct InvalidTransform;

/// Build a vector of transforms from a given [ProposalPayload]
pub fn payload_to_transforms(
    payload: &ProposalPayload,
) -> Result<Vec<Transform>, InvalidTransform> {
    let mut v = vec![];

    for transform in &payload.transforms {
        let mut encryption_algorithm = None;
        let mut hash_algorithm = None;
        let mut authentication_method = None;
        let mut group_description = None;
        let mut key_size = None;

        for attr in &transform.sa_attributes {
            match attr {
                DataAttribute::DataAttributeShort(attr) => match attr.attribute_type {
                    AttributeType::EncryptionAlgorithm => {
                        encryption_algorithm = Some(
                            EncryptionAlgorithm::try_from(attr.attribute_value)
                                .map_err(|_| InvalidTransform)?,
                        )
                    }
                    AttributeType::HashAlgorithm => {
                        hash_algorithm = Some(
                            HashAlgorithm::try_from(attr.attribute_value)
                                .map_err(|_| InvalidTransform)?,
                        );
                    }
                    AttributeType::AuthenticationMethod => {
                        authentication_method = Some(
                            AuthenticationMethod::try_from(attr.attribute_value)
                                .map_err(|_| InvalidTransform)?,
                        );
                    }
                    AttributeType::GroupDescription => {
                        group_description = Some(
                            GroupDescription::try_from(attr.attribute_value)
                                .map_err(|_| InvalidTransform)?,
                        );
                    }
                    AttributeType::KeyLength => key_size = Some(attr.attribute_value),
                    _ => {}
                },
                DataAttribute::DataAttributeLong(attr) => {
                    let a = attr
                        .attribute_value
                        .get(0)
                        .map(|x| *x)
                        .ok_or(InvalidTransform)?;
                    let b = attr
                        .attribute_value
                        .get(1)
                        .map(|x| *x)
                        .ok_or(InvalidTransform)?;

                    let value = u16::from_be_bytes([a, b]);

                    match attr.attribute_type {
                        AttributeType::EncryptionAlgorithm => {
                            encryption_algorithm = Some(
                                EncryptionAlgorithm::try_from(value)
                                    .map_err(|_| InvalidTransform)?,
                            )
                        }
                        AttributeType::HashAlgorithm => {
                            hash_algorithm =
                                Some(HashAlgorithm::try_from(value).map_err(|_| InvalidTransform)?);
                        }
                        AttributeType::AuthenticationMethod => {
                            authentication_method = Some(
                                AuthenticationMethod::try_from(value)
                                    .map_err(|_| InvalidTransform)?,
                            );
                        }
                        AttributeType::GroupDescription => {
                            group_description = Some(
                                GroupDescription::try_from(value).map_err(|_| InvalidTransform)?,
                            );
                        }
                        AttributeType::KeyLength => key_size = Some(value),
                        _ => {}
                    }
                }
            }
        }

        v.push(Transform {
            encryption_algorithm: encryption_algorithm.ok_or_else(|| InvalidTransform)?,
            hash_algorithm: hash_algorithm.ok_or_else(|| InvalidTransform)?,
            authentication_method: authentication_method.ok_or_else(|| InvalidTransform)?,
            group_description: group_description.ok_or_else(|| InvalidTransform)?,
            key_size,
        });
    }

    Ok(v)
}
