//! Parser for all payloads

use crate::v1::parser::definitions::NotificationPayload;
use crate::v1::parser::definitions::ProposalPayload;
use crate::v1::parser::definitions::SecurityAssociationPayload;
use crate::v1::parser::definitions::TransformPayload;
use crate::v1::parser::definitions::VendorIDPayload;
use crate::v1::parser::errors::IsakmpParseError;
use crate::v1::parser::payload_notification::parse_notification;
use crate::v1::parser::payload_proposal::parse_proposal;
use crate::v1::parser::payload_sa::parse_security_association;
use crate::v1::parser::payload_transform::parse_transform;
use crate::v1::parser::payload_vendor_id::parse_vendor_id;

/// All parsable payload types
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum Payload {
    Notification(NotificationPayload),
    SecurityAssociation(SecurityAssociationPayload),
    VendorID(VendorIDPayload),
    Proposal(ProposalPayload),
    Transform(TransformPayload),
}

/// Representation of a generic payload
#[derive(Debug, Clone)]
pub struct GenericPayload {
    /// Size of the payload
    pub payload_size: usize,
    /// type of the next payload
    pub next_payload_type: crate::v1::definitions::PayloadType,
    /// The payload itself
    pub payload: Payload,
}

/// Parse the next payload of the message
pub fn parse_next_payload(
    buf: &[u8],
    payload_type: crate::v1::definitions::PayloadType,
) -> Result<GenericPayload, IsakmpParseError> {
    match payload_type {
        crate::v1::definitions::PayloadType::None => Err(IsakmpParseError::UnexpectedPayload),
        crate::v1::definitions::PayloadType::Notification => {
            let notification = parse_notification(buf)?;

            Ok(GenericPayload {
                payload_size: notification.length as usize,
                next_payload_type: notification.next_payload,
                payload: Payload::Notification(notification),
            })
        }
        crate::v1::definitions::PayloadType::SecurityAssociation => {
            let sa = parse_security_association(buf)?;

            Ok(GenericPayload {
                payload_size: sa.length as usize,
                next_payload_type: sa.next_payload,
                payload: Payload::SecurityAssociation(sa),
            })
        }
        crate::v1::definitions::PayloadType::VendorID => {
            let vendor_id = parse_vendor_id(buf)?;

            Ok(GenericPayload {
                payload_size: vendor_id.length as usize,
                next_payload_type: vendor_id.next_payload,
                payload: Payload::VendorID(vendor_id),
            })
        }
        crate::v1::definitions::PayloadType::Proposal => {
            let proposal = parse_proposal(buf)?;

            Ok(GenericPayload {
                payload_size: proposal.length as usize,
                next_payload_type: proposal.next_payload,
                payload: Payload::Proposal(proposal),
            })
        }
        crate::v1::definitions::PayloadType::Transform => {
            let transform = parse_transform(buf)?;

            Ok(GenericPayload {
                payload_size: transform.length as usize,
                next_payload_type: transform.next_payload,
                payload: Payload::Transform(transform),
            })
        }
        _ => {
            todo!("Payload type {payload_type:?} not implemented yet");
        }
    }
}
