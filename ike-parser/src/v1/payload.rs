//! Parser for all payloads

use crate::v1::definitions::NotificationPayload;
use crate::v1::definitions::ProposalPayload;
use crate::v1::definitions::SecurityAssociationPayload;
use crate::v1::definitions::TransformPayload;
use crate::v1::definitions::VendorIDPayload;
use crate::v1::errors::IsakmpParseError;
use crate::v1::payload_notification::parse_notification;
use crate::v1::payload_proposal::parse_proposal;
use crate::v1::payload_sa::parse_security_association;
use crate::v1::payload_transform::parse_transform;
use crate::v1::payload_vendor_id::parse_vendor_id;

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
    pub next_payload_type: isakmp::v1::PayloadType,
    /// The payload itself
    pub payload: Payload,
}

/// Parse the next payload of the message
pub fn parse_next_payload(
    buf: &[u8],
    payload_type: isakmp::v1::PayloadType,
) -> Result<GenericPayload, IsakmpParseError> {
    match payload_type {
        isakmp::v1::PayloadType::None => Err(IsakmpParseError::UnexpectedPayload),
        isakmp::v1::PayloadType::Notification => {
            let notification = parse_notification(buf)?;

            Ok(GenericPayload {
                payload_size: notification.length as usize,
                next_payload_type: notification.next_payload,
                payload: Payload::Notification(notification),
            })
        }
        isakmp::v1::PayloadType::SecurityAssociation => {
            let sa = parse_security_association(buf)?;

            Ok(GenericPayload {
                payload_size: sa.length as usize,
                next_payload_type: sa.next_payload,
                payload: Payload::SecurityAssociation(sa),
            })
        }
        isakmp::v1::PayloadType::VendorID => {
            let vendor_id = parse_vendor_id(buf)?;

            Ok(GenericPayload {
                payload_size: vendor_id.length as usize,
                next_payload_type: vendor_id.next_payload,
                payload: Payload::VendorID(vendor_id),
            })
        }
        isakmp::v1::PayloadType::Proposal => {
            let proposal = parse_proposal(buf)?;

            Ok(GenericPayload {
                payload_size: proposal.length as usize,
                next_payload_type: proposal.next_payload,
                payload: Payload::Proposal(proposal),
            })
        }
        isakmp::v1::PayloadType::Transform => {
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
