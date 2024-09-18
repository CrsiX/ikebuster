//! Parsers for IKEv1

use isakmp::v1::ExchangeType;
use isakmp::v1::Header;
use isakmp::v1::PayloadType;

use crate::v1::definitions::Packet;
use crate::v1::errors::IsakmpParseError;
use crate::v1::payload::parse_next_payload;
use crate::v1::payload::GenericPayload;
use crate::v1::payload::Payload;

pub mod data_attribute;
pub mod definitions;
pub mod errors;
pub mod header;
pub mod payload;
pub mod payload_notification;
pub mod payload_proposal;
pub mod payload_sa;
pub mod payload_transform;
pub mod payload_vendor_id;

/// Parse an ISAKMP message
pub fn parse_packet(buf: &[u8]) -> Result<Packet, IsakmpParseError> {
    // Parse header
    let header = header::parse_header(buf)?;

    if header.exchange_mode == ExchangeType::None {
        return Err(IsakmpParseError::UnexpectedPayload);
    }

    // Construct packet
    let mut packet = Packet {
        header,
        notification_payloads: vec![],
        security_associations: vec![],
        proposals: vec![],
        transforms: vec![],
        vendor_ids: vec![],
    };

    let mut next_payload = packet.header.next_payload;
    let mut curr_offset = size_of::<Header>();

    loop {
        if next_payload == PayloadType::None {
            break;
        }

        let GenericPayload {
            payload_size,
            next_payload_type,
            payload,
        } = parse_next_payload(&buf[curr_offset..], next_payload)?;
        curr_offset += payload_size;
        next_payload = next_payload_type;

        match payload {
            Payload::Notification(notification) => packet.notification_payloads.push(notification),
            Payload::SecurityAssociation(security_association) => {
                packet.security_associations.push(security_association)
            }
            Payload::VendorID(vendor_id) => packet.vendor_ids.push(vendor_id),
            Payload::Proposal(proposal) => packet.proposals.push(proposal),
            Payload::Transform(transform) => packet.transforms.push(transform),
        }
    }

    Ok(packet)
}
