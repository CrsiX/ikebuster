//! The high level definitions of parts of an isakmp message

use crate::v1::definitions::AttributeType;
use crate::v1::definitions::DomainOfInterpretation;
use crate::v1::definitions::ExchangeType;
use crate::v1::definitions::NotifyMessageType;
use crate::v1::definitions::PayloadType;

/// The high level representation of an ISAKMP message, version 1
#[derive(Debug, Clone)]
pub struct Packet {
    /// The header of the message
    pub header: Header,
    /// Notification payloads
    pub notification_payloads: Vec<NotificationPayload>,
    /// Security Association payloads
    pub security_associations: Vec<SecurityAssociationPayload>,
    /// List of vendor ids
    pub vendor_ids: Vec<VendorIDPayload>,
    /// List of transform payloads
    pub transforms: Vec<TransformPayload>,
    /// List of proposal payloads
    pub proposals: Vec<ProposalPayload>,
}

/// High level presentation of an ISAKMP header
#[derive(Debug, Clone)]
pub struct Header {
    /// Cookie of the initiator party
    pub initiator_cookie: u64,
    /// Responder cookie
    pub responder_cookie: u64,
    /// The type of the next payload
    pub next_payload: PayloadType,
    /// Major version
    pub major_version: u8,
    /// Minor version
    pub minor_version: u8,
    /// Mode of exchange
    pub exchange_mode: ExchangeType,
    /// Additional flags
    pub flags: u8,
    /// Phase 1: Set to 0
    /// Phase 2: Set to random value
    pub message_id: u32,
    /// Length of the total message
    pub length: u32,
}

/// High-level representation of a Notification payload
#[derive(Debug, Clone)]
pub struct NotificationPayload {
    /// The type of the next payload
    pub next_payload: PayloadType,
    /// Length of this payload including header and sub-payloads
    pub length: u16,
    /// Specifies the protocol identifier for the current notification.
    ///
    /// Examples might include ISAKMP, IPSEC ESP, IPSEC AH, OSPF, TLS, etc.
    // TODO: Replace with enum
    pub protocol_id: u8,
    /// Notify message type
    pub notify_message_type: NotifyMessageType,
    /// Notification interpreted as a string
    pub notification: Vec<u8>,
}

/// High-level representation of a security association payload
#[derive(Debug, Clone)]
pub struct SecurityAssociationPayload {
    /// The type of the next payload
    pub next_payload: PayloadType,
    /// Length of this payload including header and sub-payloads
    pub length: u16,
    /// The domain of interpretation
    pub domain_of_interpretation: DomainOfInterpretation,
    /// A DOI-specific field that identifies the situation under which this negotiation
    /// is taking place.
    pub situation: Vec<u8>,
    /// Proposal payloads
    pub proposal_payload: Vec<ProposalPayload>,
}

/// High-level representation of a proposal payload
#[derive(Debug, Clone)]
pub struct ProposalPayload {
    /// The type of the next payload
    pub next_payload: PayloadType,
    /// Length of this payload including header and sub-payloads
    pub length: u16,
    /// Identifies the Proposal number for the current payload
    pub proposal_no: u8,
    /// Specifies the protocol identifier for the current notification.
    ///
    /// Examples might include ISAKMP, IPSEC ESP, IPSEC AH, OSPF, TLS, etc.
    // TODO: Replace with enum
    pub protocol_id: u8,
    /// Size of the SPI field
    pub spi_size: u8,
    /// Specifies the number of transforms for the Proposal. Each of these is contained in
    /// a Transform payload.
    pub no_of_transforms: u8,
    /// The sending entity's SPI. In the event the SPI Size is not a multiple of 4 octets,
    /// there is no padding applied to the payload, however, it can be applied
    /// at the end of the message.
    pub spi: Vec<u8>,
    /// Transform payloads
    pub transforms: Vec<TransformPayload>,
}

/// High-level representation of a transform payload
#[derive(Debug, Clone)]
pub struct TransformPayload {
    /// The type of the next payload
    pub next_payload: PayloadType,
    /// Length of this payload including header and sub-payloads
    pub length: u16,
    /// Identifies the Transform number for the current payload. If there is more than one transform
    /// proposed for a specific protocol within the Proposal payload, then each Transform payload
    /// has a unique Transform number
    pub transform_no: u8,
    /// Specifies the Transform identifier for the protocol within the current proposal.
    /// These transforms are defined by the DOI and are dependent on the protocol being negotiated.
    // TODO: Make enum
    pub transform_id: u8,
    /// This field contains the security association attributes as defined for the transform given
    /// in the Transform-Id field.
    pub sa_attributes: Vec<DataAttribute>,
}

/// High-level representation of a vendor id payload
#[derive(Debug, Clone)]
pub struct VendorIDPayload {
    /// The type of the next payload
    pub next_payload: PayloadType,
    /// Length of this payload including header and sub-payloads
    pub length: u16,
    /// Hashed vendor id string
    pub vendor_id: Vec<u8>,
}

/// Possible data attributes
#[derive(Debug, Clone)]
pub enum DataAttribute {
    /// Short data attribute with static value
    DataAttributeShort(DataAttributeShort),
    /// Variable length data attribute
    DataAttributeLong(DataAttributeLong),
}

/// High-level representation of a short data attribute
#[derive(Debug, Clone)]
pub struct DataAttributeShort {
    /// Type of the data attribute
    pub attribute_type: AttributeType,
    /// Value of the data attributee
    pub attribute_value: u16,
}

/// High-level representation of a variable-length data attribute
#[derive(Debug, Clone)]
pub struct DataAttributeLong {
    /// Type of the data attribute
    pub attribute_type: AttributeType,
    /// Value of the data attribute
    pub attribute_value: Vec<u8>,
}
