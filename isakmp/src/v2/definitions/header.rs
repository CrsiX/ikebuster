//! Module containing network level header structs for pieces of the protocol

use super::params::{SecurityProtocol, TransformType};
use zerocopy::network_endian::U16;
use zerocopy::{AsBytes, FromBytes, FromZeroes, Unaligned};

/// Protocol header for a Proposal
///
/// For IKEv2, a proposal must include transformations for encryption,
/// pseudo-random number generation, integrity and the Diffie-Hellman group.
#[derive(Debug, FromBytes, FromZeroes, AsBytes, Unaligned, Copy, Clone)]
#[repr(C, packed)]
pub struct ProposalHeader {
    /// Specification whether the Proposal is the last of the Security Association, uses
    /// value 0 for the last and value 2 for any other (although it could be inferred
    /// from the size information in each header, it is still mandated by the spec)
    pub last_substruct: u8,
    /// Reserved, must be zero and must be ignored on receipt
    pub reserved: u8,
    /// Length in octets of the current Proposal, including the header itself
    pub proposal_length: U16,
    /// Number of this Proposal in the Security Association; it must be 1 for the first
    /// Proposal, and it must be incremented by 1 for each following Proposal; when the
    /// receiver accepts a proposal, the number must match exactly this number
    pub proposal_num: u8,
    /// Identifier for the protocol inside the Proposal, it is IKE in this project
    /// and therefore should be set to 1; see [SecurityProtocol]
    pub protocol_id: u8,
    /// Size of the SPI (Security Parameter Indexes) in octets used in subsequent SA
    /// negotiations; it must be 0 for the first negotiation, but since this project
    /// does not support subsequent negotiations, it is always 0
    pub spi_size: u8,
    /// Number of transformations
    pub num_transforms: u8,
    // omitted: the variable-size sending entity's SPI for re-negotiations
    // following: a list of Transforms
}

/// Protocol header for a Transform
#[derive(Debug, FromBytes, FromZeroes, AsBytes, Unaligned, Copy, Clone)]
#[repr(C, packed)]
pub struct TransformHeader {
    /// Specification whether the Transform is the last of the Proposal, uses
    /// value 0 for the last and value 3 for any other (although it could be inferred
    /// from the size information in each header, it is still mandated by the spec)
    pub last_substruct: u8,
    /// Reserved, must be zero and must be ignored on receipt
    pub reserved: u8,
    /// Length in octets of the current Transform, including the header itself
    pub transform_length: U16,
    /// Type of transformation found in the body of this payload;
    /// see RFC 7296, section 3.3.2; also see [TransformType]
    pub transform_type: u8,
    /// Reserved, must be zero and must be ignored on receipt
    pub reserved2: u8,
    /// Identifier for the actually used transformation inside the Transform body,
    /// where the ID depends on the [TransformType]; for example, if the transform type
    /// was 1 (encryption algorithms) and the transform ID was 20, then the selected
    /// encryption algorithm of this transform was AES-GCM256
    pub transform_id: U16,
}

/// Protocol field for fixed-length attributes of a Transform as per RFC 7296, section 3.3.5
#[derive(Debug, FromBytes, FromZeroes, AsBytes, Unaligned, Copy, Clone)]
#[repr(C, packed)]
pub struct AttributeHeaderTV {
    /// Type of the attribute encoded in the value field; the top bit must be set to 1
    pub attribute_type: U16,
    /// Fixed-length attribute value specific for a transformation, currently only the
    /// key length is supported as valid attribute
    pub attribute_value: U16,
}

// TODO: Key Exchange Header
// TODO: Certificate Header
// TODO: Nonce Header
// TODO: Notify Header
// TODO: Delete Header
// TODO: Vendor ID Header
