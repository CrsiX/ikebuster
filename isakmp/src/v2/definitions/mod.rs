mod params;

pub use super::super::v1::definitions::GenericPayloadHeader;
pub use super::super::v1::definitions::Header;

/// When parsing a parameter from u8, there are several "regions" in the definitions
/// that can't be defined by Rusts enum. Typically, the last two regions of the
/// parameter definitions are unassigned and/or reserved for private use.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum UnparseableParameter {
    /// The parameter is reserved and must not be used, as it may conflict with older standards
    Reserved,
    /// The parameter has no recognized meaning by any known standard
    Unassigned,
    /// The parameter is reserved for Private Use by proprietary implementations
    /// and not part of a standard
    PrivateUse,
    /// The parameter can not reach the value this resolves to,
    /// as such the packet where it originates from must be invalid
    OutOfRange,
}
