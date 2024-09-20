//! Parser of the vendor id

use zerocopy::FromBytes;

use crate::v1::definitions::PayloadType;
use crate::v1::parser::definitions::VendorIDPayload;
use crate::v1::parser::errors::IsakmpParseError;

/// Parse a vendor id
pub fn parse_vendor_id(buf: &[u8]) -> Result<VendorIDPayload, IsakmpParseError> {
    let static_part = crate::v1::definitions::StaticVendorIDPayload::ref_from_prefix(buf)
        .ok_or(IsakmpParseError::BufferTooSmall)?;

    if static_part.generic_payload_header.reserved != 0 {
        return Err(IsakmpParseError::UnexpectedPayload);
    }

    let static_size = size_of::<crate::v1::definitions::StaticVendorIDPayload>();
    let vendor_id =
        buf[static_size..static_part.generic_payload_header.payload_length.get() as usize].to_vec();

    Ok(VendorIDPayload {
        length: static_part.generic_payload_header.payload_length.get(),
        next_payload: PayloadType::try_from(static_part.generic_payload_header.next_payload)?,
        vendor_id,
    })
}
