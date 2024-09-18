//! Parser of the vendor id

use isakmp::v1::PayloadType;
use isakmp::zerocopy::FromBytes;

use crate::v1::definitions::VendorIDPayload;
use crate::v1::errors::IsakmpParseError;

/// Parse a vendor id
pub fn parse_vendor_id(buf: &[u8]) -> Result<VendorIDPayload, IsakmpParseError> {
    let static_part = isakmp::v1::StaticVendorIDPayload::ref_from_prefix(buf)
        .ok_or(IsakmpParseError::BufferTooSmall)?;

    if static_part.generic_payload_header.reserved != 0 {
        return Err(IsakmpParseError::UnexpectedPayload);
    }

    let static_size = size_of::<isakmp::v1::StaticVendorIDPayload>();
    let vendor_id =
        buf[static_size..static_part.generic_payload_header.payload_length.get() as usize].to_vec();

    Ok(VendorIDPayload {
        length: static_part.generic_payload_header.payload_length.get(),
        next_payload: PayloadType::try_from(static_part.generic_payload_header.next_payload)?,
        vendor_id,
    })
}
