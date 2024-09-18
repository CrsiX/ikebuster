//! Parser for the notification payload

use isakmp::v1::NotifyMessageType;
use isakmp::v1::PayloadType;
use isakmp::v1::StaticNotificationPayload;
use isakmp::zerocopy::FromBytes;

use crate::v1::definitions::NotificationPayload;
use crate::v1::errors::IsakmpParseError;

/// Parse a notification payload
pub fn parse_notification(buf: &[u8]) -> Result<NotificationPayload, IsakmpParseError> {
    let static_part =
        StaticNotificationPayload::ref_from_prefix(buf).ok_or(IsakmpParseError::BufferTooSmall)?;

    if static_part.generic_payload_header.reserved != 0 {
        return Err(IsakmpParseError::UnexpectedPayload);
    }

    let notification = NotificationPayload {
        next_payload: PayloadType::try_from(static_part.generic_payload_header.next_payload)?,
        length: static_part.generic_payload_header.payload_length.get(),
        protocol_id: static_part.protocol_id,
        notify_message_type: NotifyMessageType::try_from(static_part.notify_message_type.get())?,
        notification: buf[size_of::<StaticNotificationPayload>()..].to_vec(),
    };

    Ok(notification)
}
