use crate::v2::definitions::header::NotifyHeader;
use crate::v2::definitions::params::{NotifyErrorMessage, NotifyStatusMessage, SecurityProtocol};
use crate::v2::definitions::{Notification, NotificationType};
use crate::v2::parser::ParserError;
use zerocopy::FromBytes;

impl Notification {
    /// Parses a buffer into a [Notification]. The buffer must not contain the
    /// generic payload header. Fails if the buffer is empty.
    pub(crate) fn try_parse(buf: &[u8]) -> Result<Self, ParserError> {
        let notify_header =
            NotifyHeader::ref_from_prefix(buf).ok_or(ParserError::BufferTooSmall)?;
        let spi_size = notify_header.spi_size as usize;
        let variant = if notify_header.is_error() {
            NotificationType::Error(NotifyErrorMessage::try_from(
                notify_header.notify_message_type.get(),
            )?)
        } else {
            NotificationType::Status(NotifyStatusMessage::try_from(
                notify_header.notify_message_type.get(),
            )?)
        };
        let protocol = SecurityProtocol::try_from(notify_header.protocol_id)?;

        if spi_size > 0 && protocol == SecurityProtocol::InternetKeyExchange {
            // It is not legal to have both an SPI and use IKE
            return Err(ParserError::ProtocolViolation);
        } else if spi_size == 0 && protocol != SecurityProtocol::Reserved {
            // If the SPI is not sent, the protocol ID must be 0 (=reserved)
            return Err(ParserError::ProtocolViolation);
        }

        let spi = if spi_size > 0 {
            Some(buf[size_of::<NotifyHeader>()..size_of::<NotifyHeader>() + spi_size].to_vec())
        } else {
            None
        };

        Ok(Self {
            variant,
            // TODO: max size of buffer? do not use too much data
            data: buf[size_of::<NotifyHeader>() + spi_size..].to_vec(),
            protocol,
            spi,
        })
    }
}
