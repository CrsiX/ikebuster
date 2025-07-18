use crate::v2::definitions::header::NotifyHeader;
use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::{GenericPayloadHeader, Notification, NotificationType};
use crate::v2::generator::GeneratorError;
use zerocopy::network_endian::U16;
use zerocopy::AsBytes;

impl Notification<'_> {
    pub fn try_build(&self, next_payload: PayloadType) -> Result<Vec<u8>, GeneratorError> {
        let notification_type = match self.variant {
            NotificationType::Error(e) => e as u16,
            NotificationType::Status(s) => s as u16,
        };

        let spi_len = if let Some(spi_data) = self.spi {
            u8::try_from(spi_data.len()).map_err(|_| GeneratorError::MaxSpiLengthExceeded)?
        } else {
            0
        };
        let generic_header = GenericPayloadHeader {
            next_payload: next_payload as u8,
            reserved: 0,
            payload_length: U16::from(8 + spi_len as u16 + self.data.len() as u16),
        };
        let notify_header = NotifyHeader {
            protocol_id: if let None = self.spi {
                0
            } else {
                self.protocol as u8
            },
            spi_size: spi_len,
            notify_message_type: U16::from(notification_type),
        };

        let mut packet = Vec::with_capacity(8 + spi_len as usize + self.data.len());
        packet.extend_from_slice(generic_header.as_bytes());
        packet.extend_from_slice(notify_header.as_bytes());
        if let Some(data) = self.spi {
            packet.extend_from_slice(data);
        }
        packet.extend_from_slice(self.data.as_slice());
        Ok(packet)
    }
}
