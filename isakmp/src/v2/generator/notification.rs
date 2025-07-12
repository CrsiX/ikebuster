use crate::v1::definitions::GenericPayloadHeader;
use crate::v2::definitions::header::NotifyHeader;
use crate::v2::definitions::params::{PayloadType, SecurityProtocol};
use crate::v2::definitions::Notification;
use zerocopy::network_endian::U16;
use zerocopy::AsBytes;

impl Notification {
    pub fn build(
        &self,
        next_payload: PayloadType,
        protocol: SecurityProtocol,
        spi: Option<&[u8]>,
    ) -> Vec<u8> {
        let (notification_type, notification_data) = match self {
            Notification::Error(e, d) => (*e as u16, d),
            Notification::Status(s, d) => (*s as u16, d),
        };

        let spi_len = if let Some(spi_data) = spi {
            assert!(spi_data.len() < 256);
            spi_data.len() as u8
        } else {
            0
        };
        let generic_header = GenericPayloadHeader {
            next_payload: next_payload as u8,
            reserved: 0,
            payload_length: U16::from(8 + spi_len as u16 + notification_data.len() as u16),
        };
        let notify_header = NotifyHeader {
            protocol_id: if let None = spi { 0 } else { protocol as u8 },
            spi_size: spi_len,
            notify_message_type: U16::from(notification_type),
        };

        let mut packet = Vec::with_capacity(notification_data.len() + 8);
        packet.extend_from_slice(generic_header.as_bytes());
        packet.extend_from_slice(notify_header.as_bytes());
        if let Some(data) = spi {
            packet.extend_from_slice(data);
        }
        packet.extend(notification_data);
        packet
    }
}
