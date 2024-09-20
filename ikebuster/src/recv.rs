use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use isakmp::v1::ExchangeType;
use isakmp::v1::NotifyMessageType;
use tokio::net::UdpSocket;
use tracing::debug;
use tracing::info;
use tracing::trace;

use crate::v1::generation::Transform;
use crate::v1::helper::format_attribute;

/// Handle the receival of isakmp messages
pub async fn handle_receive(
    s: Arc<UdpSocket>,
    m: Arc<Mutex<HashMap<u64, Vec<Transform>>>>,
) -> Result<(), String> {
    loop {
        const MAX_DATAGRAM_SIZE: usize = 65_507;
        let mut buf = [0u8; MAX_DATAGRAM_SIZE];
        let len = s.recv(&mut buf).await.map_err(|e| e.to_string())?;

        let packet = ike_parser::v1::parse_packet(&buf[..len]).map_err(|e| e.to_string())?;

        trace!("{packet:#?}");

        if let Some(sa) = packet.security_associations.first() {
            if let Some(prop) = sa.proposal_payload.first() {
                if let Some(transform) = prop.transforms.first() {
                    let mut t = vec![];
                    for attribute in &transform.sa_attributes {
                        t.push(format_attribute(attribute));
                    }
                    info!("Found valid transformation:\n\t{}", t.join("\n\t"));
                }
            }
        } else {
            for not in packet.notification_payloads {
                if not.notify_message_type == NotifyMessageType::NoProposalChosen {
                    let cookie = packet.header.initiator_cookie;
                    debug!("Remove {cookie} from message");
                    m.lock().unwrap().remove(&cookie);
                } else {
                    debug!(
                        "Other: {:?} - {}",
                        not.notify_message_type,
                        String::from_utf8_lossy(&not.notification)
                    );
                }
            }
        }

        if packet.header.exchange_mode == ExchangeType::Base {
            break;
        }
    }

    Ok(())
}
