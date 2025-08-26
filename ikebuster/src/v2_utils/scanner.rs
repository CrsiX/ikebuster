use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::ops::AddAssign;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::v2_utils::gen_proposals::list_all_proposals;
use crate::ScanError;
use isakmp::v2::definitions;
use isakmp::v2::definitions::params::NotifyStatusMessage::Cookie;
use isakmp::v2::definitions::params::{NotifyErrorMessage, NotifyStatusMessage, SecurityProtocol};
use isakmp::v2::definitions::{
    IKEv2, Notification, NotificationType, Payload, Proposal, SecurityAssociation,
};
use isakmp::v2::utils::get_random_vec;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
// type ProposalCookieNonce = (Proposal, Option<Vec<u8>>, Vec<u8>);

#[derive(Clone)]
pub struct Scanner {
    socket: Arc<UdpSocket>,
    open: Arc<Mutex<HashMap<u64, IKEv2>>>, // map to proposal and optional cookie
    pub accepted: Arc<Mutex<Vec<Proposal>>>,
    pub rejected: Arc<Mutex<Vec<Proposal>>>,
    pub invalid_syntax: Arc<Mutex<Vec<Proposal>>>,
    pub vendor_ids: Arc<Mutex<Vec<Vec<u8>>>>,
    pub errors: Arc<Mutex<u64>>,
    pub sent_bytes: Arc<Mutex<u64>>,
    pub sent_packets: Arc<Mutex<u64>>,
    pub recv_bytes: Arc<Mutex<u64>>,
    pub recv_packets: Arc<Mutex<u64>>,
    scan_started: Instant,
    last_packet_sent: Arc<Mutex<Option<Instant>>>,
}

const SENDING_DELAY: Duration = Duration::from_millis(1000);
const WAITING_DELAY: Duration = Duration::from_millis(1000);

impl Scanner {
    pub async fn scan(target: IpAddr) -> Result<Arc<Self>, ScanError> {
        let addr = SocketAddr::new(target, 500);
        info!("Binding and starting to scan {addr}");

        let socket = Arc::new(match addr.ip() {
            IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:4500")
                .await
                .map_err(ScanError::CouldNotBind)?,
            IpAddr::V6(_) => UdpSocket::bind("[::]:4500")
                .await
                .map_err(ScanError::CouldNotBind)?,
        });
        info!(
            "Bound to {}",
            socket.local_addr().map_err(ScanError::CouldNotBind)?
        );
        socket.connect(&addr).await.map_err(ScanError::Receive)?;

        let scanner = Scanner {
            socket,
            open: Arc::new(Default::default()),
            accepted: Arc::new(Default::default()),
            rejected: Arc::new(Default::default()),
            invalid_syntax: Arc::new(Default::default()),
            vendor_ids: Arc::new(Default::default()),
            errors: Arc::new(Default::default()),
            sent_bytes: Arc::new(Default::default()),
            sent_packets: Arc::new(Default::default()),
            recv_bytes: Arc::new(Default::default()),
            recv_packets: Arc::new(Default::default()),
            scan_started: Instant::now(),
            last_packet_sent: Arc::new(Mutex::new(None)),
        };

        let arc = Arc::new(scanner);
        let inner_arc = arc.clone();
        tokio::spawn(async move {
            let me = inner_arc.as_ref();
            me.handle_receiving().await;
        });
        arc.do_scan().await?;

        while *arc.recv_bytes.lock().await < *arc.sent_bytes.lock().await {
            debug!("Waiting to receive all messages ...");
            tokio::time::sleep(WAITING_DELAY).await;
        }

        info!(
            "Sent {} bytes / {} packets, received {} bytes / {} packets",
            arc.sent_bytes.lock().await,
            arc.sent_packets.lock().await,
            arc.recv_bytes.lock().await,
            arc.recv_packets.lock().await
        );
        Ok(arc)
    }

    async fn do_scan(&self) -> Result<(), ScanError> {
        let mut todo = list_all_proposals();

        while let Some(proposal) = todo.pop_front() {
            let dh_group =
                proposal.key_exchange_methods.get(0).cloned().expect(
                    "'list_proposals' must not return without a KeyExchange in the proposal",
                );
            let msg = IKEv2::hello(vec![
                Payload::SecurityAssociation(SecurityAssociation {
                    proposals: vec![proposal.clone()],
                }),
                Payload::KeyExchange(definitions::KeyExchange {
                    dh_group,
                    data: get_random_vec(dh_group.get_key_handshake_length()),
                }),
                Payload::Nonce(get_random_vec(16)),
            ]);

            let serialized_msg = msg.try_build().map_err(ScanError::GeneratorFailed)?;
            self.open.lock().await.insert(msg.initiator_cookie, msg);

            let ts = Instant::now();
            let sent_bytes = self
                .socket
                .send(serialized_msg.as_slice())
                .await
                .map_err(ScanError::Send)?;
            self.last_packet_sent.lock().await.replace(ts);
            self.sent_bytes.lock().await.add_assign(sent_bytes as u64);
            self.sent_packets.lock().await.add_assign(1);
            tokio::time::sleep(SENDING_DELAY).await;
        }

        Ok(())
    }

    async fn handle_receiving(&self) {
        loop {
            const MAX_DATAGRAM_SIZE: usize = 65_507;
            let mut buf = [0u8; MAX_DATAGRAM_SIZE];
            let len = match self.socket.recv(&mut buf).await {
                Ok(len) => len,
                Err(e) => {
                    error!("Failed to read bytes from socket: {e}. Exiting!");
                    return;
                }
            };

            self.recv_bytes.lock().await.add_assign(len as u64);
            self.recv_packets.lock().await.add_assign(1);

            match IKEv2::try_parse(&buf[..len]) {
                Ok(packet) => {
                    debug!("received {packet:?}");
                    self.handle_packet(packet).await;
                }
                Err(err) => {
                    error!("Failed to parse IKEv2 packet: {}", err);
                    debug!("Invalid IKEv2 packet: {:02x?}", buf);
                    self.errors.lock().await.add_assign(1);
                }
            }
        }
    }

    async fn handle_packet(&self, packet: IKEv2) {
        if !packet.response || packet.initiator {
            error!(
                "Received IKEv2 packet with response or initiator flags set! Refusing to parse!"
            );
            self.errors.lock().await.add_assign(1);
            return;
        }

        // Detect DoS cookies before handling other cases
        let mut dos_cookie = None;
        for payload in packet.payloads.iter() {
            match payload {
                Payload::Notify(n) => {
                    if let NotificationType::Status(s) = n.variant {
                        match s {
                            Cookie => {
                                if n.protocol != SecurityProtocol::InternetKeyExchange {
                                    error!(
                                        "Received unexpected cookie for non-IKE protocol: {:#?}",
                                        n
                                    );
                                } else {
                                    if n.data.len() > 64 {
                                        warn!("Received cookie with more than 64 bytes payload, violating the protocol! Proceeding anyway...");
                                    } else if n.data.is_empty() {
                                        warn!("Received empty cookie payload, violating the protocol! Proceeding anyway...");
                                    }
                                    dos_cookie = Some(n.data.clone());
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(dos_cookie) = dos_cookie {
            let mut map = self.open.lock().await;
            if let Some(msg) = map.get_mut(&packet.initiator_cookie) {
                msg.payloads.push(Payload::Notify(Notification {
                    variant: NotificationType::Status(Cookie),
                    data: dos_cookie,
                    protocol: SecurityProtocol::InternetKeyExchange,
                    spi: None,
                }));
            } else {
                error!(
                    "Initiator cookie from response not found in local storage: {:#?}",
                    packet.initiator_cookie
                );
                self.errors.lock().await.add_assign(1);
            }
            return;
        }
    }
}
