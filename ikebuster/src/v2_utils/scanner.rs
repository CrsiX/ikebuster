use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::ops::AddAssign;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use isakmp::v2::definitions;
use isakmp::v2::definitions::params::{NotifyErrorMessage, NotifyStatusMessage, SecurityProtocol};
use isakmp::v2::definitions::{
    IKEv2, Notification, NotificationType, Payload, Proposal, SecurityAssociation,
};
use isakmp::v2::utils::get_random_vec;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::v2_utils::gen_proposals::list_all_proposals;
use crate::ScanError;

#[derive(Clone)]
pub struct Scanner {
    socket: Arc<UdpSocket>,
    open: Arc<Mutex<HashMap<u64, IKEv2>>>,
    /// List of initiator cookies found in `open` that should be retried as soon as possible
    /// so that the target's state is not polluted by too many open cookie requests, even
    /// though the target should not require any persistent state for its DoS cookie handling
    retry: Arc<Mutex<Vec<u64>>>,
    todo: Arc<Mutex<VecDeque<Proposal>>>,
    total_checks: usize,
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

        let mut scanner = Scanner {
            socket,
            open: Arc::new(Default::default()),
            retry: Arc::new(Default::default()),
            todo: Arc::new(Mutex::new(list_all_proposals())),
            total_checks: Default::default(),
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
        scanner.total_checks = scanner.todo.lock().unwrap().len();

        let arc = Arc::new(scanner);
        let inner_arc = arc.clone();
        tokio::spawn(async move {
            let me = inner_arc.as_ref();
            me.handle_receiving().await;
        });
        arc.do_scan().await?;

        while *arc.recv_bytes.lock().unwrap() < *arc.sent_bytes.lock().unwrap() {
            debug!("Waiting to receive all messages ...");
            tokio::time::sleep(WAITING_DELAY).await;
        }

        info!(
            "Sent {} bytes / {} packets, received {} bytes / {} packets",
            arc.sent_bytes.lock().unwrap(),
            arc.sent_packets.lock().unwrap(),
            arc.recv_bytes.lock().unwrap(),
            arc.recv_packets.lock().unwrap()
        );
        Ok(arc)
    }

    async fn do_scan(&self) -> Result<(), ScanError> {
        enum Sending {
            Retry(u64),
            Proposal(Proposal),
        }

        /// Get the next item to send to the target, giving a higher priority to retries
        fn pop_next_sending_item(this: &Scanner) -> Option<Sending> {
            this.retry
                .lock()
                .unwrap()
                .pop()
                .map(|r| Sending::Retry(r))
                .or_else(|| {
                    this.todo
                        .lock()
                        .unwrap()
                        .pop_front()
                        .map(|i| Sending::Proposal(i))
                })
        }

        while let Some(sending) = pop_next_sending_item(self) {
            let serialized_msg = match sending {
                Sending::Retry(initiator_cookie) => {
                    if let Some(msg) = self.open.lock().unwrap().get(&initiator_cookie) {
                        msg.try_build().map_err(ScanError::GeneratorFailed)?
                    } else {
                        error!("Retrying with cookie {initiator_cookie} impossible, message not found in local storage!");
                        self.errors.lock().unwrap().add_assign(1);
                        continue;
                    }
                }
                Sending::Proposal(proposal) => {
                    let dh_group = proposal.key_exchange_methods.get(0).cloned().expect(
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
                    self.open.lock().unwrap().insert(msg.initiator_cookie, msg);
                    serialized_msg
                }
            };

            let ts = Instant::now();
            let sent_bytes = self
                .socket
                .send(serialized_msg.as_slice())
                .await
                .map_err(ScanError::Send)?;
            self.last_packet_sent.lock().unwrap().replace(ts);
            self.sent_bytes
                .lock()
                .unwrap()
                .add_assign(sent_bytes as u64);
            self.sent_packets.lock().unwrap().add_assign(1);
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
            // TODO: handle unresponsive peers (e.g. when they do not send any packets & timeouts)

            self.recv_bytes.lock().unwrap().add_assign(len as u64);
            self.recv_packets.lock().unwrap().add_assign(1);
            self.update_progress().await;

            match IKEv2::try_parse(&buf[..len]) {
                Ok(packet) => {
                    self.handle_packet(packet).await;
                }
                Err(err) => {
                    error!("Failed to parse IKEv2 packet: {}", err);
                    debug!("Invalid IKEv2 packet: {:02x?}", buf);
                    self.errors.lock().unwrap().add_assign(1);
                }
            }
        }
    }

    async fn handle_packet(&self, packet: IKEv2) {
        if !packet.response || packet.initiator {
            error!(
                "Received IKEv2 packet with response or initiator flags set! Refusing to parse!"
            );
            self.errors.lock().unwrap().add_assign(1);
            return;
        }

        // Handle notifications (e.g. DoS cookies and invalid proposals) before handling successful cases
        let mut dos_cookie = None;
        for payload in packet.payloads.iter() {
            if let Payload::Notify(n) = payload {
                match n.variant {
                    NotificationType::Error(e) => match e {
                        NotifyErrorMessage::InvalidSyntax => {
                            if let Some(open_packet) =
                                self.open.lock().unwrap().remove(&packet.initiator_cookie)
                            {
                                if let Some(sa) = open_packet
                                    .payloads
                                    .iter()
                                    .filter_map(|p| match p {
                                        Payload::SecurityAssociation(sa) => Some(sa),
                                        _ => None,
                                    })
                                    .collect::<Vec<_>>()
                                    .first()
                                {
                                    if sa.proposals.len() != 1 {
                                        warn!("Multiple proposals not supported in recv handler: {:?}", sa.proposals);
                                    } else {
                                        let p = sa.proposals.first().unwrap().clone();
                                        self.invalid_syntax.lock().unwrap().push(p);
                                    }
                                }
                            }
                        }
                        NotifyErrorMessage::NoProposalChosen => {
                            if let Some(open_packet) =
                                self.open.lock().unwrap().remove(&packet.initiator_cookie)
                            {
                                // TODO: ensure that this is the correct behavior, i.e. confirm that an appliance
                                //  actually does not support *any* of the proposals if they are rejected
                                //  -> it's suspected that this may not be the case for all receivers and that we may
                                //  need to just split the package into smaller pieces and retry with all of them once more
                                let mut rejected = self.rejected.lock().unwrap();
                                for p in get_proposals(&open_packet) {
                                    rejected.push(p.clone());
                                }
                            }
                        }
                        NotifyErrorMessage::InvalidKeyExchangePayload => {
                            // TODO: add support for InvalidKeyExchangePayload
                            warn!("InvalidKeyExchangePayload unsupported");
                        }
                        _ => {
                            error!("Unexpected error notification: {:?}", n);
                        }
                    },
                    NotificationType::Status(s) => match s {
                        NotifyStatusMessage::Cookie => {
                            if n.protocol != SecurityProtocol::InternetKeyExchange {
                                error!("Received unexpected cookie for non-IKE protocol: {:#?}", n);
                            } else {
                                if n.data.len() > 64 {
                                    warn!("Received cookie with more than 64 bytes payload, violating the protocol! Proceeding anyway...");
                                } else if n.data.is_empty() {
                                    warn!("Received empty cookie payload, violating the protocol! Proceeding anyway...");
                                }
                                if dos_cookie.is_some() {
                                    error!("Multiple cookies in a single response! Proceeding anyway...");
                                    self.errors.lock().unwrap().add_assign(1);
                                }
                                dos_cookie = Some(n.data.clone());
                            }
                        }
                        // Simply ignore various status messages we are not interested in
                        NotifyStatusMessage::MultipleAuthSupported
                        | NotifyStatusMessage::NatDetectionSourceIp
                        | NotifyStatusMessage::NatDetectionDestinationIp
                        | NotifyStatusMessage::ChildlessIkev2Supported => {}
                        _ => {
                            warn!("Unexpected status notification: {:?}", n)
                        }
                    },
                }
            }
        }
        if let Some(dos_cookie) = dos_cookie {
            let mut map = self.open.lock().unwrap();
            if let Some(msg) = map.get_mut(&packet.initiator_cookie) {
                msg.payloads.push(Payload::Notify(Notification {
                    variant: NotificationType::Status(NotifyStatusMessage::Cookie),
                    data: dos_cookie,
                    protocol: SecurityProtocol::InternetKeyExchange,
                    spi: None,
                }));
                self.retry.lock().unwrap().push(packet.initiator_cookie);
            } else {
                error!(
                    "Initiator cookie from response not found in local storage: {:#?}",
                    packet.initiator_cookie
                );
                self.errors.lock().unwrap().add_assign(1);
            }
            return;
        }

        // Successful handshakes produce
        for payload in packet.payloads {
            match payload {
                Payload::SecurityAssociation(sa) => {
                    if let Some(received_proposal) = sa.proposals.first() {
                        if let Some(open_packet) =
                            self.open.lock().unwrap().remove(&packet.initiator_cookie)
                        {
                            let existing_proposals = get_proposals(&open_packet);
                            for p in existing_proposals {
                                if *p == *received_proposal {
                                    self.accepted.lock().unwrap().push(p.clone());
                                    // TODO: send Delete payload
                                } else {
                                    self.todo.lock().unwrap().push_front(p.clone());
                                }
                            }
                        }
                    }
                }
                Payload::KeyExchange(_) => {}        // TODO: verify KE
                Payload::CertificateRequest(_) => {} // TODO: verify CR
                Payload::VendorID(_) => {}           // TODO: fingerprinting
                _ => {}
            }
        }
    }

    async fn update_progress(&self) {
        let todo = self.todo.lock().unwrap().len();
        if todo % 1000 == 0 {
            debug!(
                "Progress: Left todo: {} ({:.2}% done) after {:#?}, {} errors, {} sent, {} received",
                todo,
                100f64 * (self.total_checks - todo) as f64 / (self.total_checks) as f64,
                self.scan_started.elapsed(),
                self.errors.lock().unwrap(),
                self.sent_packets.lock().unwrap(),
                self.recv_packets.lock().unwrap(),
            );
        }
    }
}

fn get_proposals(ike: &IKEv2) -> Vec<&Proposal> {
    ike.payloads
        .iter()
        .filter_map(|p| match p {
            Payload::SecurityAssociation(sa) => Some::<&Vec<Proposal>>(sa.proposals.as_ref()),
            _ => None,
        })
        .flatten()
        .collect()
}
