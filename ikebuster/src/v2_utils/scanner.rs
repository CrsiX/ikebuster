use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::ops::AddAssign;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use isakmp::v2::definitions;
use isakmp::v2::definitions::params::{NotifyErrorMessage, NotifyStatusMessage, SecurityProtocol};
use isakmp::v2::definitions::{
    IKEv2, Notification, NotificationType, Payload, Proposal, SecurityAssociation,
};
use isakmp::v2::utils::get_random_vec;
use serde::Serialize;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::v2_utils::finding::{Finding, FindingResult};
use crate::v2_utils::gen_proposals::list_all_proposals;
use crate::ScanError;

#[derive(Clone)]
pub struct Scanner {
    target: IpAddr,
    socket: Arc<UdpSocket>,
    open: Arc<Mutex<HashMap<u64, IKEv2>>>,
    /// List of initiator cookies found in `open` that should be retried as soon as possible
    /// so that the target's state is not polluted by too many open cookie requests, even
    /// though the target should not require any persistent state for its DoS cookie handling
    retry: Arc<Mutex<Vec<u64>>>,
    todo: Arc<Mutex<VecDeque<Proposal>>>,
    /// Tracker when a packet identified by its initiator SPI was sent to the remote
    /// side. Only packets in `open` are still valid. This is used to track packet timings
    /// and detect dropped packets.
    packet_tracking: Arc<Mutex<HashMap<u64, Instant>>>,
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
    save_state: Option<fn(String, IpAddr) -> Result<(), ScanError>>,
}

#[derive(Debug, Serialize)]
struct ScannerSerialization {
    target: IpAddr,
    retry_len: usize,
    total_checks: usize,
    errors: u64,
    sent_bytes: u64,
    sent_packets: u64,
    recv_bytes: u64,
    recv_packets: u64,
    /// UNIX timestamp when the scan was started
    scan_started: u64,
    /// Elapsed scan time in milliseconds
    elapsed_ms: u64,
    /// UNIX timestamp when this file was created
    save_created: u64,
    open: HashMap<u64, Vec<Proposal>>,
    accepted: Vec<Proposal>,
    rejected: Vec<Proposal>,
    invalid_syntax: Vec<Proposal>,
    todo: VecDeque<Proposal>,
    vendor_ids: Vec<Vec<u8>>,
}

/// Delay between sending packets
const SENDING_DELAY: Duration = Duration::from_millis(1_000);

/// Delay for waiting on incoming packets if we still await some
const WAITING_DELAY: Duration = Duration::from_millis(1_000);

/// Timeout until packets without response are considered permanently lost;
/// it must be strictly higher than [SENDING_DELAY]
const TIMEOUT_DELAY: Duration = Duration::from_millis(10_000);

impl Scanner {
    pub async fn scan(
        target: IpAddr,
        save_state: Option<fn(String, IpAddr) -> Result<(), ScanError>>,
    ) -> Result<Arc<Self>, ScanError> {
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
            target,
            socket,
            open: Arc::new(Default::default()),
            retry: Arc::new(Default::default()),
            todo: Arc::new(Mutex::new(list_all_proposals())),
            packet_tracking: Arc::new(Mutex::new(HashMap::new())),
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
            save_state,
        };
        scanner.total_checks = scanner.todo.lock().unwrap().len();

        let arc = Arc::new(scanner);
        let inner_arc = arc.clone();
        tokio::spawn(async move {
            let me = inner_arc.as_ref();
            me.handle_receiving().await;
        });
        arc.do_scan().await?;

        /// Returns any open but lost packet identifier as `Some<Some<_>>`,
        /// or `Some<None>` if there are open packets but not over the
        /// timeout yet, or `None` if there aren't any
        fn get_dropped_open_identifier(s: Arc<Scanner>) -> Option<Option<u64>> {
            let open = s.open.lock().unwrap();
            if open.is_empty() {
                None
            } else {
                let tracking = s.packet_tracking.lock().unwrap();
                for k in open.keys() {
                    if tracking.get(k)?.elapsed() > TIMEOUT_DELAY {
                        return Some(Some(*k));
                    };
                }
                Some(None)
            }
        }

        // Handle dropped packets and other issues at the very end of the scanning process
        while let Some(open_identifier) = get_dropped_open_identifier(arc.clone()) {
            match open_identifier {
                None => {
                    debug!("Waiting to receive all messages ...");
                }
                Some(lost_identifier) => {
                    debug!("Detected dropped packet, restoring proposal(s) and retrying ...");
                    arc.packet_tracking.lock().unwrap().remove(&lost_identifier);
                    if let Some(packet) = arc.open.lock().unwrap().remove(&lost_identifier) {
                        for p in get_proposals(&packet) {
                            arc.todo.lock().unwrap().push_back(p.clone());
                        }
                    };
                    arc.do_scan().await?;
                }
            }
            tokio::time::sleep(WAITING_DELAY).await;
        }

        info!(
            "Sent {} bytes / {} packets, received {} bytes / {} packets",
            arc.sent_bytes.lock().unwrap(),
            arc.sent_packets.lock().unwrap(),
            arc.recv_bytes.lock().unwrap(),
            arc.recv_packets.lock().unwrap()
        );
        arc.save_current_state()?;
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
            let (serialized_msg, identifier) = match sending {
                Sending::Retry(initiator_cookie) => {
                    if let Some(msg) = self.open.lock().unwrap().get(&initiator_cookie) {
                        (
                            msg.try_build().map_err(ScanError::GeneratorFailed)?,
                            initiator_cookie,
                        )
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
                    let initiator_cookie = msg.initiator_cookie;
                    self.open.lock().unwrap().insert(msg.initiator_cookie, msg);
                    (serialized_msg, initiator_cookie)
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
            self.packet_tracking.lock().unwrap().insert(identifier, ts);
            tokio::time::sleep(SENDING_DELAY).await;
        }

        Ok(())
    }

    async fn handle_receiving(&self) -> Result<(), ScanError> {
        loop {
            const MAX_DATAGRAM_SIZE: usize = 65_507;
            let mut buf = [0u8; MAX_DATAGRAM_SIZE];
            let timed_receiving = tokio::time::timeout(RECEIVE_TIMEOUT, self.socket.recv(&mut buf));
            let len = match timed_receiving.await {
                Ok(v) => match v {
                    Ok(len) => Ok(len),
                    Err(e) => {
                        error!("Failed to read bytes from socket: {e}");
                        Err(ScanError::Receive(e))
                    }
                },
                Err(_) => {
                    error!("Timeout while waiting for incoming data for {RECEIVE_TIMEOUT:#?}");
                    Err(ScanError::Timeout(RECEIVE_TIMEOUT))
                }
            }?;

            self.recv_bytes.lock().unwrap().add_assign(len as u64);

            match IKEv2::try_parse(&buf[..len]) {
                Ok(packet) => {
                    self.handle_packet(packet).await;
                    self.recv_packets.lock().unwrap().add_assign(1);
                    let _ = self.update_progress();
                }
                Err(err) => {
                    error!("Failed to parse IKEv2 packet: {}", err);
                    debug!("Invalid IKEv2 packet: {:02x?}", &buf[..len]);
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
                            self.packet_tracking
                                .lock()
                                .unwrap()
                                .remove(&packet.initiator_cookie);
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
                            self.packet_tracking
                                .lock()
                                .unwrap()
                                .remove(&packet.initiator_cookie);
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
                            if n.protocol == SecurityProtocol::InternetKeyExchange
                                || n.protocol == SecurityProtocol::Reserved
                            {
                                if n.protocol == SecurityProtocol::Reserved {
                                    debug!("Received cookie for {}, but using anyway", n.protocol);
                                }
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
                            } else {
                                error!("Received unexpected cookie for non-IKE protocol: {:#?}", n);
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
                        self.packet_tracking
                            .lock()
                            .unwrap()
                            .remove(&packet.initiator_cookie);
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

    fn update_progress(&self) -> Result<(), ScanError> {
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
            self.save_current_state()?
        }
        Ok(())
    }

    fn save_current_state(&self) -> Result<(), ScanError> {
        if let Some(save_fn) = self.save_state {
            match serde_json::to_string(&self.serialize()) {
                Ok(serialization) => save_fn(serialization, self.target)?,
                Err(err) => error!("Serialization error avoiding saving state: {}", err),
            }
        }
        Ok(())
    }

    /// Construct a vec of [Finding]s from the previous scan
    pub fn get_findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        #[inline]
        fn to_finding(proposal: &Proposal, result: FindingResult) -> Finding {
            Finding {
                encryption: proposal.encryption_algorithms.get(0).unwrap().0,
                key_size: proposal.encryption_algorithms.get(0).unwrap().1,
                is_aead: proposal
                    .encryption_algorithms
                    .get(0)
                    .unwrap()
                    .0
                    .is_aead_cipher(),
                prf: proposal.pseudo_random_functions.get(0).unwrap().clone(),
                integrity: proposal.integrity_algorithms.first().cloned(),
                kex: proposal.key_exchange_methods.first().cloned().unwrap(),
                result,
            }
        }

        for i in self.accepted.lock().unwrap().iter() {
            findings.push(to_finding(i, FindingResult::Accepted));
        }
        for i in self.rejected.lock().unwrap().iter() {
            findings.push(to_finding(i, FindingResult::Rejected));
        }
        for i in self.invalid_syntax.lock().unwrap().iter() {
            findings.push(to_finding(i, FindingResult::InvalidSyntax));
        }
        findings
    }

    fn serialize(&self) -> ScannerSerialization {
        let now = SystemTime::now();
        let since_start = self.scan_started.elapsed();
        let scan_started = (now - since_start)
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Acquire all relevant locks to keep the state clean
        let open_l = self.open.lock().unwrap();
        let todo_l = self.todo.lock().unwrap();
        let accepted_l = self.accepted.lock().unwrap();
        let rejected_l = self.rejected.lock().unwrap();
        let invalid_l = self.invalid_syntax.lock().unwrap();
        let vendor_l = self.vendor_ids.lock().unwrap();

        let mut open = HashMap::new();
        for (k, v) in open_l.iter() {
            let mut propoosals = vec![];
            for p in get_proposals(v) {
                propoosals.push(p.clone());
            }
            open.insert(*k, propoosals);
        }

        let mut todo = VecDeque::new();
        for i in todo_l.iter() {
            todo.push_back(i.clone());
        }

        let mut accepted = Vec::new();
        for i in accepted_l.iter() {
            accepted.push(i.clone());
        }

        let mut rejected = Vec::new();
        for i in rejected_l.iter() {
            rejected.push(i.clone());
        }

        let mut invalid_syntax = Vec::new();
        for i in invalid_l.iter() {
            invalid_syntax.push(i.clone());
        }

        let mut vendor_ids = Vec::new();
        for i in vendor_l.iter() {
            vendor_ids.push(i.clone());
        }

        ScannerSerialization {
            target: self.target,
            retry_len: self.retry.lock().unwrap().len(),
            total_checks: self.total_checks,
            errors: self.errors.lock().unwrap().clone(),
            sent_bytes: self.sent_bytes.lock().unwrap().clone(),
            sent_packets: self.sent_packets.lock().unwrap().clone(),
            recv_bytes: self.recv_bytes.lock().unwrap().clone(),
            recv_packets: self.recv_packets.lock().unwrap().clone(),
            scan_started,
            elapsed_ms: since_start.as_millis() as u64,
            save_created: now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            open,
            accepted,
            rejected,
            invalid_syntax,
            todo,
            vendor_ids,
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
