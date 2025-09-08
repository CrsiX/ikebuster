//! IKEv2 scan core functionality

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use isakmp::v2::definitions::Proposal;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, error, info, trace};

use crate::v2_utils::gen_proposals::list_all_proposals;
use crate::v2_utils::receiver::handle_receiving;
use crate::v2_utils::scanner::{ScannerSerialization, RECEIVE_TIMEOUT};
use crate::v2_utils::sender::{handle_sending_hello, send_packet};
use crate::v2_utils::{Open, Results, ScanOptionsV2, Statistics};
use crate::ScanError;

#[derive(Debug)]
enum ControlChannelEvent {
    Abort,
    DumpState(oneshot::Sender<ScannerSerialization>),
    Stats(oneshot::Sender<Statistics>),
    Progress(oneshot::Sender<f64>),
    Remaining(oneshot::Sender<usize>),
}

/// Timeout when a host that was alive before stopped sending over 30 minutes ago
pub const HOST_DEAD_TIMEOUT: Duration = Duration::from_secs(1800); // 30 minutes

/// Perform the actual scan of the target for all possible proposals.
/// This should be executed in a tokio task. Use the control socket for interaction.
async fn scan(
    mut control_rx: mpsc::Receiver<ControlChannelEvent>,
    socket: Arc<UdpSocket>,
    options: ScanOptionsV2,
) -> Result<(Results, Statistics), ScanError> {
    trace!("Starting scan...");
    let scan_started = Instant::now();
    let mut sending_interval = interval(Duration::from_millis(options.interval));
    sending_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    sending_interval.tick().await;

    let mut todo = list_all_proposals();
    let mut stats = Statistics {
        total_checks: todo.len(),
        ..Default::default()
    };
    let mut results = Results::default();
    let mut open = Open::default();
    let mut last_received_packet = None;

    const MAX_DATAGRAM_SIZE: usize = 65_507;
    let mut recv_buffer = [0u8; MAX_DATAGRAM_SIZE];

    loop {
        select! {
            // Receive and parse any incoming packet
            recv_result = socket.recv(&mut recv_buffer) => {
                match recv_result {
                    Ok(recv_bytes) => {
                        trace!("Received bytes: {:#?}", &recv_buffer[..recv_bytes]);
                        last_received_packet = Some(Instant::now());
                        stats.recv_bytes += recv_bytes as u64;
                        handle_receiving(&mut stats, &mut open, &mut results, &recv_buffer[..recv_bytes]);
                    }
                    Err(e) => {
                        error!("Failed to read bytes from socket: {e}");
                        return Err(ScanError::Receive(e))
                    }
                }
            }

            // Send a new packet to the destination
            _ = sending_interval.tick() => {
                if open.sent.is_empty()
                    && open.retry.is_empty()
                    && open.verify.is_empty()
                    && last_received_packet.is_some()
                    && todo.is_empty()
                {
                    debug!("Search completed");
                    break;
                }
                trace!(sent = open.sent.len(), retry = open.retry.len(), verify = open.verify.len(), todo = todo.len(), "Sending packet");
                if !handle_sending_hello(&mut stats, &mut open, &mut todo, &socket, &options).await? {
                    debug!("Reached threshold for open connections, did not send new packets");
                    let now = Instant::now();
                    if open.sent.iter().all(|(_, i)| (now - *i) > RECEIVE_TIMEOUT) {
                        // If no packets were received and all sent packets timed out, the
                        // host is either dead or went into DoS protection and drops packets.
                        // DoS protection is likely not active at the very beginning of the
                        // program, thus it is likely that any response is received if there is
                        // an IKE responder on the other side.
                        if stats.recv_bytes == 0 {
                            error!("Timeout reached while waiting for incoming packets, does the host accept IKE connections?");
                            return Err(ScanError::Timeout(RECEIVE_TIMEOUT))
                        } else if last_received_packet.is_some_and(|i| Instant::now() - i > HOST_DEAD_TIMEOUT) {
                            error!("Timeout reached while waiting for incoming packets, the host likely died or disconnected.");
                            return Err(ScanError::Timeout(HOST_DEAD_TIMEOUT))
                        }
                        // Otherwise, if packets were received already and the last packet was
                        // received less than 30 minutes ago, we just keep retrying with some
                        // packet, while the retry list is already empty at this point.
                        if let Some((packet, _)) = open.sent.pop() {
                            send_packet(packet, &socket, &mut open, &mut stats).await?;
                        }
                    };
                };
            }

            // Control channel functionality
            Some(event) = control_rx.recv() => {
                trace!(event = ?event, "Received ControlChannelEvent");
                match event {
                    ControlChannelEvent::Abort => {
                        info!("Aborting current scan to {}", options.ip);
                        break;
                    }
                    ControlChannelEvent::DumpState(ch) => {
                        let dump = dump_state(&mut open, &mut todo, &mut stats, &mut results, &options, &scan_started);
                        ch.send(dump).expect("can't send state dump via channel")
                    }
                    ControlChannelEvent::Stats(ch) => {
                        ch.send(stats.clone()).expect("can't send stats via channel")
                    }
                    ControlChannelEvent::Progress(ch) => {
                        let progress = (stats.total_checks - todo.len()) as f64 / stats.total_checks as f64;
                        ch.send(progress).expect("can't send progress via channel");
                    }
                    ControlChannelEvent::Remaining(ch) => {
                        let total_len = todo.len() + open.sent.len() + open.verify.len();
                        ch.send(total_len).expect("can't send remaining via channel");
                    }
                }
            }
        }
    }

    Ok((results, stats))
}

fn dump_state(
    open: &mut Open,
    todo: &mut VecDeque<Proposal>,
    stats: &mut Statistics,
    results: &mut Results,
    opts: &ScanOptionsV2,
    scan_started: &Instant,
) -> ScannerSerialization {
    let now = SystemTime::now();
    let since_start = scan_started.elapsed();
    let scan_started = (now - since_start)
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    ScannerSerialization {
        target: opts.ip,
        target_port: opts.port,
        retry_len: open.retry.len(),
        statistics: stats.clone(),
        scan_started,
        elapsed_ms: since_start.as_millis() as u64,
        save_created: now
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        open: HashMap::new(),
        accepted: results.accepted.clone(),
        rejected: results.rejected.clone(),
        invalid_syntax: results.invalid_syntax.clone(),
        todo: todo.clone(),
        vendor_ids: results.vendor_ids.clone(),
    }
}

/// Handler around a running IKEv2 scan
pub struct ScanV2Handler {
    task: JoinHandle<Result<(Results, Statistics), ScanError>>,
    socket: Arc<UdpSocket>,
    controller: mpsc::Sender<ControlChannelEvent>,
}

impl ScanV2Handler {
    /// Abort the currently running scan
    pub async fn abort(&self) {
        let _ = self.controller.send(ControlChannelEvent::Abort).await;
        self.task.abort()
    }

    /// Dump the current state of the scan in a serialized format; returns
    /// None if the scan is currently not running (i.e., on completion returns None as well)
    pub async fn dump_state(&self) -> Option<ScannerSerialization> {
        let (tx, rx) = oneshot::channel();
        if self
            .controller
            .send(ControlChannelEvent::DumpState(tx))
            .await
            .is_err()
        {
            return None;
        };
        rx.await.ok()
    }

    /// Get statistics from the currently running scan; returns
    /// None if the scan is currently not running (i.e., on completion returns None as well)
    pub async fn stats(&self) -> Option<Statistics> {
        let (tx, rx) = oneshot::channel();
        if self
            .controller
            .send(ControlChannelEvent::Stats(tx))
            .await
            .is_err()
        {
            return None;
        };
        rx.await.ok()
    }

    /// Poll the running scan to determine the current progress (value between 0 and 1, inclusive);
    /// returns None if the scan is currently not running (i.e., on completion returns None as well)
    pub async fn progress(&self) -> Option<f64> {
        let (tx, rx) = oneshot::channel();
        if self
            .controller
            .send(ControlChannelEvent::Progress(tx))
            .await
            .is_err()
        {
            return None;
        };
        rx.await.ok()
    }

    /// Poll the running scan to determine how many proposals are left to be checked;
    /// returns None if the scan is currently not running (i.e., on completion returns None as well)
    pub async fn remaining(&self) -> Option<usize> {
        let (tx, rx) = oneshot::channel();
        if self
            .controller
            .send(ControlChannelEvent::Remaining(tx))
            .await
            .is_err()
        {
            return None;
        };
        rx.await.ok()
    }

    /// Check if the running scan is finished
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Complete the running scan and yield its result
    pub async fn complete(self) -> Result<Result<(Results, Statistics), ScanError>, JoinError> {
        self.task.await
    }
}

/// Start the IKEv2 scan using the provided scan options, returning a handle to the running scan immediately
pub async fn start_scan(options: &ScanOptionsV2) -> Result<ScanV2Handler, ScanError> {
    let addr = SocketAddr::new(options.ip, options.port);
    info!("Binding and starting to scan {addr}");

    let socket = Arc::new(match addr.ip() {
        IpAddr::V4(_) => UdpSocket::bind(("0.0.0.0", options.listen_port))
            .await
            .map_err(ScanError::CouldNotBind)?,
        IpAddr::V6(_) => UdpSocket::bind(("[::]", options.listen_port))
            .await
            .map_err(ScanError::CouldNotBind)?,
    });
    info!(
        "Bound to {}",
        socket.local_addr().map_err(ScanError::CouldNotBind)?
    );
    socket.connect(&addr).await.map_err(ScanError::Receive)?;

    let (tx, rx) = mpsc::channel(1);
    Ok(ScanV2Handler {
        task: tokio::spawn(scan(rx, socket.clone(), options.clone())),
        socket,
        controller: tx,
    })
}
