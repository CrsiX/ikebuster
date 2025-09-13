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
use tracing::{debug, error, info, trace, warn};

use crate::v2::gen_proposals::list_all_proposals;
use crate::v2::peeking::peek;
use crate::v2::receiver::handle_receiving;
use crate::v2::sender::handle_sending;
use crate::v2::serialization::ScannerSerialization;
use crate::v2::{Open, Results, ScanOptionsV2, Statistics, MAX_DATAGRAM_SIZE, RECEIVE_TIMEOUT};
use crate::{bind, ScanError};

#[derive(Debug)]
enum ControlChannelEvent {
    Abort,
    DumpState(oneshot::Sender<ScannerSerialization>),
    Stats(oneshot::Sender<Statistics>),
    Progress(oneshot::Sender<f64>),
    Remaining(oneshot::Sender<usize>),
}

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
                        handle_receiving(&mut stats, &mut open, &mut results, &recv_buffer[..recv_bytes])?;
                    }
                    Err(e) => {
                        error!("Failed to read bytes from socket: {e}");
                        return Err(ScanError::Receive(e))
                    }
                }
            }

            // Send a new packet to the destination, which may be a new SA_IKE_INIT
            // or a retry to an already sent packet
            _ = sending_interval.tick() => {
                if open.sent.is_empty()
                    && open.retry.is_empty()
                    && open.verify.is_empty()
                    && todo.is_empty()
                {
                    info!("Search completed");
                    break;
                }
                handle_sending(
                    &mut stats,
                    &mut open,
                    &mut todo,
                    &socket,
                    &options,
                    &last_received_packet
                ).await?;
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
    let socket = Arc::new(bind(options.ip, options.port, options.listen_port).await?);

    if options.enable_peeking {
        debug!("Peeking with a blown-up IKEv2 message...");
        match tokio::time::timeout(RECEIVE_TIMEOUT, peek(&socket)).await {
            Ok(v) => match v {
                Ok(s) => {}
                Err(e) => return Err(e),
            },
            Err(e) => {
                warn!("Peek failed with timeout (is the host alive?): {}", e);
            }
        };
    }

    let (tx, rx) = mpsc::channel(1);
    Ok(ScanV2Handler {
        task: tokio::spawn(scan(rx, socket.clone(), options.clone())),
        socket,
        controller: tx,
    })
}
