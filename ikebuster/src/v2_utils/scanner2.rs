//! IKEv2 scan core functionality

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::v2_utils::gen_proposals::list_all_proposals;
use crate::v2_utils::scanner::ScannerSerialization;
use crate::v2_utils::ScanOptionsV2;
use crate::ScanError;
use isakmp::v2::definitions::{IKEv2, Proposal};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::interval;
use tracing::{debug, error, info, trace};

#[derive(Debug)]
enum ControlChannelEvent {
    Abort,
    DumpState(oneshot::Sender<ScannerSerialization>),
    Progress(oneshot::Sender<f64>),
    Remaining(oneshot::Sender<usize>),
}

#[derive(Debug, Default)]
struct Statistics {
    pub errors: u64,
    pub sent_bytes: u64,
    pub sent_packets: u64,
    pub recv_bytes: u64,
    pub recv_packets: u64,
    pub total_checks: u64,
}

#[derive(Debug, Default)]
struct Results {
    pub accepted: Vec<Proposal>,
    pub rejected: Vec<Proposal>,
    pub invalid_syntax: Vec<Proposal>,
    pub vendor_ids: Vec<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Open {
    sent: Vec<(IKEv2, Instant)>,
    retry: Vec<IKEv2>,
}

fn handle_receiving(stats: &mut Statistics, raw_rx: &[u8]) {}

async fn scan(
    mut control_rx: mpsc::Receiver<ControlChannelEvent>,
    socket: Arc<UdpSocket>,
    options: ScanOptionsV2,
) -> Result<(), ScanError> {
    trace!("Starting scan...");
    let scan_started = Instant::now();
    let mut sending_interval = interval(Duration::from_millis(options.interval));
    sending_interval.tick().await;

    let mut todo = list_all_proposals();
    let mut stats = Statistics {
        total_checks: todo.len() as u64,
        ..Default::default()
    };
    let mut results = Results::default();
    let mut open = Open::default();

    const MAX_DATAGRAM_SIZE: usize = 65_507;
    let mut recv_buffer = [0u8; MAX_DATAGRAM_SIZE];

    loop {
        select! {
            // Receive and parse any incoming packet
            recv_result = socket.recv(&mut recv_buffer) => {
                match recv_result {
                    Ok(recv_bytes) => {
                        trace!("Received bytes: {:#?}", &recv_buffer[..recv_bytes]);
                        stats.recv_bytes += recv_bytes as u64;
                        handle_receiving(&mut stats, &recv_buffer[..recv_bytes]);
                    }
                    Err(e) => {
                        error!("Failed to read bytes from socket: {e}");
                        return Err(ScanError::Receive(e))
                    }
                }
            }

            // Send a new packet to the destination
            _ = sending_interval.tick() => {
                // TODO
                trace!("Sending packet");
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
                        ch.send(dump_state(&mut open, &mut todo, &mut stats, &mut results, &options)).expect("can't send state via channel")
                    }
                    ControlChannelEvent::Progress(ch) => {
                        ch.send(0.0).expect("can't send progress via channel");
                    }
                    ControlChannelEvent::Remaining(ch) => {
                        ch.send(1).expect("can't send remaining via channel");
                    }
                }
            }
        }
    }

    // TODO: actually scan something
    Ok(())
}

fn dump_state(
    open: &mut Open,
    todo: &mut VecDeque<Proposal>,
    stats: &mut Statistics,
    results: &mut Results,
    opts: &ScanOptionsV2,
) -> ScannerSerialization {
    ScannerSerialization {}
}

/// Handler around a running IKEv2 scan
pub struct ScanV2Handler {
    task: JoinHandle<Result<(), ScanError>>,
    socket: Arc<UdpSocket>,
    controller: mpsc::Sender<ControlChannelEvent>,
}

impl ScanV2Handler {
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

    /// Dump the current state of the scan in a serialized format
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

    /// Abort the currently running scan
    pub async fn abort(&self) {
        let _ = self.controller.send(ControlChannelEvent::Abort).await;
        self.task.abort()
    }

    /// Check if the running scan is finished
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Complete the running scan and yield its result
    pub async fn complete(self) -> Result<Result<(), ScanError>, JoinError> {
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
