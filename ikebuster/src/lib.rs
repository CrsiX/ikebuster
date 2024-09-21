//! # ikebuster
//!
//! A small utility to scan your IKE servers for insecure ciphers

#![warn(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use isakmp::v1::definitions::NotifyMessageType;
use isakmp::v1::generator::MessageBuilder;
use isakmp::v1::generator::Transform;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::interval;
use tokio::time::sleep;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::instrument;
use tracing::trace;
use tracing::warn;

use crate::recv::ReceiveError;
use crate::utils::gen_transforms::gen_v1_transforms;
use crate::utils::payload_to_transforms::payload_to_transforms;

mod recv;
pub mod utils;

/// The results of the scan
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// All transforms that were accepted by the target server
    pub valid_transforms: Vec<Transform>,
}

/// Options to "configure" the scanner
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Target IP
    pub ip: IpAddr,
    /// Target port
    pub port: u16,
    /// Interval between each sent message
    pub interval: u64,
    /// Number of transforms to send in a single proposal
    pub transform_no: usize,
    /// The sleep to set when a valid transform is found.
    ///
    /// This may be important as some servers timeout requests when requests aren't fully closed
    pub sleep_on_transform_found: Duration,
}

/// Scan the provided ip address
#[instrument(skip_all)]
pub async fn scan(opts: ScanOptions) -> Result<ScanResult, ScanError> {
    // Initialize udp socket
    let addr = SocketAddr::new(opts.ip, opts.port);

    info!("Binding and starting to scan {addr}");
    let socket = Arc::new(match addr.ip() {
        IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:500")
            .await
            .map_err(ScanError::CouldNotBind)?,
        IpAddr::V6(_) => UdpSocket::bind("[::]:500")
            .await
            .map_err(ScanError::CouldNotBind)?,
    });
    socket.connect(&addr).await.map_err(ScanError::Receive)?;

    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut interval = interval(Duration::from_millis(opts.interval));

    tokio::spawn(recv::handle_receive(socket.clone(), tx));

    // list of a list of transforms which should be sent in the future
    let mut todo: VecDeque<Vec<_>> = gen_v1_transforms(opts.transform_no);

    // Lookup of cookie to the transforms that were sent in the corresponding message
    let mut open: HashMap<u64, Vec<Transform>> = HashMap::new();

    // The valid transforms that were found
    let mut found: Vec<Transform> = vec![];

    // If sleep is active, the sending part will pause
    let mut do_sleep = false;

    loop {
        select! {
            // Handle received isakmp messages or errors from receiving side
            msg_res = rx.recv() => {
                if let Some(res) = msg_res {
                    match res {
                        Ok(msg) => {
                            trace!("Received message: {msg:?}");

                            // Retrieving a security association means we got at least one transform right
                            if !msg.security_associations.is_empty() {
                                for sa in &msg.security_associations {
                                    for prop in &sa.proposal_payload {
                                        do_sleep = true;

                                        let Ok(transforms) = payload_to_transforms(prop) else {
                                            warn!("Could not retrieve transform from msg: {msg:?}");
                                            debug!("{msg:?}");
                                            continue;
                                        };

                                        // Add the found transform to our list
                                        found.extend(transforms.clone());

                                        let Some(all) = open.get(&msg.header.initiator_cookie) else {
                                            warn!("Missing initiator cookie");
                                            trace!("{} :: {:#?}", msg.header.initiator_cookie, open);
                                            continue;
                                        };

                                        // Retrieve all transforms not returned in the message
                                        let other: Vec<Transform> = all.clone().into_iter().filter(|x| !transforms.contains(x)).collect();

                                        // Split the transforms into two new messages
                                        let  [mut a,mut b] = [vec![], vec![]];
                                        for x in other {
                                            if a.len() == b.len() {
                                                a.push(x);
                                            } else {
                                                b.push(x);
                                            }
                                        }

                                        // create new todos
                                        if !b.is_empty() {
                                            todo.push_back(a);
                                            todo.push_back(b);
                                        } else if !a.is_empty() {
                                            todo.push_back(a);
                                        }
                                    }
                                }
                                let removed = open.remove(&msg.header.initiator_cookie);
                                if removed.is_none() {
                                    warn!("Could not find corresponding initiator cookie: {}", msg.header.initiator_cookie);
                                }

                            // A notification of type NO_PROPOSAL_CHOSEN means all transforms were invalid
                            } else if msg.notification_payloads.iter().any(|x| x.notify_message_type == NotifyMessageType::NoProposalChosen) {
                                let removed = open.remove(&msg.header.initiator_cookie);
                                if removed.is_none() {
                                    warn!("Could not find corresponding initiator cookie: {}", msg.header.initiator_cookie);
                                }
                            } else {
                                warn!("Unknown message: {:?}", msg)
                            }

                        }
                        Err(err) => match err {
                            ReceiveError::Io(err) => {
                                error!("Error in receiving side: {err}");
                                return Err(ScanError::Receive(err));
                            }
                            ReceiveError::InvalidMessage(err) => {
                                trace!("Could not parse incoming message: {err}");
                            }}
                    }
                }
            }

            // Handle the sending of messages
            _ = interval.tick() => {
                match todo.pop_front() {
                    // Nothing more todo, this will be the return path
                    None => {
                        debug!("Nothing more to do, waiting some time for more incoming messages");
                        interval.tick().await;
                        if todo.is_empty() {
                            found.sort();
                            found.dedup();

                            return Ok(ScanResult {
                                valid_transforms: found,
                             })
                        }
                    }
                    Some(transforms) => {
                        let mut mb = MessageBuilder::new();
                        for transform in &transforms {
                            mb = mb.add_transform(transform.clone());
                        }
                        let (msg, initiator_cookie) = mb.build();
                        trace!("Send ({initiator_cookie}) transforms: {transforms:?}");

                        if do_sleep {
                            info!(
                                "Sleep {} seconds to evade running into timeout due to half-open connections",
                                opts.sleep_on_transform_found.as_secs(),
                            );
                            sleep(opts.sleep_on_transform_found).await;
                            do_sleep = false;
                        }

                        open.insert(initiator_cookie, transforms);
                        socket.send(&msg).await.map_err(ScanError::Send)?;

                    }}

            }
        }
    }
}

/// Errors that may occur while scanning
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum ScanError {
    #[error("Could not bind: {0}")]
    CouldNotBind(io::Error),
    #[error("Could not recv: {0}")]
    Receive(io::Error),
    #[error("Could not send: {0}")]
    Send(io::Error),
}
