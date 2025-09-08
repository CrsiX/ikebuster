use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use isakmp::v2::definitions::constants::MIN_SUPPORTED_MSG_SIZE;
use isakmp::v2::definitions::{IKEv2, KeyExchange, Payload, Proposal, SecurityAssociation};
use tokio::net::UdpSocket;
use tracing::{debug, error, instrument, warn};

use crate::v2::{Open, ScanOptionsV2, Statistics};
use crate::ScanError;

/// Maximum number of packets that should be kept in `open` state simultaneously
const SENT_THRESHOLD: usize = 5;

/// Send IKEv2 `IKE_SA_INIT` messages, returning whether any packet was sent;
/// it will first retry any packet that has already been sent at least once,
/// and then check for proposal lists that need to be verified before
/// trying new proposals that have not been attempted yet
pub(crate) async fn handle_sending_hello(
    stats: &mut Statistics,
    open: &mut Open,
    todo: &mut VecDeque<Proposal>,
    socket: &Arc<UdpSocket>,
    options: &ScanOptionsV2,
) -> Result<bool, ScanError> {
    if let Some(packet) = open.retry.pop() {
        send_packet(packet, socket, open, stats).await?;
        return Ok(true);
    }

    if open.sent.len() >= SENT_THRESHOLD {
        return Ok(false);
    }
    if let Some(proposals) = open.verify.pop() {
        if let Some((packet, unused_proposals)) = make_new_hello_packet(proposals) {
            if !unused_proposals.is_empty() {
                open.verify.push(unused_proposals);
            }
            send_packet(packet, socket, open, stats).await?;
        }
        return Ok(true);
    }

    let mut proposals = vec![];
    for _ in 0..options.transform_no {
        if let Some(proposal) = todo.pop_front() {
            proposals.push(proposal);
        }
    }
    if let Some((packet, unused_proposals)) = make_new_hello_packet(proposals) {
        for p in unused_proposals {
            todo.push_front(p)
        }
        send_packet(packet, socket, open, stats).await?;
    }
    Ok(true)
}

/// Send a single [IKEv2] packet and keep track of stats and open connections
#[instrument(skip_all, fields(payloads = packet.payloads.len(), proposals = count_proposals(&packet)))]
pub(crate) async fn send_packet(
    packet: IKEv2,
    socket: &Arc<UdpSocket>,
    open: &mut Open,
    stats: &mut Statistics,
) -> Result<(), ScanError> {
    let serialized_msg = packet.try_build().map_err(ScanError::GeneratorFailed)?;
    let ts = Instant::now();
    let sent_bytes = match socket.send(serialized_msg.as_slice()).await {
        Ok(v) => v,
        Err(err) => {
            warn!("Sending failed: {}: {:#?}", err.kind(), err);
            // For ErrorKind::Uncategorized errors with error number 90, the MTU
            // along the path was lower than expected. If Path MTU Discovery is enabled,
            // this error signals that the sender should reduce the packet size.
            // However, since the kernel performs Path MTU Discovery as well,
            // simply retrying to send the packet once will already solve the problem,
            // as the kernel will fragment the outgoing UDP packet correctly.
            if let Some(e) = err.raw_os_error() {
                if e == 90 {
                    debug!(
                        "Detected raw OS error value 90. This is likely due to Path
                        MTU Discovery. Retrying to send the packet once..."
                    );
                    let sent_bytes = socket.send(serialized_msg.as_slice()).await.map_err(|e| {
                        error!("Failed to resend the packet after MTU discovery: {}", e);
                        ScanError::Send(e)
                    })?;
                    open.sent.push((packet, ts));
                    stats.sent_bytes += sent_bytes as u64;
                    stats.sent_packets += 1;
                    return Ok(());
                }
            }
            return Err(ScanError::Send(err));
        }
    };
    open.sent.push((packet, ts));
    stats.sent_bytes += sent_bytes as u64;
    stats.sent_packets += 1;
    Ok(())
}

/// Construct a new hello packet from a list of proposals that should be used in the
/// SA of that packet, returning the packet and all unused proposals on success.
/// Proposals may not all be used if the packet would grow too large if they were added.
fn make_new_hello_packet(mut proposals: Vec<Proposal>) -> Option<(IKEv2, Vec<Proposal>)> {
    let mut used_proposals = vec![];
    if let Some(p) = proposals.pop() {
        used_proposals.push(p);
    } else {
        return None;
    }
    let mut packet = if let Some(dh_group) = match used_proposals.first() {
        Some(first) => first.key_exchange_methods.first().cloned(),
        None => None,
    } {
        IKEv2::hello(vec![
            Payload::SecurityAssociation(SecurityAssociation { proposals: vec![] }),
            Payload::KeyExchange(KeyExchange {
                dh_group,
                data: get_random_vec(dh_group.get_key_handshake_length()),
            }),
            Payload::Nonce(get_random_vec(16)),
        ])
    } else {
        return None;
    };

    let mut current_len = packet
        .try_build()
        .map_err(ScanError::GeneratorFailed)
        .ok()?
        .len();

    while let Some(next) = proposals.last() {
        let serialized_proposal_len = next
            .try_build(1, true)
            .map_err(ScanError::GeneratorFailed)
            .ok()?
            .len();
        if current_len + serialized_proposal_len <= MIN_SUPPORTED_MSG_SIZE {
            current_len += serialized_proposal_len;
            for payload in packet.payloads.iter_mut() {
                if let Payload::SecurityAssociation(sa) = payload {
                    sa.proposals.push(proposals.pop()?);
                    break;
                }
            }
        } else {
            break;
        }
    }
    Some((packet, proposals))
}

fn count_proposals(packet: &IKEv2) -> usize {
    packet
        .payloads
        .iter()
        .filter_map(|p| match p {
            Payload::SecurityAssociation(sa) => Some(sa.proposals.len()),
            _ => None,
        })
        .sum()
}

/// Create a `Vec<u8>` filled with random bytes
///
/// These bytes are not guaranteed to be cryptographically safe.
pub fn get_random_vec(len: usize) -> Vec<u8> {
    rand::random_iter().take(len).collect()
}
