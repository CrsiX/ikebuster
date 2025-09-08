use std::collections::VecDeque;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Instant;

use isakmp::v2::definitions;
use isakmp::v2::definitions::{IKEv2, Payload, Proposal, SecurityAssociation};
use isakmp::v2::utils::get_random_vec;
use tokio::net::UdpSocket;
use tracing::{debug, error, instrument, warn};

use crate::v2_utils::{Open, ScanOptionsV2, Statistics};
use crate::ScanError;

/// Maximum number of packets that should be kept in `open` state simultaneously
const SENT_THRESHOLD: usize = 5;

/// Send IKEv2 `IKE_SA_INIT` packages, returning whether any packet was sent;
/// it will first retry any packet that has already been sent at least once,
/// and then check for proposal lists that need to be verified
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
        if let Some(packet) = make_new_hello_packet(proposals) {
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
    if let Some(packet) = make_new_hello_packet(proposals) {
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
                        "Detected raw OS error value 90. This is likely due to Path "
                        "MTU Discovery. Retrying to send the packet once..."
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

fn make_new_hello_packet(proposals: Vec<Proposal>) -> Option<IKEv2> {
    let dh_group = match proposals.first() {
        Some(first) => first.key_exchange_methods.first().cloned(),
        None => None,
    };
    dh_group.map(|dh_group| {
        IKEv2::hello(vec![
            Payload::SecurityAssociation(SecurityAssociation { proposals }),
            Payload::KeyExchange(definitions::KeyExchange {
                dh_group,
                data: get_random_vec(dh_group.get_key_handshake_length()),
            }),
            Payload::Nonce(get_random_vec(16)),
        ])
    })
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
