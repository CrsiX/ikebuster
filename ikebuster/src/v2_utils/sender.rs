use crate::v2_utils::{Open, ScanOptionsV2, Statistics};
use crate::ScanError;
use isakmp::v2::definitions;
use isakmp::v2::definitions::{IKEv2, Payload, Proposal, SecurityAssociation};
use isakmp::v2::utils::get_random_vec;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;

/// Maximum number of packets that should be kept in `open` state simultaneously
const SENT_THRESHOLD: usize = 4;

/// Send IKEv2 `IKE_SA_INIT` packages, returning whether any packet was sent;
/// it will first retry any packet that has already been sent at least once
pub(crate) async fn handle_sending_hello(
    stats: &mut Statistics,
    open: &mut Open,
    todo: &mut VecDeque<Proposal>,
    socket: &Arc<UdpSocket>,
    options: &ScanOptionsV2,
) -> Result<bool, ScanError> {
    if let Some(packet) = open.retry.pop() {
        let serialized_msg = packet.try_build().map_err(ScanError::GeneratorFailed)?;
        let ts = Instant::now();
        let sent_bytes = socket
            .send(serialized_msg.as_slice())
            .await
            .map_err(ScanError::Send)?;
        open.sent.push((packet, ts));
        stats.sent_bytes += sent_bytes as u64;
        stats.sent_packets += 1;
        return Ok(true);
    }

    if open.sent.len() >= SENT_THRESHOLD {
        return Ok(false);
    }
    if let Some(packet) = make_new_hello_packet(todo, options) {
        let serialized_msg = packet.try_build().map_err(ScanError::GeneratorFailed)?;
        let ts = Instant::now();
        let sent_bytes = socket
            .send(serialized_msg.as_slice())
            .await
            .map_err(ScanError::Send)?;
        open.sent.push((packet, ts));
        stats.sent_bytes += sent_bytes as u64;
        stats.sent_packets += 1;
    }
    Ok(true)
}

fn make_new_hello_packet(todo: &mut VecDeque<Proposal>, options: &ScanOptionsV2) -> Option<IKEv2> {
    let mut proposals = vec![];
    for _ in 0..options.transform_no {
        if let Some(proposal) = todo.pop_front() {
            proposals.push(proposal);
        }
    }
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
