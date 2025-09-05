use isakmp::v2::definitions::params::{NotifyErrorMessage, NotifyStatusMessage, SecurityProtocol};
use isakmp::v2::definitions::{IKEv2, Notification, NotificationType, Payload, Proposal};
use tracing::{debug, error, instrument, warn};

use crate::v2_utils::{Open, Results, Statistics};

#[instrument(skip_all)]
pub(crate) fn handle_receiving(
    stats: &mut Statistics,
    open: &mut Open,
    results: &mut Results,
    raw_rx: &[u8],
) {
    match IKEv2::try_parse(raw_rx) {
        Ok(packet) => {
            handle_packet(packet, stats, open, results);
            stats.recv_packets += 1;
        }
        Err(err) => {
            error!(err = ?err, "Failed to parse IKEv2 packet: {}", err);
            debug!(buff = ?raw_rx, "Invalid IKEv2 packet: {:02x?}", raw_rx);
            stats.errors += 1;
        }
    }
}

/// Handle an [IKEv2] packet including updates to the statistics
fn handle_packet(packet: IKEv2, stats: &mut Statistics, open: &mut Open, results: &mut Results) {
    if !packet.response || packet.initiator {
        error!(
            packet = ?packet,
            "Received IKEv2 packet with response or initiator flags set, refusing to parse!"
        );
        stats.errors += 1;
        return;
    }

    let tracked_packet_index = match open
        .sent
        .iter()
        .position(|(p, _)| p.initiator_cookie == packet.initiator_cookie)
    {
        Some(index) => index,
        None => {
            error!(
                packet = ?packet,
                "Received IKEv2 packet with unknown initiator SPI not tracked in `open` connections!"
            );
            stats.errors += 1;
            return;
        }
    };

    // Handle notifications (e.g. DoS cookies and invalid proposals) before handling successful cases
    for payload in packet.payloads.iter() {
        if let Payload::Notify(n) = payload {
            match n.variant {
                NotificationType::Error(e) => {
                    match e {
                        NotifyErrorMessage::NoProposalChosen
                        | NotifyErrorMessage::InvalidSyntax => {
                            let (open_packet, _) = open.sent.swap_remove(tracked_packet_index);
                            return handle_rejected_or_invalid(
                                open_packet,
                                open,
                                stats,
                                results,
                                e,
                            );
                        }
                        NotifyErrorMessage::InvalidKeyExchangePayload => {
                            // TODO: add support for InvalidKeyExchangePayload
                            warn!(packet = ?packet, "InvalidKeyExchangePayload unsupported");
                        }
                        _ => {
                            warn!(packet = ?packet, "Unexpected error notification: {:?}", n);
                        }
                    }
                }
                NotificationType::Status(s) => {
                    match s {
                        NotifyStatusMessage::Cookie => {
                            let (open_packet, _) = open.sent.swap_remove(tracked_packet_index);
                            if handle_dos_cookie(open_packet, open, n) {
                                return;
                            };
                        }
                        // Simply ignore various status messages we are not interested in
                        NotifyStatusMessage::MultipleAuthSupported
                        | NotifyStatusMessage::NatDetectionSourceIp
                        | NotifyStatusMessage::NatDetectionDestinationIp
                        | NotifyStatusMessage::ChildlessIkev2Supported => {}
                        _ => {
                            warn!("Unexpected status notification: {:?}", n)
                        }
                    }
                }
            }
        }
    }

    // Successful handshakes produce SecurityAssociation payloads as response, but the
    // Proposal inside may be ordered differently and is identified by the Proposal number
    // that is not accessible here anymore, thus we need to iterate over all Proposals
    for payload in packet.payloads {
        match payload {
            Payload::SecurityAssociation(sa) => {
                let (open_packet, _) = open.sent.swap_remove(tracked_packet_index);
                if let Some(received_proposal) = sa.proposals.first() {
                    let mut todo = vec![];
                    for p in open_packet
                        .payloads
                        .into_iter()
                        .filter_map(|p| match p {
                            Payload::SecurityAssociation(sa) => Some::<Vec<Proposal>>(sa.proposals),
                            _ => None,
                        })
                        .flatten()
                    {
                        if p == *received_proposal {
                            results.accepted.push(p);
                            // TODO: return a Delete payload
                        } else {
                            todo.push(p);
                        }
                    }
                    if !todo.is_empty() {
                        open.verify.push(todo);
                    }
                }
            }
            Payload::KeyExchange(_) => {}        // TODO: verify KE
            Payload::CertificateRequest(_) => {} // TODO: verify CR
            Payload::VendorID(v) => {
                if !results.vendor_ids.contains(&v) {
                    results.vendor_ids.push(v);
                }
            }
            _ => {}
        }
    }
}

fn handle_rejected_or_invalid(
    open_packet: IKEv2,
    open: &mut Open,
    stats: &mut Statistics,
    results: &mut Results,
    variant: NotifyErrorMessage,
) {
    if let Some(&sa) = open_packet
        .payloads
        .iter()
        .filter_map(|p| match p {
            Payload::SecurityAssociation(sa) => Some(sa),
            _ => None,
        })
        .collect::<Vec<_>>()
        .first()
    {
        match &sa.proposals {
            v if v.len() == 0 => {
                error!(
                    packet = ?open_packet,
                    "Sent IKEv2 packet seems to have no proposals, found a bug."
                );
                stats.errors += 1;
            }
            v if v.len() == 1 => {
                if let Some(proposal) = v.first() {
                    match variant {
                        NotifyErrorMessage::NoProposalChosen => {
                            results.rejected.push(proposal.clone())
                        }
                        NotifyErrorMessage::InvalidSyntax => {
                            results.invalid_syntax.push(proposal.clone())
                        }
                        _ => {}
                    }
                }
            }
            v => {
                let [mut a, mut b] = [vec![], vec![]];
                for x in v {
                    if a.len() == b.len() {
                        a.push(x.clone());
                    } else {
                        b.push(x.clone());
                    }
                }
                open.verify.push(a);
                open.verify.push(b);
            }
        }
    }
}

/// Handle DoS cookies, returns `true` when the packet should be discarded
#[instrument(skip_all, fields(?notification))]
fn handle_dos_cookie(mut open_packet: IKEv2, open: &mut Open, notification: &Notification) -> bool {
    if notification.protocol == SecurityProtocol::InternetKeyExchange
        || notification.protocol == SecurityProtocol::Reserved
    {
        if notification.protocol == SecurityProtocol::Reserved {
            debug!(notification = ?notification, "Received cookie for Reserved, but using anyway");
        }
        if notification.data.len() > 64 {
            warn!(
                notification = ?notification,
                "Received cookie with more than 64 bytes payload, violating the protocol! Proceeding anyway..."
            );
        } else if notification.data.is_empty() {
            warn!(
                notification = ?notification,
                "Received empty cookie payload, violating the protocol! Proceeding anyway..."
            );
        }
        let data = notification.data.clone();
        open_packet.payloads.push(Payload::Notify(Notification {
            variant: NotificationType::Status(NotifyStatusMessage::Cookie),
            data,
            protocol: notification.protocol,
            spi: None,
        }));
        open.retry.push(open_packet);
        true
    } else {
        error!(
            "Received unexpected cookie for non-IKE protocol: {:#?}",
            notification
        );
        false
    }
}
