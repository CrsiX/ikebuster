use isakmp::v2::definitions::IKEv2;
use tracing::{debug, error};

use crate::v2_utils::{Results, Statistics};

pub(crate) fn handle_receiving(stats: &mut Statistics, results: &mut Results, raw_rx: &[u8]) {
    match IKEv2::try_parse(raw_rx) {
        Ok(packet) => {
            handle_packet(packet, stats, results);
            stats.recv_packets += 1;
        }
        Err(err) => {
            error!(err = ?err, "Failed to parse IKEv2 packet: {}", err);
            debug!(buff = ?raw_rx, "Invalid IKEv2 packet: {:02x?}", raw_rx);
            stats.errors += 1;
        }
    }
}

fn handle_packet(packet: IKEv2, stats: &mut Statistics, results: &mut Results) {
    todo!()
}
