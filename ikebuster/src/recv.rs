use std::io;
use std::sync::Arc;

use isakmp::v1::parser::definitions::Packet;
use isakmp::v1::parser::errors::IsakmpParseError;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;

/// Handle the receival of isakmp messages
///
/// After a message is received, it is sent back via the provided channel
pub async fn handle_receive(
    socket: Arc<UdpSocket>,
    tx: UnboundedSender<Result<Packet, ReceiveError>>,
) {
    loop {
        const MAX_DATAGRAM_SIZE: usize = 65_507;
        let mut buf = [0u8; MAX_DATAGRAM_SIZE];
        let len = match socket.recv(&mut buf).await {
            Ok(len) => len,
            Err(e) => {
                let _res = tx.send(Err(ReceiveError::Io(e)));
                return;
            }
        };

        match isakmp::v1::parser::parse_packet(&buf[..len]) {
            Ok(packet) => {
                if tx.send(Ok(packet)).is_err() {
                    // Stop loop if we can't send to channel
                    return;
                }
            }
            Err(err) => {
                if tx.send(Err(ReceiveError::InvalidMessage(err))).is_err() {
                    // Stop loop if we can't send to channel
                    return;
                }
            }
        }
    }
}

/// Errors that may occur on the receiving side
#[derive(Debug, Error)]
pub enum ReceiveError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("Error while parsing message: {0}")]
    InvalidMessage(#[from] IsakmpParseError),
}
