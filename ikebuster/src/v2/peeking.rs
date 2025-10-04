use isakmp::v2::definitions::params::EncryptionAlgorithm;
use isakmp::v2::definitions::params::IntegrityAlgorithm;
use isakmp::v2::definitions::params::KeyExchangeMethod;
use isakmp::v2::definitions::params::NotifyErrorMessage;
use isakmp::v2::definitions::params::PseudorandomFunction;
use isakmp::v2::definitions::params::SecurityProtocol;
use isakmp::v2::definitions::IKEv2;
use isakmp::v2::definitions::NotificationType;
use isakmp::v2::definitions::Payload;
use isakmp::v2::definitions::Proposal;
use isakmp::v2::definitions::Transform;
use isakmp::v2::parser::ParserError;
use tokio::net::UdpSocket;
use tracing::debug;
use tracing::error;
use tracing::info;

use crate::v2::sender::make_new_hello_packet;
use crate::v2::MAX_DATAGRAM_SIZE;
use crate::ScanError;

/// Peek towards the IKEv2 destination and send a single [IKEv2] packet with
/// two huge proposals that accept a lot of defaults to determine if the
/// destination is likely to accept our scan. It will not be a fool-proof indicator,
/// but if this returns `false` then the scan might not produce any results.
/// Note that this should be done at the start of the scan, because it can quickly
/// determine if a host is dead or does not support [IKEv2] at all.
pub(crate) async fn peek(socket: &UdpSocket) -> Result<bool, ScanError> {
    // These two proposals list a lot of transformations that are seen often
    // and therefore are likely to be accepted by a responder that is
    // willing to negotiate using the standard ciphers.
    let mut p1 = Proposal::new_empty(SecurityProtocol::InternetKeyExchange, Some(vec![]));
    p1.add(vec![
        Transform::Encryption(EncryptionAlgorithm::AES_CBC, Some(128)),
        Transform::Encryption(EncryptionAlgorithm::AES_CBC, Some(256)),
        Transform::Encryption(EncryptionAlgorithm::AES_CTR, Some(256)),
        Transform::Encryption(EncryptionAlgorithm::TRIPLE_DES, None),
        Transform::Encryption(EncryptionAlgorithm::RC5, Some(256)),
        Transform::Encryption(EncryptionAlgorithm::CAMELLIA_CBC, Some(256)),
        Transform::Encryption(EncryptionAlgorithm::CAMELLIA_CTR, Some(256)),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_MD5),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA1),
        Transform::PseudoRandomFunction(PseudorandomFunction::AES128_CMAC),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_256),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_384),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_512),
        Transform::Integrity(IntegrityAlgorithm::HMAC_MD5_96),
        Transform::Integrity(IntegrityAlgorithm::HMAC_MD5_128),
        Transform::Integrity(IntegrityAlgorithm::HMAC_SHA1_96),
        Transform::Integrity(IntegrityAlgorithm::AES_128_GMAC),
        Transform::Integrity(IntegrityAlgorithm::AES_256_GMAC),
        Transform::Integrity(IntegrityAlgorithm::HMAC_SHA2_256_128),
        Transform::Integrity(IntegrityAlgorithm::HMAC_SHA2_384_192),
        Transform::Integrity(IntegrityAlgorithm::HMAC_SHA2_512_256),
        Transform::KeyExchange(KeyExchangeMethod::MODP_2048),
        Transform::KeyExchange(KeyExchangeMethod::ECP_Random_192),
        Transform::KeyExchange(KeyExchangeMethod::ECP_Random_384),
        Transform::KeyExchange(KeyExchangeMethod::ECP_Random_521),
        Transform::KeyExchange(KeyExchangeMethod::MODP_1024),
        Transform::KeyExchange(KeyExchangeMethod::MODP_3072),
        Transform::KeyExchange(KeyExchangeMethod::MODP_4096),
        Transform::KeyExchange(KeyExchangeMethod::Curve_448),
        Transform::KeyExchange(KeyExchangeMethod::Curve_25519),
    ]);
    let mut p2 = Proposal::new_empty(SecurityProtocol::InternetKeyExchange, Some(vec![]));
    p2.add(vec![
        Transform::Encryption(EncryptionAlgorithm::AES_CCM_8, Some(256)),
        Transform::Encryption(EncryptionAlgorithm::AES_CCM_16, Some(256)),
        Transform::Encryption(EncryptionAlgorithm::AES_GCM_8, Some(256)),
        Transform::Encryption(EncryptionAlgorithm::AES_GCM_16, Some(256)),
        Transform::Encryption(EncryptionAlgorithm::CHACHA20_POLY1305, None),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_MD5),
        Transform::PseudoRandomFunction(PseudorandomFunction::AES128_CMAC),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_256),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_384),
        Transform::PseudoRandomFunction(PseudorandomFunction::HMAC_SHA2_512),
        Transform::KeyExchange(KeyExchangeMethod::ECP_Random_192),
        Transform::KeyExchange(KeyExchangeMethod::ECP_Random_384),
        Transform::KeyExchange(KeyExchangeMethod::ECP_Random_521),
        Transform::KeyExchange(KeyExchangeMethod::MODP_1024),
        Transform::KeyExchange(KeyExchangeMethod::MODP_2048),
        Transform::KeyExchange(KeyExchangeMethod::MODP_3072),
        Transform::KeyExchange(KeyExchangeMethod::MODP_4096),
        Transform::KeyExchange(KeyExchangeMethod::Curve_448),
        Transform::KeyExchange(KeyExchangeMethod::Curve_25519),
    ]);
    let proposals = vec![p1, p2];

    if let Some((msg, _)) = make_new_hello_packet(proposals) {
        let serialized_msg = msg.try_build().map_err(ScanError::GeneratorFailed)?;
        let sent_bytes = socket
            .send(serialized_msg.as_slice())
            .await
            .map_err(ScanError::Send)?;
        debug!(
            "Sent {} bytes with huge proposal to check availability",
            sent_bytes
        );

        let mut accepted_indicators = 0;
        let mut recv_buffer = [0u8; MAX_DATAGRAM_SIZE];
        match socket.recv(&mut recv_buffer).await {
            Ok(recv_bytes) => {
                debug!(
                    data = ?&recv_buffer[..recv_bytes],
                    "Received {} bytes from responder",
                    recv_bytes
                );
                match IKEv2::try_parse(&recv_buffer[..recv_bytes]) {
                    Ok(packet) => {
                        accepted_indicators += 1;
                        for payload in packet.payloads.iter() {
                            match payload {
                                Payload::SecurityAssociation(_)
                                | Payload::KeyExchange(_)
                                | Payload::Nonce(_) => accepted_indicators += 1,
                                Payload::Notify(n) => {
                                    if let NotificationType::Error(e) = n.variant {
                                        match e {
                                            NotifyErrorMessage::InvalidMajorVersion => {
                                                accepted_indicators -= 100;
                                                error!(
                                                    "Destination is not capable of speaking IKEv2"
                                                );
                                            }
                                            NotifyErrorMessage::NoProposalChosen
                                            | NotifyErrorMessage::InvalidSyntax => {
                                                accepted_indicators -= 100
                                            }
                                            NotifyErrorMessage::InvalidKeyExchangePayload => {
                                                accepted_indicators += 1
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(err) => {
                        if let ParserError::WrongProtocol = err {
                            info!(err = ?err, "Responder replied with different IKE protocol version. Try IKEv1.")
                        } else {
                            error!(err = ?err, "Failed to parse IKEv2 packet: {}", err);
                        }
                        accepted_indicators -= 100;
                    }
                }
            }
            Err(e) => {
                error!("Failed to read bytes from socket: {e}");
                return Err(ScanError::Receive(e));
            }
        }
        if accepted_indicators > 0 {
            info!(
                "Positive acceptance indicators ({}), destination likely accepts our IKEv2 scan",
                accepted_indicators
            );
        } else if accepted_indicators == 0 {
            info!(
                "Neutral acceptance indicators ({}), unknown if destination accepts our IKEv2 scan",
                accepted_indicators
            );
        } else {
            info!(
                "Negative acceptance indicators ({}), destination likely rejects our IKEv2 scan",
                accepted_indicators
            );
        }
        Ok(accepted_indicators > 0)
    } else {
        Ok(false)
    }
}
