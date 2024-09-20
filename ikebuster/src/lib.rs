//! # ikebuster
//!
//! A small utility to scan your IKE servers for insecure ciphers

#![warn(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use isakmp::strum::IntoEnumIterator;
use isakmp::v1::AuthenticationMethod;
use isakmp::v1::EncryptionAlgorithm;
use isakmp::v1::GroupDescription;
use isakmp::v1::HashAlgorithm;
use itertools::iproduct;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::error;
use tracing::info;
use tracing::instrument;
use tracing::Instrument;

use crate::v1::generation::MessageBuilder;
use crate::v1::generation::Transform;

mod recv;
pub mod v1;

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
    pub interval: usize,
    /// Number of transforms to send in a single proposal
    pub transform_no: usize,
}

/// Scan the provided ip address
#[instrument(skip_all)]
pub async fn scan(opts: ScanOptions) -> Result<ScanResult, Box<dyn Error>> {
    let addr = SocketAddr::new(opts.ip, opts.port);

    info!("Trying to connect to {addr}");
    let socket = Arc::new(match addr.ip() {
        IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await?,
        IpAddr::V6(_) => UdpSocket::bind("[::]:0").await?,
    });
    socket.connect(&addr).await?;

    let messages = Arc::new(Mutex::new(HashMap::new()));

    let s = socket.clone();
    let m = messages.clone();
    let t: JoinHandle<Result<(), String>> =
        tokio::spawn(recv::handle_receive(s, m).instrument(tracing::info_span!("recv")));

    sleep(Duration::from_millis(100)).await;

    let iterator = iproduct!(
        EncryptionAlgorithm::iter().filter(|x| *x as u16 != 0),
        HashAlgorithm::iter().filter(|x| *x as u16 != 0),
        AuthenticationMethod::iter().filter(|x| *x as u16 != 0),
        GroupDescription::iter().filter(|x| *x as u16 != 0),
    )
    .fold(vec![], |mut acc, (e, h, a, g)| {
        if e == EncryptionAlgorithm::AES_CBC {
            acc.push((e, h, a, g, Some(128)));
            acc.push((e, h, a, g, Some(192)));
            acc.push((e, h, a, g, Some(256)));
        } else {
            acc.push((e, h, a, g, None));
        }

        acc
    });

    const CHUNK_SIZE: usize = 100;
    let mut curr = 0;
    for chunk in iterator.chunks(CHUNK_SIZE) {
        curr += CHUNK_SIZE;

        let mut mb = MessageBuilder::new();

        let mut transforms = vec![];

        for (enc, hash, auth, group, key_size) in chunk {
            let transform = Transform {
                encryption_algorithm: *enc,
                hash_algorithm: *hash,
                authentication_method: *auth,
                group_description: *group,
                key_size: *key_size,
            };
            transforms.push(transform.clone());
            mb = mb.add_transform(transform);
        }

        let (raw, initiator) = mb.build();

        messages.lock().unwrap().insert(initiator, transforms);

        socket.send(&raw).await?;

        sleep(Duration::from_millis(100)).await;
    }

    info!("Finished sending transforms");

    if let Err(err) = t.await? {
        error!("{err}");
        return Err(Box::from(err));
    }

    Ok(ScanResult {
        valid_transforms: vec![],
    })
}
