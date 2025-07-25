use crate::v2::definitions::params::SecurityProtocol;
use crate::v2::definitions::{Proposal, Transform};

impl Proposal {
    pub fn len(&self) -> usize {
        self.encryption_algorithms.len()
            + self.pseudo_random_functions.len()
            + self.integrity_algorithms.len()
            + self.key_exchange_methods.len()
            + self.sequence_numbers.len()
    }

    pub fn add(&mut self, transforms: Vec<Transform>) {
        for transform in transforms {
            match transform {
                Transform::Encryption(a, o) => self.encryption_algorithms.push((a, o)),
                Transform::PseudoRandomFunction(p) => self.pseudo_random_functions.push(p),
                Transform::Integrity(i) => self.integrity_algorithms.push(i),
                Transform::KeyExchange(k) => self.key_exchange_methods.push(k),
                Transform::SequenceNumber(s) => self.sequence_numbers.push(s),
            }
        }
    }

    pub fn new_empty(protocol: SecurityProtocol, spi: Option<Vec<u8>>) -> Self {
        Self {
            protocol,
            spi: spi.unwrap_or_default(),
            encryption_algorithms: vec![],
            pseudo_random_functions: vec![],
            integrity_algorithms: vec![],
            key_exchange_methods: vec![],
            sequence_numbers: vec![],
        }
    }
}
