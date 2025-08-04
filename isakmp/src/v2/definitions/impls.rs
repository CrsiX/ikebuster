use crate::v2::definitions::params::SecurityProtocol;
use crate::v2::definitions::{Proposal, Transform};

impl Proposal {
    /// Return the length of the [Proposal] as sum of the number of all its transform
    pub fn len(&self) -> usize {
        self.encryption_algorithms.len()
            + self.pseudo_random_functions.len()
            + self.integrity_algorithms.len()
            + self.key_exchange_methods.len()
            + self.sequence_numbers.len()
    }

    /// Check whether the [Proposal] has no transforms at all
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Add a number of transforms to the [Proposal], grouping by the correct transform type
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

    /// Easily construct a new empty [Proposal] with the supplied protocol and SPI
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
