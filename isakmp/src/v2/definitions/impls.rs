use crate::v2::definitions::params::{
    EncryptionAlgorithm, ExchangeType, KeyExchangeMethod, SecurityProtocol,
};
use crate::v2::definitions::{IKEv2, Payload, Proposal, Transform};

impl IKEv2 {
    /// Create a "hello" (`IKE_SA_INIT`) packet with the respective payloads that
    /// can be sent to an IKEv2 receiver (server)
    pub fn hello(payloads: Vec<Payload>) -> Self {
        Self {
            initiator_cookie: rand::random(),
            responder_cookie: 0,
            exchange_type: ExchangeType::IkeSaInit,
            initiator: true,
            response: false,
            message_id: 0,
            payloads,
        }
    }
}

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

    /// Easily construct a new [Proposal] with the supplied protocol that is already configured
    /// with the number of transforms grouped by the correct transform type but with an empty SPI
    pub fn new_full(protocol: SecurityProtocol, transforms: Vec<Transform>) -> Self {
        let mut new = Self::new_empty(protocol, None);
        new.add(transforms);
        new
    }
}

impl EncryptionAlgorithm {
    /// Determine if an encryption algorithm usually has a key length attribute and
    /// get a list of typical key lengths. An empty Vec means that no key length
    /// attribute should be used at all.
    pub fn get_key_lengths(&self) -> Vec<u16> {
        match self {
            EncryptionAlgorithm::DES_IV64 => vec![], // RFC 7296
            EncryptionAlgorithm::DES => vec![],      // RFC 7296
            EncryptionAlgorithm::TRIPLE_DES => vec![112, 168], // Wikipedia
            EncryptionAlgorithm::RC5 => vec![64, 128, 256], // RFC 7296: it allows for variable-length keys
            EncryptionAlgorithm::IDEA => vec![],            // RFC 7296
            EncryptionAlgorithm::CAST => vec![128], // no source, but it should work with 128 bits
            EncryptionAlgorithm::BLOWFISH => vec![48, 128, 256], // RFC 7296: it allows for variable-length keys
            EncryptionAlgorithm::TRIPLE_IDEA => vec![],          // RFC 7296
            EncryptionAlgorithm::DES_IV32 => vec![],             // RFC 7296
            EncryptionAlgorithm::NULL => vec![],                 // obviously bad
            EncryptionAlgorithm::AES_CBC => vec![128, 196, 256], // RFC 3602
            EncryptionAlgorithm::AES_CTR => vec![128, 196, 256], // RFC 3686
            EncryptionAlgorithm::AES_CCM_8 => vec![128, 196, 256], // RFC 4106
            EncryptionAlgorithm::AES_CCM_12 => vec![128, 196, 256], // RFC 4106
            EncryptionAlgorithm::AES_CCM_16 => vec![128, 196, 256], // RFC 4106
            EncryptionAlgorithm::AES_GCM_8 => vec![128, 196, 256], // RFC 4106
            EncryptionAlgorithm::AES_GCM_12 => vec![128, 196, 256], // RFC 4106
            EncryptionAlgorithm::AES_GCM_16 => vec![128, 196, 256], // RFC 4106
            EncryptionAlgorithm::NULL_AUTH_AES_GMAC => vec![], // unknown but should not be used anyway
            EncryptionAlgorithm::CAMELLIA_CBC => vec![128, 196, 256], // RFC 5529
            EncryptionAlgorithm::CAMELLIA_CTR => vec![128, 196, 256], // RFC 5529
            EncryptionAlgorithm::CAMELLIA_CCM_8 => vec![128, 196, 256], // RFC 5529
            EncryptionAlgorithm::CAMELLIA_CCM_12 => vec![128, 196, 256], // RFC 5529
            EncryptionAlgorithm::CAMELLIA_CCM_16 => vec![128, 196, 256], // RFC 5529
            EncryptionAlgorithm::CHACHA20_POLY1305 => vec![],
            EncryptionAlgorithm::AES_CCM_8_IIV => vec![128, 196, 256],
            EncryptionAlgorithm::AES_GCM_16_IIV => vec![128, 196, 256],
            EncryptionAlgorithm::CHACHA20_POLY1305_IIV => vec![],
            EncryptionAlgorithm::KUZNYECHIK_MGM_KTREE => vec![], // fixed key length: 256 bits
            EncryptionAlgorithm::MAGMA_MGM_KTREE => vec![],      // fixed key length: 256 bits
            EncryptionAlgorithm::KUZNYECHIK_MGM_MAC_KTREE => vec![], // fixed key length: 256 bits
            EncryptionAlgorithm::MAGMA_MGM_MAC_KTREE => vec![],  // fixed key length: 256 bits
        }
    }
}

impl KeyExchangeMethod {
    /// Determine the length of the key handshake in bytes
    pub fn get_key_handshake_length(&self) -> usize {
        match self {
            KeyExchangeMethod::None => 0,
            KeyExchangeMethod::ModP_768 => 96,
            KeyExchangeMethod::ModP_1024 => 128,
            KeyExchangeMethod::ModP_1536 => 192,
            KeyExchangeMethod::ModP_2048 => 256,
            KeyExchangeMethod::ModP_3072 => 384,
            KeyExchangeMethod::ModP_4096 => 512,
            KeyExchangeMethod::ModP_6144 => 768,
            KeyExchangeMethod::ModP_8192 => 1024,
            KeyExchangeMethod::ECP_Random_256 => 64,
            KeyExchangeMethod::ECP_Random_384 => 96,
            KeyExchangeMethod::ECP_Random_521 => 132,
            KeyExchangeMethod::ModP_1024_Prime_160 => 128, // unverified
            KeyExchangeMethod::ModP_2048_Prime_224 => 256, // unverified
            KeyExchangeMethod::ModP_2048_Prime_256 => 256, // unverified
            KeyExchangeMethod::ECP_Random_192 => 48,
            KeyExchangeMethod::ECP_Random_224 => 56,
            KeyExchangeMethod::ECP_Brainpool_224 => 28, // unverified
            KeyExchangeMethod::ECP_Brainpool_256 => 32, // unverified
            KeyExchangeMethod::ECP_Brainpool_384 => 48, // unverified
            KeyExchangeMethod::ECP_Brainpool_512 => 64, // unverified
            KeyExchangeMethod::Curve_25519 => 32,
            KeyExchangeMethod::Curve_448 => 56, // unverified
            KeyExchangeMethod::GOST3410_2012_256 => 32, // unverified
            KeyExchangeMethod::GOST3410_2012_512 => 64, // unverified
            KeyExchangeMethod::ML_KEM_512 => 64, // unverified
            KeyExchangeMethod::ML_KEM_768 => 96, // unverified
            KeyExchangeMethod::ML_KEM_1024 => 128, // unverified
        }
    }
}
