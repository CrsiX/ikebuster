//! IKEv2 parameters and their parsers as defined in the IANA IKEv2 list
//! found at https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml

use super::{Payload, Transform, UnparseableParameter};

use serde::{Deserialize, Serialize};

/// Bitflag for IKEv2 (ISAKMP) header to indicate whether the sender of the packet is
/// an initiator (bit set) or a responder (bit not set); see RFC 7296, section 3.1
pub const FLAG_INITIATOR: u8 = 0b1000;
/// Bitflag for IKEv2 (ISAKMP) header to indicate whether the sender is able to speak a
/// higher version of IKE than IKEv2; it must be unset for IKEv2; see RFC 7296, section 3.1
pub const FLAG_HIGHER_VERSION: u8 = 0b10000;
/// Bitflag for IKEv2 (ISAKMP) header to indicate that a message is a response to a message
/// containing the same message ID; it must be cleared in all requests and must be set in all
/// responses; receiving see RFC 7296, section 3.1
pub const FLAG_RESPONSE: u8 = 0b100000;

/// Bitflag for IKEv2 payload header to indicate whether the recipient of the message should skip it
/// if the message is not understood (bit not set) or reject the entire message (bit set), where the
/// flag must be zero for all officially described types found in the RFC; see RFC 7296, section 2.5
pub const FLAG_CRITICAL: u8 = 0b10000000;

/// Flag that specifies whether this is the last Proposal Substructure
/// in the [SecurityAssociation]. The respective field has a value of 0
/// if this was the last Proposal Substructure, and a value of 2 if
/// there are more Proposal Substructures. This syntax is inherited
/// from ISAKMP, but is unnecessary because the last Proposal could be
/// identified from the length of the SA. The value (2) corresponds
/// to a payload type of Proposal in IKEv1, and the first four octets
/// of the Proposal structure are designed to look somewhat like the
/// header of a payload.
pub const FLAG_MORE_FOLLOWING_PROPOSALS: u8 = 2;

/// Type of the exchanged being used
///
/// This constrains the payloads sent in each message in an exchange.
/// Notably, values 0-33 are reserved, 45-239 are currently unassigned
/// and 240-255 reserved for private use. Also see [UnparseableParameter].
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum ExchangeType {
    // RFC 7296
    IkeSaInit = 34,
    // RFC 7296
    IkeAuth = 35,
    // RFC 7296
    CreateChildSa = 36,
    // RFC 7296
    Informational = 37,
    // RFC 5723
    IkeSessionResume = 38,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaAuth = 39,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaRegistration = 40,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaRekey = 41,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaInbandRekey = 42,
    // RFC 9242
    IkeIntermediate = 43,
    // RFC 9370
    IkeFollowupKeyExchange = 44,
}

impl TryFrom<u8> for ExchangeType {
    type Error = UnparseableParameter;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0..=33 => Err(UnparseableParameter::Reserved),
            34 => Ok(ExchangeType::IkeSaInit),
            35 => Ok(ExchangeType::IkeAuth),
            36 => Ok(ExchangeType::CreateChildSa),
            37 => Ok(ExchangeType::Informational),
            38 => Ok(ExchangeType::IkeSessionResume),
            39 => Ok(ExchangeType::GsaAuth),
            40 => Ok(ExchangeType::GsaRegistration),
            41 => Ok(ExchangeType::GsaRekey),
            42 => Ok(ExchangeType::GsaInbandRekey),
            43 => Ok(ExchangeType::IkeIntermediate),
            44 => Ok(ExchangeType::IkeFollowupKeyExchange),
            45..=239 => Err(UnparseableParameter::Unassigned),
            240..=255 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Type of the payload being used
///
/// This constrains the payloads sent in each message in an exchange.
/// Refer to https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
/// for details. Notably, values 1-33 are reserved, 55-127 are currently unassigned
/// and 128-255 reserved for private use. Also see [UnparseableParameter].
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum PayloadType {
    // RFC 7296, this also matches the IKEv1 value while all other values do not
    NoNextPayload = 0,
    // RFC 7296, includes GM supported transforms as per draft-ietf-ipsecme-g-ikev2-22
    SecurityAssociation = 33,
    // RFC 7296
    KeyExchange = 34,
    // RFC 7296
    IdentificationInitiator = 35,
    // RFC 7296
    IdentificationResponder = 36,
    // RFC 7296
    Certificate = 37,
    // RFC 7296
    CertificateRequest = 38,
    // RFC 7296
    Authentication = 39,
    // RFC 7296
    Nonce = 40,
    // RFC 7296
    Notify = 41,
    // RFC 7296
    Delete = 42,
    // RFC 7296
    VendorID = 43,
    // RFC 7296
    TrafficSelectorInitiator = 44,
    // RFC 7296
    TrafficSelectorResponder = 45,
    // RFC 7296
    EncryptedAndAuthenticated = 46,
    // RFC 7296
    Configuration = 47,
    // RFC 7296
    ExtensibleAuthentication = 48,
    // RFC 6467
    GenericSecurePasswordMethod = 49,
    // draft-ietf-ipsecme-g-ikev2-22
    GroupIdentification = 50,
    // draft-ietf-ipsecme-g-ikev2-22
    GroupSecureAssociation = 51,
    // draft-ietf-ipsecme-g-ikev2-22
    KeyDownload = 52,
    // RFC 7383
    EncryptedAndAuthenticatedFragment = 53,
    // RFC 8019
    PuzzleSolution = 54,
}

impl TryFrom<u8> for PayloadType {
    type Error = UnparseableParameter;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PayloadType::NoNextPayload),
            1..=32 => Err(UnparseableParameter::Reserved),
            33 => Ok(PayloadType::SecurityAssociation),
            34 => Ok(PayloadType::KeyExchange),
            35 => Ok(PayloadType::IdentificationInitiator),
            36 => Ok(PayloadType::IdentificationResponder),
            37 => Ok(PayloadType::Certificate),
            38 => Ok(PayloadType::CertificateRequest),
            39 => Ok(PayloadType::Authentication),
            40 => Ok(PayloadType::Nonce),
            41 => Ok(PayloadType::Notify),
            42 => Ok(PayloadType::Delete),
            43 => Ok(PayloadType::VendorID),
            44 => Ok(PayloadType::TrafficSelectorInitiator),
            45 => Ok(PayloadType::TrafficSelectorResponder),
            46 => Ok(PayloadType::EncryptedAndAuthenticated),
            47 => Ok(PayloadType::Configuration),
            48 => Ok(PayloadType::ExtensibleAuthentication),
            49 => Ok(PayloadType::GenericSecurePasswordMethod),
            50 => Ok(PayloadType::GroupIdentification),
            51 => Ok(PayloadType::GroupSecureAssociation),
            52 => Ok(PayloadType::KeyDownload),
            53 => Ok(PayloadType::EncryptedAndAuthenticatedFragment),
            54 => Ok(PayloadType::PuzzleSolution),
            55..=127 => Err(UnparseableParameter::Unassigned),
            128..=255 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

impl From<&Payload<'_>> for PayloadType {
    fn from(value: &Payload) -> Self {
        match value {
            Payload::SecurityAssociation(_) => Self::SecurityAssociation,
            Payload::KeyExchange(_) => Self::KeyExchange,
            Payload::Nonce(_) => Self::Nonce,
            Payload::Notify(_) => Self::Notify,
            Payload::Delete(_) => Self::Delete,
            Payload::VendorID(_) => Self::VendorID,
            Payload::EncryptedAndAuthenticated(_) => Self::EncryptedAndAuthenticated,
        }
    }
}

/// Type of the transform being used
///
/// Value 0 is reserved, 15-240 is unassigned and 241-255 is
/// reserved for private use. Also see [UnparseableParameter].
///
/// The "Key Exchange Method (KE)" transform type was originally
/// named "Diffie-Hellman Group (D-H)" and was referenced by
/// that name in a number of RFCs published prior
/// to RFC 9370, which gave it the current title.
///
/// All "Additional Key Exchange (ADDKE)" entries use the same
/// "Transform Type 4 - Key Exchange Method Transform IDs"
/// registry as the "Key Exchange Method (KE)" entry.
///
/// "Sequence Numbers (SN)" transform type was originally named
/// "Extended Sequence Numbers (ESN)" and was referenced by
/// that name in a number of RFCs published before RFC 9370.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum TransformType {
    EncryptionAlgorithm = 1,
    PseudoRandomFunction = 2,
    IntegrityAlgorithm = 3,
    KeyExchangeMethod = 4,
    SequenceNumber = 5,
    AdditionalKeyExchange1 = 6,
    AdditionalKeyExchange2 = 7,
    AdditionalKeyExchange3 = 8,
    AdditionalKeyExchange4 = 9,
    AdditionalKeyExchange5 = 10,
    AdditionalKeyExchange6 = 11,
    AdditionalKeyExchange7 = 12,
    KeyWrapAlgorithm = 13,
    GroupControllerAuthenticationMethod = 14,
}

impl TryFrom<u8> for TransformType {
    type Error = UnparseableParameter;

    /// Determine the [TransformType] from an u8 value as used in the network packet structure
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(TransformType::EncryptionAlgorithm),
            2 => Ok(TransformType::PseudoRandomFunction),
            3 => Ok(TransformType::IntegrityAlgorithm),
            4 => Ok(TransformType::KeyExchangeMethod),
            5 => Ok(TransformType::SequenceNumber),
            6 => Ok(TransformType::AdditionalKeyExchange1),
            7 => Ok(TransformType::AdditionalKeyExchange2),
            8 => Ok(TransformType::AdditionalKeyExchange3),
            9 => Ok(TransformType::AdditionalKeyExchange4),
            10 => Ok(TransformType::AdditionalKeyExchange5),
            11 => Ok(TransformType::AdditionalKeyExchange6),
            12 => Ok(TransformType::AdditionalKeyExchange7),
            13 => Ok(TransformType::KeyWrapAlgorithm),
            14 => Ok(TransformType::GroupControllerAuthenticationMethod),
            15..=240 => Err(UnparseableParameter::Unassigned),
            241..=255 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

impl From<&Transform> for TransformType {
    fn from(value: &Transform) -> Self {
        match value {
            Transform::Encryption(_, _) => TransformType::EncryptionAlgorithm,
            Transform::PseudoRandomFunction(_) => TransformType::PseudoRandomFunction,
            Transform::Integrity(_) => TransformType::IntegrityAlgorithm,
            Transform::KeyExchange(_) => TransformType::KeyExchangeMethod,
            Transform::SequenceNumber(_) => TransformType::SequenceNumber,
        }
    }
}

/// Values for attribute types used to describe extra data for any transformation
///
/// Values 0-13 and 15-17 are reserved, 19-16383 are unassigned and
/// 16384-32767 reserved for private use.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)] // Base
#[derive(strum::EnumIter, strum::Display)] // Enumerate over variants + display implementation
#[derive(Serialize, Deserialize)] // Serialization
#[repr(u16)]
#[allow(missing_docs)]
pub enum AttributeType {
    /// Definition for the key length of variable-length encryption algorithms like AES-CBC;
    /// requires TV (type/value) format for the attribute payload packet
    KeyLength = 14,
    /// Definition for the signature algorithm used in Group Controller authentication;
    /// defined in draft-ietf-ipsecme-g-ikev2-22 and therefore not implemented in this project;
    /// requires TLV (type/length/value) format for the attribute payload packet
    SignatureAlgorithm = 18,
}

impl TryFrom<u16> for AttributeType {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0..=13 => Err(UnparseableParameter::Reserved),
            14 => Ok(AttributeType::KeyLength),
            15..=17 => Err(UnparseableParameter::Reserved),
            18 => Ok(AttributeType::SignatureAlgorithm),
            19..=16383 => Err(UnparseableParameter::Reserved),
            16384..=32767 => Err(UnparseableParameter::Reserved),
            32768..=65535 => Err(UnparseableParameter::OutOfRange),
        }
    }
}

/// Values for valid encryption algorithm transformations
///
/// Values 0, 10 and 22 are reserved, 17 and 36-1023 are unassigned
/// and 1024-65535 are reserved for private use. See also [UnparseableParameter].
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)] // Base
#[derive(strum::EnumIter, strum::Display)] // Enumerate over variants + display implementation
#[derive(Serialize, Deserialize)] // Serialization
#[repr(u16)]
#[allow(missing_docs)]
pub enum EncryptionAlgorithm {
    DesIv64 = 1, // deprecated
    Des = 2,     // deprecated
    TripleDes = 3,
    Rc5 = 4,        // deprecated
    Idea = 5,       // deprecated
    Cast = 6,       // deprecated
    Blowfish = 7,   // deprecated
    TripleIdea = 8, // deprecated
    DesIv32 = 9,    // deprecated
    Null = 11,      // not allowed
    AesCbc = 12,
    AesCtr = 13,
    AesCcm8 = 14,
    AesCcm12 = 15,
    AesCcm16 = 16,
    AesGcm8 = 18,
    AesGcm12 = 19,
    AesGcm16 = 20,
    NullAuthAesGmac = 21, // not allowed
    CamelliaCbc = 23,
    CamelliaCtr = 24,
    CamelliaCcm8 = 25,
    CamelliaCcm12 = 26,
    CamelliaCcm16 = 27,
    Chacha20Poly1305 = 28,
    AesCcm8IIV = 29,          // not allowed
    AesGcm16IIV = 30,         // not allowed
    Chacha20Poly1305IIV = 31, // not allowed
    KuznyechikMgmKTree = 32,
    MagmaMgmKTree = 33,
    KuznyechikMgmMacKTree = 34, // not allowed
    MagmaMgmMacKTree = 35,      // not allowed
}

impl TryFrom<u16> for EncryptionAlgorithm {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(EncryptionAlgorithm::DesIv64),
            2 => Ok(EncryptionAlgorithm::Des),
            3 => Ok(EncryptionAlgorithm::TripleDes),
            4 => Ok(EncryptionAlgorithm::Rc5),
            5 => Ok(EncryptionAlgorithm::Idea),
            6 => Ok(EncryptionAlgorithm::Cast),
            7 => Ok(EncryptionAlgorithm::Blowfish),
            8 => Ok(EncryptionAlgorithm::TripleIdea),
            9 => Ok(EncryptionAlgorithm::DesIv32),
            10 => Err(UnparseableParameter::Reserved),
            11 => Ok(EncryptionAlgorithm::Null),
            12 => Ok(EncryptionAlgorithm::AesCbc),
            13 => Ok(EncryptionAlgorithm::AesCtr),
            14 => Ok(EncryptionAlgorithm::AesCcm8),
            15 => Ok(EncryptionAlgorithm::AesCcm12),
            16 => Ok(EncryptionAlgorithm::AesCcm16),
            17 => Err(UnparseableParameter::Unassigned),
            18 => Ok(EncryptionAlgorithm::AesGcm8),
            19 => Ok(EncryptionAlgorithm::AesGcm12),
            20 => Ok(EncryptionAlgorithm::AesGcm16),
            21 => Ok(EncryptionAlgorithm::NullAuthAesGmac),
            22 => Err(UnparseableParameter::Reserved),
            23 => Ok(EncryptionAlgorithm::CamelliaCbc),
            24 => Ok(EncryptionAlgorithm::CamelliaCtr),
            25 => Ok(EncryptionAlgorithm::CamelliaCcm8),
            26 => Ok(EncryptionAlgorithm::CamelliaCcm12),
            27 => Ok(EncryptionAlgorithm::CamelliaCcm16),
            28 => Ok(EncryptionAlgorithm::Chacha20Poly1305),
            29 => Ok(EncryptionAlgorithm::AesCcm8IIV),
            30 => Ok(EncryptionAlgorithm::AesGcm16IIV),
            31 => Ok(EncryptionAlgorithm::Chacha20Poly1305IIV),
            32 => Ok(EncryptionAlgorithm::KuznyechikMgmKTree),
            33 => Ok(EncryptionAlgorithm::MagmaMgmKTree),
            34 => Ok(EncryptionAlgorithm::KuznyechikMgmMacKTree),
            35 => Ok(EncryptionAlgorithm::MagmaMgmMacKTree),
            36..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for valid pseudorandom functions used in transformations
///
/// To find out requirement levels for PRFs for IKEv2, see RFC 8247.
/// Values 0 is reserved, 10-1023 are unassigned and 1024-65535 reserved for private use.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)] // Base
#[derive(strum::EnumIter, strum::Display)] // Enumerate over variants + display implementation
#[derive(Serialize, Deserialize)] // Serialization
#[repr(u16)]
#[allow(missing_docs)]
pub enum PseudorandomFunction {
    HmacMd5 = 1, // deprecated
    HmacSha1 = 2,
    HmacTiger = 3, // deprecated
    Aes128Xcbc = 4,
    HmacSha2_256 = 5,
    HmacSha2_384 = 6,
    HmacSha2_512 = 7,
    Aes128Cmac = 8,
    HmacStreebog512 = 9,
}

impl TryFrom<u16> for PseudorandomFunction {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(PseudorandomFunction::HmacMd5),
            2 => Ok(PseudorandomFunction::HmacSha1),
            3 => Ok(PseudorandomFunction::HmacTiger),
            4 => Ok(PseudorandomFunction::Aes128Xcbc),
            5 => Ok(PseudorandomFunction::HmacSha2_256),
            6 => Ok(PseudorandomFunction::HmacSha2_384),
            7 => Ok(PseudorandomFunction::HmacSha2_512),
            8 => Ok(PseudorandomFunction::Aes128Cmac),
            9 => Ok(PseudorandomFunction::HmacStreebog512),
            10..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for valid integrity algorithms used in transformations
///
/// To find out requirement levels for encryption algorithms for
/// ESP/AH, see RFC 8221. For IKEv2, see RFC 8247.
/// Values 15-1023 are unassigned and 1024-65535 reserved for private use.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)] // Base
#[derive(strum::EnumIter, strum::Display)] // Enumerate over variants + display implementation
#[derive(Serialize, Deserialize)] // Serialization
#[repr(u16)]
#[allow(missing_docs)]
pub enum IntegrityAlgorithm {
    None = 0,
    HmacMd5_96 = 1, // deprecated
    HmacSha1_96 = 2,
    DesMac = 3,  // deprecated
    KpdkMd5 = 4, // deprecated
    AesXcbc96 = 5,
    HmacMd5_128 = 6,  // deprecated
    HmacSha1_160 = 7, // deprecated
    AesCmac96 = 8,
    Aes128Gmac = 9,
    Aes192Gmac = 10,
    Aes256Gmac = 11,
    HmacSha2_256_128 = 12,
    HmacSha2_384_192 = 13,
    HmacSha2_512_256 = 14,
}

impl TryFrom<u16> for IntegrityAlgorithm {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IntegrityAlgorithm::None),
            1 => Ok(IntegrityAlgorithm::HmacMd5_96),
            2 => Ok(IntegrityAlgorithm::HmacSha1_96),
            3 => Ok(IntegrityAlgorithm::DesMac),
            4 => Ok(IntegrityAlgorithm::KpdkMd5),
            5 => Ok(IntegrityAlgorithm::AesXcbc96),
            6 => Ok(IntegrityAlgorithm::HmacMd5_128),
            7 => Ok(IntegrityAlgorithm::HmacSha1_160),
            8 => Ok(IntegrityAlgorithm::AesCmac96),
            9 => Ok(IntegrityAlgorithm::Aes128Gmac),
            10 => Ok(IntegrityAlgorithm::Aes192Gmac),
            11 => Ok(IntegrityAlgorithm::Aes256Gmac),
            12 => Ok(IntegrityAlgorithm::HmacSha2_256_128),
            13 => Ok(IntegrityAlgorithm::HmacSha2_384_192),
            14 => Ok(IntegrityAlgorithm::HmacSha2_512_256),
            15..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for valid key exchange methods used in transformations
///
/// This registry was originally named "Transform Type 4 -
/// Diffie-Hellman Group Transform IDs" and was referenced
/// using that name in a number of RFCs published prior to
/// RFC 9370, which gave it its current title.
///
/// This registry is used by the "Key Exchange Method (KE)"
/// transform type and by all "Additional Key Exchange (ADDKE)"
/// transform types. To find out requirement levels for key
/// exchange methods for IKEv2, see RFC 8247.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)] // Base
#[derive(strum::EnumIter, strum::Display)] // Enumerate over variants + display implementation
#[derive(Serialize, Deserialize)] // Serialization
#[repr(u16)]
#[allow(missing_docs)]
pub enum KeyExchangeMethod {
    None = 0,
    ModP768 = 1, // deprecated
    ModP1024 = 2,
    ModP1536 = 5,
    ModP2048 = 14,
    ModP3072 = 15,
    ModP4096 = 16,
    ModP6144 = 17,
    ModP8192 = 18,
    EcpGroup256 = 19,
    EcpGroup384 = 20,
    EcpGroup521 = 21,
    ModP1024with160Prime = 22, // deprecated
    ModP2048with224Prime = 23,
    ModP2048with256Prime = 24,
    EcpGroup192 = 25,
    EcpGroup224 = 26,
    BrainPoolP224 = 27,
    BrainPoolP256 = 28,
    BrainPoolP384 = 29,
    BrainPoolP512 = 30,
    Curve25519 = 31,
    Curve448 = 32,
    Gost310_256 = 33,
    Gost310_512 = 34,
    MlKem512 = 35,
    MlKem768 = 36,
    MlKem1024 = 37,
}

impl TryFrom<u16> for KeyExchangeMethod {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyExchangeMethod::None),
            1 => Ok(KeyExchangeMethod::ModP768),
            2 => Ok(KeyExchangeMethod::ModP1024),
            3..=4 => Err(UnparseableParameter::Reserved),
            5 => Ok(KeyExchangeMethod::ModP1536),
            6..=13 => Err(UnparseableParameter::Unassigned),
            14 => Ok(KeyExchangeMethod::ModP2048),
            15 => Ok(KeyExchangeMethod::ModP3072),
            16 => Ok(KeyExchangeMethod::ModP4096),
            17 => Ok(KeyExchangeMethod::ModP6144),
            18 => Ok(KeyExchangeMethod::ModP8192),
            19 => Ok(KeyExchangeMethod::EcpGroup256),
            20 => Ok(KeyExchangeMethod::EcpGroup384),
            21 => Ok(KeyExchangeMethod::EcpGroup521),
            22 => Ok(KeyExchangeMethod::ModP1024with160Prime),
            23 => Ok(KeyExchangeMethod::ModP2048with224Prime),
            24 => Ok(KeyExchangeMethod::ModP2048with256Prime),
            25 => Ok(KeyExchangeMethod::EcpGroup192),
            26 => Ok(KeyExchangeMethod::EcpGroup224),
            27 => Ok(KeyExchangeMethod::BrainPoolP224),
            28 => Ok(KeyExchangeMethod::BrainPoolP256),
            29 => Ok(KeyExchangeMethod::BrainPoolP384),
            30 => Ok(KeyExchangeMethod::BrainPoolP512),
            31 => Ok(KeyExchangeMethod::Curve25519),
            32 => Ok(KeyExchangeMethod::Curve448),
            33 => Ok(KeyExchangeMethod::Gost310_256),
            34 => Ok(KeyExchangeMethod::Gost310_512),
            35 => Ok(KeyExchangeMethod::MlKem512),
            36 => Ok(KeyExchangeMethod::MlKem768),
            37 => Ok(KeyExchangeMethod::MlKem1024),
            38..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for sequence number types
///
/// The default is likely to be [SequenceNumberType::Sequential32bit],
/// as it was originally called "No Extended Sequence Numbers".
/// Values 3-1023 are unassigned and 1024-65535 are reserved for private use.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)] // Base
#[derive(strum::EnumIter, strum::Display)] // Enumerate over variants + display implementation
#[derive(Serialize, Deserialize)] // Serialization
#[repr(u16)]
#[allow(missing_docs)]
pub enum SequenceNumberType {
    Sequential32bit = 0,
    PartiallyTransmitted64bit = 1,
    Unspecified32bit = 2, // not used, since defined only in draft-ietf-ipsecme-g-ikev2-22
}

impl TryFrom<u16> for SequenceNumberType {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SequenceNumberType::Sequential32bit),
            1 => Ok(SequenceNumberType::PartiallyTransmitted64bit),
            2 => Ok(SequenceNumberType::Unspecified32bit),
            3..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Indicator for the encoding of certificates and related data
///
/// Values 0 and 5 are reserved, 16-200 are unassigned and 201-255 are reserved for private use.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum CertificateEncoding {
    PKCS7WrappedX509Certificate = 1,
    PGPCertificate = 2,
    DNSSignedKey = 3,
    X509CertificateSignature = 4,
    KerberosTokens = 6,
    CertificateRevocationList = 7,
    AuthorityRevocationList = 8,
    SPKICertificate = 9,
    X509CertificateAttribute = 10,
    RawRSAKey = 11, // deprecated
    HashUrlX509Certificate = 12,
    HashUrlX509Bundle = 13,
    OCSPContent = 14,
    RawPublicKey = 15,
}

impl TryFrom<u8> for CertificateEncoding {
    type Error = UnparseableParameter;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(CertificateEncoding::PKCS7WrappedX509Certificate),
            2 => Ok(CertificateEncoding::PGPCertificate),
            3 => Ok(CertificateEncoding::DNSSignedKey),
            4 => Ok(CertificateEncoding::X509CertificateSignature),
            5 => Err(UnparseableParameter::Reserved),
            6 => Ok(CertificateEncoding::KerberosTokens),
            7 => Ok(CertificateEncoding::CertificateRevocationList),
            8 => Ok(CertificateEncoding::AuthorityRevocationList),
            9 => Ok(CertificateEncoding::SPKICertificate),
            10 => Ok(CertificateEncoding::X509CertificateAttribute),
            11 => Ok(CertificateEncoding::RawRSAKey),
            12 => Ok(CertificateEncoding::HashUrlX509Certificate),
            13 => Ok(CertificateEncoding::HashUrlX509Bundle),
            14 => Ok(CertificateEncoding::OCSPContent),
            15 => Ok(CertificateEncoding::RawPublicKey),
            16..=200 => Err(UnparseableParameter::Unassigned),
            201..=255 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Type of authentication method being used
///
/// Value 0 is reserved, values 4-8 and 15-200 are unassigned and
/// values 201-255 are reserved for private use.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum AuthenticationMethod {
    RSADigitalSignature = 1,
    SharedKeyMessageIntegrityCode = 2,
    DSSDigitalSignature = 3,
    ECDSAWithSHA256 = 9,  // with P-256 curve
    ECDSAWithSHA384 = 10, // with P-384 curve
    ECDSAWithSHA512 = 11, // with P-521 curve
    GenericSecurePassword = 12,
    NULLAuthentication = 13,
    DigitalSignature = 14,
}

impl TryFrom<u8> for AuthenticationMethod {
    type Error = UnparseableParameter;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(AuthenticationMethod::RSADigitalSignature),
            2 => Ok(AuthenticationMethod::SharedKeyMessageIntegrityCode),
            3 => Ok(AuthenticationMethod::DSSDigitalSignature),
            4..=8 => Err(UnparseableParameter::Unassigned),
            9 => Ok(AuthenticationMethod::ECDSAWithSHA256),
            10 => Ok(AuthenticationMethod::ECDSAWithSHA384),
            11 => Ok(AuthenticationMethod::ECDSAWithSHA512),
            12 => Ok(AuthenticationMethod::GenericSecurePassword),
            13 => Ok(AuthenticationMethod::NULLAuthentication),
            14 => Ok(AuthenticationMethod::DigitalSignature),
            15..=200 => Err(UnparseableParameter::Unassigned),
            201..=255 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for the notify error message types
///
/// The values 0, 2, 3, 6, 8, 10, 12, 13, 15, 16, 18-23, 25-33 are reserved.
/// Values 50-8191 are currently unassigned and 8192-65535 reserved for private use.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)] // Base
#[derive(strum::EnumIter, strum::Display)] // Enumerate over variants + display implementation
#[derive(Serialize, Deserialize)] // Serialization
#[repr(u16)]
#[allow(missing_docs)]
pub enum NotifyErrorMessage {
    UnsupportedCriticalPayload = 1,
    InvalidIkeSpi = 4,
    InvalidMajorVersion = 5,
    InvalidSyntax = 7,
    InvalidMessageId = 9,
    InvalidSpi = 11,
    NoProposalChosen = 14,
    InvalidKeyExchangePayload = 17,
    AuthenticationFailed = 24,
    SinglePairRequired = 34,
    NoAdditionalSas = 35,
    InternalAddressFailure = 36,
    FailedCpRequired = 37,
    TsUnacceptable = 38,
    InvalidSelectors = 39,
    UnacceptableAddresses = 40,
    UnexpectedNatDetected = 41,
    UseAssignedHoA = 42,
    TemporaryFailure = 43,
    ChildSaNotFound = 44,
    InvalidGroupId = 45,
    AuthorizationFailed = 46,
    StateNotFound = 47,
    TsMaxQueue = 48,
    RegistrationFailed = 49,
}

impl TryFrom<u16> for NotifyErrorMessage {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(NotifyErrorMessage::UnsupportedCriticalPayload),
            2..=3 => Err(UnparseableParameter::Reserved),
            4 => Ok(NotifyErrorMessage::InvalidIkeSpi),
            5 => Ok(NotifyErrorMessage::InvalidMajorVersion),
            6 => Err(UnparseableParameter::Reserved),
            7 => Ok(NotifyErrorMessage::InvalidSyntax),
            8 => Err(UnparseableParameter::Reserved),
            9 => Ok(NotifyErrorMessage::InvalidMessageId),
            10 => Err(UnparseableParameter::Reserved),
            11 => Ok(NotifyErrorMessage::InvalidSpi),
            12..=13 => Err(UnparseableParameter::Reserved),
            14 => Ok(NotifyErrorMessage::NoProposalChosen),
            15..=16 => Err(UnparseableParameter::Reserved),
            17 => Ok(NotifyErrorMessage::InvalidKeyExchangePayload),
            18..=23 => Err(UnparseableParameter::Reserved),
            24 => Ok(NotifyErrorMessage::AuthenticationFailed),
            25..=33 => Err(UnparseableParameter::Reserved),
            34 => Ok(NotifyErrorMessage::SinglePairRequired),
            35 => Ok(NotifyErrorMessage::NoAdditionalSas),
            36 => Ok(NotifyErrorMessage::InternalAddressFailure),
            37 => Ok(NotifyErrorMessage::FailedCpRequired),
            38 => Ok(NotifyErrorMessage::TsUnacceptable),
            39 => Ok(NotifyErrorMessage::InvalidSelectors),
            40 => Ok(NotifyErrorMessage::UnacceptableAddresses),
            41 => Ok(NotifyErrorMessage::UnexpectedNatDetected),
            42 => Ok(NotifyErrorMessage::UseAssignedHoA),
            43 => Ok(NotifyErrorMessage::TemporaryFailure),
            44 => Ok(NotifyErrorMessage::ChildSaNotFound),
            45 => Ok(NotifyErrorMessage::InvalidGroupId),
            46 => Ok(NotifyErrorMessage::AuthorizationFailed),
            47 => Ok(NotifyErrorMessage::StateNotFound),
            48 => Ok(NotifyErrorMessage::TsMaxQueue),
            49 => Ok(NotifyErrorMessage::RegistrationFailed),
            50..=8191 => Err(UnparseableParameter::Unassigned),
            8192..=16383 => Err(UnparseableParameter::PrivateUse),
            16384..=65535 => Err(UnparseableParameter::OutOfRange),
        }
    }
}

/// Values for the security protocol identifiers
///
/// These are used in a proposal to specify the type of protocol to use
/// to negotiate the Security Association.
/// Values 7-200 are unassigned and 201-255 reserved for private use.
///
/// In this project, only [SecurityProtocol::InternetKeyExchange] is relevant.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)] // Base
#[derive(strum::EnumIter, strum::Display)] // Enumerate over variants + display implementation
#[derive(Serialize, Deserialize)] // Serialization
#[repr(u8)]
#[allow(missing_docs)]
pub enum SecurityProtocol {
    InternetKeyExchange = 1,
    AuthenticationHeader = 2,
    EncapsulatingSecurityPayload = 3,
    FcEncapsulatingSecurityPayloadHeader = 4,
    FcCtAuthentication = 5,
    GroupIKEUpdate = 6,
}

/// Values for the hash algorithm identifier
///
/// Values 0 are reserved, 8-1023 unassigned and 1024-65535 reserved for private use.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)] // Base
#[derive(strum::EnumIter, strum::Display)] // Enumerate over variants + display implementation
#[derive(Serialize, Deserialize)] // Serialization
#[repr(u16)]
#[allow(missing_docs)]
pub enum HashAlgorithm {
    Sha1 = 1,
    Sha2_256 = 2,
    Sha2_384 = 3,
    Sha2_512 = 4,
    Identity = 5,
    Streebog256 = 6,
    Streebog512 = 7,
}

impl TryFrom<u16> for HashAlgorithm {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(HashAlgorithm::Sha1),
            2 => Ok(HashAlgorithm::Sha2_256),
            3 => Ok(HashAlgorithm::Sha2_384),
            4 => Ok(HashAlgorithm::Sha2_512),
            5 => Ok(HashAlgorithm::Identity),
            6 => Ok(HashAlgorithm::Streebog256),
            7 => Ok(HashAlgorithm::Streebog512),
            8..=1023 => Err(UnparseableParameter::Unassigned),
            1024..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}

/// Values for the notify message status types
///
/// These are used to mark special notifications to the other peer(s) of
/// an IKE conversation. Notably, they do not indicate failures per-se,
/// unlike [NotifyErrorMessage].
///
/// Values 0-16383 are out of range, 16447-40959 currently unassigned and
/// 40960-65535 reserved for private use.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Copy)] // Base
#[derive(strum::EnumIter, strum::Display)] // Enumerate over variants + display implementation
#[derive(Serialize, Deserialize)] // Serialization
#[repr(u16)]
#[allow(missing_docs)]
pub enum NotifyStatusMessage {
    InitialContact = 16384,
    SetWindowSize = 16385,
    AdditionalTsPossible = 16386,
    IpCompSupported = 16387,
    NatDetectionSourceIp = 16388,
    NatDetectionDestinationIp = 16389,
    Cookie = 16390,
    UseTransportMode = 16391,
    HttpCertLookupSupported = 16392,
    RekeySa = 16393,
    EspTfcPaddingNotSupported = 16394,
    NonFirstFragmentsAlso = 16395,
    MobIkeSupported = 16396,
    AdditionalIp4Address = 16397,
    AdditionalIp6Address = 16398,
    NoAdditionalAddresses = 16399,
    UpdateSaAddresses = 16400,
    Cookie2 = 16401,
    NoNatsAllowed = 16402,
    AuthLifetime = 16403,
    MultipleAuthSupported = 16404,
    AnotherAuthFollows = 16405,
    RedirectSupported = 16406,
    Redirect = 16407,
    RedirectedFrom = 16408,
    TicketLtOpaque = 16409,
    TicketRequest = 16410,
    TicketAck = 16411,
    TicketNack = 16412,
    TicketOpaque = 16413,
    LinkId = 16414,
    UseWespMode = 16415,
    RohcSupported = 16416,
    EapOnlyAuthentication = 16417,
    ChildlessIkev2Supported = 16418,
    QuickCrashDetection = 16419,
    Ikev2MessageIdSyncSupported = 16420,
    IpsecReplayCounterSyncSupported = 16421,
    Ikev2MessageIdSync = 16422,
    IpsecReplayCounterSync = 16423,
    SecurePasswordMethods = 16424,
    PskPersist = 16425,
    PskConfirm = 16426,
    ErxSupported = 16427,
    IfomCapability = 16428,
    GroupSender = 16429,
    Ikev2FragmentationSupported = 16430,
    SignatureHashAlgorithms = 16431,
    CloneIkeSaSupported = 16432,
    CloneIkeSa = 16433,
    Puzzle = 16434,
    UsePpk = 16435,
    PpkIdentity = 16436,
    NoPpkAuth = 16437,
    IntermediateExchangeSupported = 16438,
    Ip4Allowed = 16439,
    Ip6Allowed = 16440,
    AdditionalKeyExchange = 16441,
    UseAgfrag = 16442,
    SupportedAuthMethods = 16443,
    SaResourceInfo = 16444,
    UsePpkInt = 16445,
    PpkIdentityKey = 16446,
}

impl TryFrom<u16> for NotifyStatusMessage {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0..=16383 => Err(UnparseableParameter::OutOfRange),
            16384 => Ok(NotifyStatusMessage::InitialContact),
            16385 => Ok(NotifyStatusMessage::SetWindowSize),
            16386 => Ok(NotifyStatusMessage::AdditionalTsPossible),
            16387 => Ok(NotifyStatusMessage::IpCompSupported),
            16388 => Ok(NotifyStatusMessage::NatDetectionSourceIp),
            16389 => Ok(NotifyStatusMessage::NatDetectionDestinationIp),
            16390 => Ok(NotifyStatusMessage::Cookie),
            16391 => Ok(NotifyStatusMessage::UseTransportMode),
            16392 => Ok(NotifyStatusMessage::HttpCertLookupSupported),
            16393 => Ok(NotifyStatusMessage::RekeySa),
            16394 => Ok(NotifyStatusMessage::EspTfcPaddingNotSupported),
            16395 => Ok(NotifyStatusMessage::NonFirstFragmentsAlso),
            16396 => Ok(NotifyStatusMessage::MobIkeSupported),
            16397 => Ok(NotifyStatusMessage::AdditionalIp4Address),
            16398 => Ok(NotifyStatusMessage::AdditionalIp6Address),
            16399 => Ok(NotifyStatusMessage::NoAdditionalAddresses),
            16400 => Ok(NotifyStatusMessage::UpdateSaAddresses),
            16401 => Ok(NotifyStatusMessage::Cookie2),
            16402 => Ok(NotifyStatusMessage::NoNatsAllowed),
            16403 => Ok(NotifyStatusMessage::AuthLifetime),
            16404 => Ok(NotifyStatusMessage::MultipleAuthSupported),
            16405 => Ok(NotifyStatusMessage::AnotherAuthFollows),
            16406 => Ok(NotifyStatusMessage::RedirectSupported),
            16407 => Ok(NotifyStatusMessage::Redirect),
            16408 => Ok(NotifyStatusMessage::RedirectedFrom),
            16409 => Ok(NotifyStatusMessage::TicketLtOpaque),
            16410 => Ok(NotifyStatusMessage::TicketRequest),
            16411 => Ok(NotifyStatusMessage::TicketAck),
            16412 => Ok(NotifyStatusMessage::TicketNack),
            16413 => Ok(NotifyStatusMessage::TicketOpaque),
            16414 => Ok(NotifyStatusMessage::LinkId),
            16415 => Ok(NotifyStatusMessage::UseWespMode),
            16416 => Ok(NotifyStatusMessage::RohcSupported),
            16417 => Ok(NotifyStatusMessage::EapOnlyAuthentication),
            16418 => Ok(NotifyStatusMessage::ChildlessIkev2Supported),
            16419 => Ok(NotifyStatusMessage::QuickCrashDetection),
            16420 => Ok(NotifyStatusMessage::Ikev2MessageIdSyncSupported),
            16421 => Ok(NotifyStatusMessage::IpsecReplayCounterSyncSupported),
            16422 => Ok(NotifyStatusMessage::Ikev2MessageIdSync),
            16423 => Ok(NotifyStatusMessage::IpsecReplayCounterSync),
            16424 => Ok(NotifyStatusMessage::SecurePasswordMethods),
            16425 => Ok(NotifyStatusMessage::PskPersist),
            16426 => Ok(NotifyStatusMessage::PskConfirm),
            16427 => Ok(NotifyStatusMessage::ErxSupported),
            16428 => Ok(NotifyStatusMessage::IfomCapability),
            16429 => Ok(NotifyStatusMessage::GroupSender),
            16430 => Ok(NotifyStatusMessage::Ikev2FragmentationSupported),
            16431 => Ok(NotifyStatusMessage::SignatureHashAlgorithms),
            16432 => Ok(NotifyStatusMessage::CloneIkeSaSupported),
            16433 => Ok(NotifyStatusMessage::CloneIkeSa),
            16434 => Ok(NotifyStatusMessage::Puzzle),
            16435 => Ok(NotifyStatusMessage::UsePpk),
            16436 => Ok(NotifyStatusMessage::PpkIdentity),
            16437 => Ok(NotifyStatusMessage::NoPpkAuth),
            16438 => Ok(NotifyStatusMessage::IntermediateExchangeSupported),
            16439 => Ok(NotifyStatusMessage::Ip4Allowed),
            16440 => Ok(NotifyStatusMessage::Ip6Allowed),
            16441 => Ok(NotifyStatusMessage::AdditionalKeyExchange),
            16442 => Ok(NotifyStatusMessage::UseAgfrag),
            16443 => Ok(NotifyStatusMessage::SupportedAuthMethods),
            16444 => Ok(NotifyStatusMessage::SaResourceInfo),
            16445 => Ok(NotifyStatusMessage::UsePpkInt),
            16446 => Ok(NotifyStatusMessage::PpkIdentityKey),
            16447..=40959 => Err(UnparseableParameter::Unassigned),
            40960..=65535 => Err(UnparseableParameter::PrivateUse),
        }
    }
}
