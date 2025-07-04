//! IKEv2 parameters and their parsers as defined in the IANA IKEv2 list
//! found at https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml

use super::UnparseableParameter;

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
    // RFC5723
    IkeSessionResume = 38,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaAuth = 39,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaRegistration = 40,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaRekey = 41,
    // draft-ietf-ipsecme-g-ikev2-22
    GsaInbandRekey = 42,
    // RFC9242
    IkeIntermediate = 43,
    // RFC9370
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
    IdentificationInitiaor = 35,
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
            35 => Ok(PayloadType::IdentificationInitiaor),
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

// TODO: IKEv2 Transform Attribute Types
// TODO: Transform Type 1 - Encryption Algorithm Transform IDs
// TODO: Transform Type 2 - Pseudorandom Function Transform IDs
// TODO: Transform Type 3 - Integrity Algorithm Transform IDs
// TODO: Transform Type 4 - Key Exchange Method Transform IDs
// TODO: Transform Type 5 - Sequence Numbers Transform IDs
// TODO: Transform Type 13 - Key Wrap Algorithm Transform IDs
// TODO: Transform Type 14 - Group Controller Authentication Method Transform IDs

// TODO: IKEv2 Identification Payload ID Types

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

pub enum NotifyErrorMessageType {
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

impl TryFrom<u16> for NotifyErrorMessageType {
    type Error = UnparseableParameter;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Err(UnparseableParameter::Reserved),
            1 => Ok(NotifyErrorMessageType::UnsupportedCriticalPayload),
            2..=3 => Err(UnparseableParameter::Reserved),
            4 => Ok(NotifyErrorMessageType::InvalidIkeSpi),
            5 => Ok(NotifyErrorMessageType::InvalidMajorVersion),
            6 => Err(UnparseableParameter::Reserved),
            7 => Ok(NotifyErrorMessageType::InvalidSyntax),
            8 => Err(UnparseableParameter::Reserved),
            9 => Ok(NotifyErrorMessageType::InvalidMessageId),
            10 => Err(UnparseableParameter::Reserved),
            11 => Ok(NotifyErrorMessageType::InvalidSpi),
            12..=13 => Err(UnparseableParameter::Reserved),
            14 => Ok(NotifyErrorMessageType::NoProposalChosen),
            15..=16 => Err(UnparseableParameter::Reserved),
            17 => Ok(NotifyErrorMessageType::InvalidKeyExchangePayload),
            18..=23 => Err(UnparseableParameter::Reserved),
            24 => Ok(NotifyErrorMessageType::AuthenticationFailed),
            25..=33 => Err(UnparseableParameter::Reserved),
            34 => Ok(NotifyErrorMessageType::SinglePairRequired),
            35 => Ok(NotifyErrorMessageType::NoAdditionalSas),
            36 => Ok(NotifyErrorMessageType::InternalAddressFailure),
            37 => Ok(NotifyErrorMessageType::FailedCpRequired),
            38 => Ok(NotifyErrorMessageType::TsUnacceptable),
            39 => Ok(NotifyErrorMessageType::InvalidSelectors),
            40 => Ok(NotifyErrorMessageType::UnacceptableAddresses),
            41 => Ok(NotifyErrorMessageType::UnexpectedNatDetected),
            42 => Ok(NotifyErrorMessageType::UseAssignedHoA),
            43 => Ok(NotifyErrorMessageType::TemporaryFailure),
            44 => Ok(NotifyErrorMessageType::ChildSaNotFound),
            45 => Ok(NotifyErrorMessageType::InvalidGroupId),
            46 => Ok(NotifyErrorMessageType::AuthorizationFailed),
            47 => Ok(NotifyErrorMessageType::StateNotFound),
            48 => Ok(NotifyErrorMessageType::TsMaxQueue),
            49 => Ok(NotifyErrorMessageType::RegistrationFailed),
            50..=8191 => Err(UnparseableParameter::Unassigned),
            8192..=16383 => Err(UnparseableParameter::PrivateUse),
            16384..=65535 => Err(UnparseableParameter::OutOfRange),
        }
    }
}

// TODO: IKEv2 Notify Message Status Types

// TODO: IKEv2 Notification IPCOMP Transform IDs (Value 16387)

// TODO: IKEv2 Security Protocol Identifiers

// TODO: IKEv2 Traffic Selector Types

// TODO: IKEv2 Configuration Payload CFG Types

// TODO: IKEv2 Configuration Payload Attribute Types

// TODO: IKEv2 Gateway Identity Types

// TODO: IKEv2 Hash Algorithms
