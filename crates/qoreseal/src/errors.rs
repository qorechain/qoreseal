// SPDX-License-Identifier: Apache-2.0

/// Every failure QoreSeal reports. [`Error::code`] is the stable code shared
/// by all implementations; the payload is a human-readable detail.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    InvalidKey(String),
    #[error("{0}")]
    MalformedEnvelope(String),
    #[error("{0}")]
    MalformedBatch(String),
    #[error("{0}")]
    UnsupportedVersion(String),
    #[error("{0}")]
    UnsupportedAlgorithm(String),
    #[error("{0}")]
    NotARecipient(String),
    #[error("{0}")]
    DecryptionFailed(String),
    #[error("{0}")]
    RecipientNeedsX25519(String),
    #[error("{0}")]
    CardInvalid(String),
    #[error("{0}")]
    UnknownEpoch(String),
    #[error("{0}")]
    KemKeyNotRegistered(String),
    #[error("{0}")]
    KemRegistryUnavailable(String),
    #[error("{0}")]
    NetworkUnavailable(String),
}

impl Error {
    /// The stable code, for example `NOT_A_RECIPIENT`.
    pub fn code(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "INVALID_ARGUMENT",
            Error::InvalidKey(_) => "INVALID_KEY",
            Error::MalformedEnvelope(_) => "MALFORMED_ENVELOPE",
            Error::MalformedBatch(_) => "MALFORMED_BATCH",
            Error::UnsupportedVersion(_) => "UNSUPPORTED_VERSION",
            Error::UnsupportedAlgorithm(_) => "UNSUPPORTED_ALGORITHM",
            Error::NotARecipient(_) => "NOT_A_RECIPIENT",
            Error::DecryptionFailed(_) => "DECRYPTION_FAILED",
            Error::RecipientNeedsX25519(_) => "RECIPIENT_NEEDS_X25519",
            Error::CardInvalid(_) => "CARD_INVALID",
            Error::UnknownEpoch(_) => "UNKNOWN_EPOCH",
            Error::KemKeyNotRegistered(_) => "KEM_KEY_NOT_REGISTERED",
            Error::KemRegistryUnavailable(_) => "KEM_REGISTRY_UNAVAILABLE",
            Error::NetworkUnavailable(_) => "NETWORK_UNAVAILABLE",
        }
    }

    /// The human-readable detail.
    pub fn message(&self) -> &str {
        match self {
            Error::InvalidArgument(m)
            | Error::InvalidKey(m)
            | Error::MalformedEnvelope(m)
            | Error::MalformedBatch(m)
            | Error::UnsupportedVersion(m)
            | Error::UnsupportedAlgorithm(m)
            | Error::NotARecipient(m)
            | Error::DecryptionFailed(m)
            | Error::RecipientNeedsX25519(m)
            | Error::CardInvalid(m)
            | Error::UnknownEpoch(m)
            | Error::KemKeyNotRegistered(m)
            | Error::KemRegistryUnavailable(m)
            | Error::NetworkUnavailable(m) => m,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
