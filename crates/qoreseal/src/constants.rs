// SPDX-License-Identifier: Apache-2.0
//
// Wire constants of QoreSeal v1 (spec/qoreseal-v1.md).

use crate::errors::{Error, Result};

/// Algorithm id of ML-KEM-1024 in the chain's KEM key registry and in envelopes.
pub const ALGORITHM_ML_KEM_1024: u8 = 2;
pub const ML_KEM_1024_PUBLIC_KEY_LENGTH: usize = 1568;
pub const ML_KEM_1024_SECRET_KEY_LENGTH: usize = 3168;
pub const ML_KEM_1024_CIPHERTEXT_LENGTH: usize = 1568;
pub const X25519_KEY_LENGTH: usize = 32;
pub const SEED_LENGTH: usize = 32;

pub const ENVELOPE_VERSION: u8 = 1;
/// `"QSEL"`.
pub const ENVELOPE_MAGIC: [u8; 4] = *b"QSEL";
pub const ENVELOPE_TEXT_PREFIX: &str = "qoreseal:";
pub const MODE_HYBRID: u8 = 0x01;
pub const MODE_MLKEM: u8 = 0x02;
pub const KDF_HKDF_SHA256: u8 = 0x01;
pub const AEAD_AES_256_GCM: u8 = 0x01;
pub const FLAG_ANONYMOUS: u8 = 0x01;
pub const FIXED_HEADER_LENGTH: usize = 28;
pub const SALT_LENGTH: usize = 16;
pub const HINT_LENGTH: usize = 16;
pub const NONCE_LENGTH: usize = 12;
pub const TAG_LENGTH: usize = 16;
pub const DATA_KEY_LENGTH: usize = 32;
pub const WRAPPED_KEY_LENGTH: usize = DATA_KEY_LENGTH + TAG_LENGTH;
pub const MAX_RECIPIENTS: usize = 1024;

/// `"qorechain-kem-v1|"`: prefix of the HKDF info of every key-encryption key.
pub const KDF_INFO_PREFIX: &str = "qorechain-kem-v1|";
pub const HYBRID_LABEL: &str = "qorechain-qoreseal-hybrid-v1";
pub const HINT_LABEL: &str = "qorechain-qoreseal-hint-v1";
pub const KEYS_LABEL_MLKEM: &str = "qorechain-qoreseal-keys-v1|ml-kem-1024";
pub const KEYS_LABEL_X25519: &str = "qorechain-qoreseal-keys-v1|x25519";
pub const MNEMONIC_LABEL: &str = "qorechain-qoreseal-mnemonic-v1|";
pub const BATCH_COMMITMENT_LABEL: &str = "qorechain-qoreseal-batch-v1";

/// `Hybrid` (default): ML-KEM-1024 plus X25519. `Mlkem`: ML-KEM-1024 only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SealMode {
    #[default]
    Hybrid,
    Mlkem,
}

impl SealMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SealMode::Hybrid => "hybrid",
            SealMode::Mlkem => "mlkem",
        }
    }

    pub(crate) fn byte(self) -> u8 {
        match self {
            SealMode::Hybrid => MODE_HYBRID,
            SealMode::Mlkem => MODE_MLKEM,
        }
    }

    /// Size of one recipient entry: 1664 bytes in hybrid mode, 1632 in mlkem mode.
    pub fn entry_length(&self) -> usize {
        match self {
            SealMode::Hybrid => 1664,
            SealMode::Mlkem => 1632,
        }
    }
}

fn charset_ok(s: &str, extra: &[u8], max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' || extra.contains(&b)
        })
}

/// `chainId` matches `^[A-Za-z0-9._-]{1,64}$`.
pub fn check_chain_id(chain_id: &str) -> Result<()> {
    if charset_ok(chain_id, &[], 64) {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "invalid chain id {chain_id:?}"
        )))
    }
}

/// `purpose` (and a batch context) matches `^[A-Za-z0-9._:/-]{1,128}$`.
pub fn check_purpose(purpose: &str) -> Result<()> {
    if charset_ok(purpose, b":/", 128) {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "invalid purpose {purpose:?}"
        )))
    }
}
