// SPDX-License-Identifier: Apache-2.0
//
// QoreSeal key pairs: an ML-KEM-1024 key pair and an X25519 key pair derived
// from one 32-byte seed (spec section 4).

use std::fmt;

use fips203::ml_kem_1024;
use fips203::traits::{KeyGen, SerDes};

use crate::constants::{
    KEYS_LABEL_MLKEM, KEYS_LABEL_X25519, ML_KEM_1024_PUBLIC_KEY_LENGTH,
    ML_KEM_1024_SECRET_KEY_LENGTH, MNEMONIC_LABEL, SEED_LENGTH, X25519_KEY_LENGTH,
};
use crate::errors::{Error, Result};
use crate::kem::x25519_public_key;
use crate::util::{hkdf_sha256, is_all_zero, random_bytes, require_key_len, require_len};

/// A recipient's keys. Keep `seed` (or the mnemonic it came from) secret and backed up.
#[derive(Clone, PartialEq, Eq)]
pub struct SealKeyPair {
    /// 32-byte seed both key pairs derive from.
    pub seed: Vec<u8>,
    /// ML-KEM-1024 encapsulation key (1568 bytes): the key registered on chain.
    pub mlkem_public_key: Vec<u8>,
    /// ML-KEM-1024 decapsulation key (3168 bytes).
    pub mlkem_secret_key: Vec<u8>,
    /// X25519 public key (32 bytes), published in a recipient card.
    pub x25519_public_key: Vec<u8>,
    /// X25519 secret key (32 bytes).
    pub x25519_secret_key: Vec<u8>,
}

impl fmt::Debug for SealKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealKeyPair")
            .field(
                "mlkem_public_key",
                &hex::encode(&self.mlkem_public_key[..8]),
            )
            .field("x25519_public_key", &hex::encode(&self.x25519_public_key))
            .finish_non_exhaustive()
    }
}

/// What a sender needs to seal to someone. `x25519_public_key` is required by the hybrid mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealRecipient {
    pub mlkem_public_key: Vec<u8>,
    pub x25519_public_key: Option<Vec<u8>>,
}

impl SealKeyPair {
    /// The public half, as a recipient.
    pub fn recipient(&self) -> SealRecipient {
        SealRecipient {
            mlkem_public_key: self.mlkem_public_key.clone(),
            x25519_public_key: Some(self.x25519_public_key.clone()),
        }
    }
}

/// Derive both key pairs from a 32-byte seed.
pub fn seal_keys_from_seed(seed: &[u8]) -> Result<SealKeyPair> {
    require_len(seed, SEED_LENGTH, "seed")?;
    let mlkem_seed = hkdf_sha256(seed, &[], KEYS_LABEL_MLKEM.as_bytes(), 64);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&mlkem_seed[..32]);
    z.copy_from_slice(&mlkem_seed[32..]);
    let (ek, dk) = ml_kem_1024::KG::keygen_from_seed(d, z);
    let x25519_secret_key = hkdf_sha256(seed, &[], KEYS_LABEL_X25519.as_bytes(), 32);
    Ok(SealKeyPair {
        seed: seed.to_vec(),
        mlkem_public_key: ek.into_bytes().to_vec(),
        mlkem_secret_key: dk.into_bytes().to_vec(),
        x25519_public_key: x25519_public_key(&x25519_secret_key)?,
        x25519_secret_key,
    })
}

/// New key pairs from a fresh random seed.
pub fn generate_seal_keys() -> SealKeyPair {
    seal_keys_from_seed(&random_bytes(SEED_LENGTH)).expect("a 32-byte seed")
}

/// The 32-byte seed for `index` (0 to 2^31-1) derived from a BIP-39 mnemonic.
pub fn seal_seed_from_mnemonic(mnemonic: &str, passphrase: &str, index: u32) -> Result<Vec<u8>> {
    if index > 0x7fff_ffff {
        return Err(Error::InvalidArgument(format!(
            "index must be from 0 to 2^31-1, got {index}"
        )));
    }
    let words = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    // parse_in normalizes to NFKD before checking the words and checksum.
    let m = bip39::Mnemonic::parse_in(bip39::Language::English, words.as_str())
        .map_err(|_| Error::InvalidArgument("invalid BIP-39 mnemonic".into()))?;
    // to_seed normalizes the passphrase to NFKD.
    let bip39_seed = m.to_seed(passphrase);
    Ok(hkdf_sha256(
        &bip39_seed,
        &[],
        format!("{MNEMONIC_LABEL}{index}").as_bytes(),
        SEED_LENGTH,
    ))
}

/// Key pairs derived from a BIP-39 mnemonic. Move to the next `index` to rotate.
pub fn derive_seal_keys(mnemonic: &str, passphrase: &str, index: u32) -> Result<SealKeyPair> {
    seal_keys_from_seed(&seal_seed_from_mnemonic(mnemonic, passphrase, index)?)
}

/// The checks the chain applies to a registered key: 1568 bytes, every 12-bit
/// coefficient of t_hat below 3329 (FIPS 203 modulus check), t_hat not all zero.
pub fn validate_mlkem_public_key(public_key: &[u8]) -> Result<()> {
    require_key_len(
        public_key,
        ML_KEM_1024_PUBLIC_KEY_LENGTH,
        "ML-KEM-1024 public key",
    )?;
    let mut non_zero = false;
    for c in public_key[..1536].chunks_exact(3) {
        let c0 = u16::from(c[0]) | (u16::from(c[1] & 0x0f) << 8);
        let c1 = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
        if c0 >= 3329 || c1 >= 3329 {
            return Err(Error::InvalidKey(
                "the ML-KEM-1024 public key fails the FIPS 203 modulus check".into(),
            ));
        }
        non_zero |= c0 != 0 || c1 != 0;
    }
    if !non_zero {
        return Err(Error::InvalidKey(
            "the ML-KEM-1024 public key is degenerate (t_hat is zero)".into(),
        ));
    }
    Ok(())
}

pub fn validate_x25519_public_key(public_key: &[u8]) -> Result<()> {
    require_key_len(public_key, X25519_KEY_LENGTH, "X25519 public key")?;
    if is_all_zero(public_key) {
        return Err(Error::InvalidKey("the X25519 public key is zero".into()));
    }
    Ok(())
}

pub(crate) fn check_key_pair(keys: &SealKeyPair) -> Result<()> {
    require_key_len(
        &keys.mlkem_secret_key,
        ML_KEM_1024_SECRET_KEY_LENGTH,
        "ML-KEM-1024 secret key",
    )?;
    require_key_len(
        &keys.mlkem_public_key,
        ML_KEM_1024_PUBLIC_KEY_LENGTH,
        "ML-KEM-1024 public key",
    )?;
    require_key_len(
        &keys.x25519_secret_key,
        X25519_KEY_LENGTH,
        "X25519 secret key",
    )?;
    require_key_len(
        &keys.x25519_public_key,
        X25519_KEY_LENGTH,
        "X25519 public key",
    )
}
