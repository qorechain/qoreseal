// SPDX-License-Identifier: Apache-2.0
//
// Building blocks of an envelope entry: encapsulation, the hybrid combiner,
// the key-encryption key and the recipient hint (spec sections 3 and 5.2).

use fips203::ml_kem_1024;
use fips203::traits::{Encaps, SerDes};
use qorechain_pqc::mlkem::ml_kem_1024 as pqc_kem;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::constants::{
    check_chain_id, check_purpose, HINT_LABEL, HINT_LENGTH, HYBRID_LABEL, KDF_INFO_PREFIX,
    ML_KEM_1024_CIPHERTEXT_LENGTH, ML_KEM_1024_SECRET_KEY_LENGTH, X25519_KEY_LENGTH,
};
use crate::errors::{Error, Result};
use crate::keys::validate_mlkem_public_key;
use crate::util::{hkdf_sha256, is_all_zero, require_key_len, require_len, sha3_256};

/// `"qorechain-kem-v1|" + chain_id + "|" + purpose`, the HKDF info of every key-encryption key.
pub fn kdf_info(chain_id: &str, purpose: &str) -> Result<String> {
    check_chain_id(chain_id)?;
    check_purpose(purpose)?;
    Ok(format!("{KDF_INFO_PREFIX}{chain_id}|{purpose}"))
}

/// HKDF-SHA-256 of a shared secret into a 32-byte key bound to the chain and purpose.
pub fn derive_key(shared: &[u8], chain_id: &str, purpose: &str, salt: &[u8]) -> Result<Vec<u8>> {
    require_len(shared, 32, "shared secret")?;
    let info = kdf_info(chain_id, purpose)?;
    Ok(hkdf_sha256(shared, salt, info.as_bytes(), 32))
}

/// Result of an ML-KEM-1024 encapsulation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// ML-KEM-1024 encapsulation to a validated key.
pub fn mlkem_encapsulate(public_key: &[u8]) -> Result<Encapsulation> {
    validate_mlkem_public_key(public_key)?;
    let (ct, ss) = pqc_kem::encapsulate(public_key).map_err(|e| Error::InvalidKey(e.into()))?;
    Ok(Encapsulation {
        ciphertext: ct,
        shared_secret: ss.to_vec(),
    })
}

/// FIPS 203 ML-KEM.Encaps_internal with explicit randomness `m`. Test vectors only.
pub(crate) fn mlkem_encapsulate_derand(public_key: &[u8], m: &[u8]) -> Result<Encapsulation> {
    validate_mlkem_public_key(public_key)?;
    require_len(m, 32, "encapsulation randomness")?;
    let mut arr = [0u8; 1568];
    arr.copy_from_slice(public_key);
    let ek =
        ml_kem_1024::EncapsKey::try_from_bytes(arr).map_err(|e| Error::InvalidKey(e.into()))?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(m);
    let (ss, ct) = ek.encaps_from_seed(&seed);
    Ok(Encapsulation {
        ciphertext: ct.into_bytes().to_vec(),
        shared_secret: ss.into_bytes().to_vec(),
    })
}

pub fn mlkem_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    require_key_len(
        secret_key,
        ML_KEM_1024_SECRET_KEY_LENGTH,
        "ML-KEM-1024 secret key",
    )?;
    require_len(
        ciphertext,
        ML_KEM_1024_CIPHERTEXT_LENGTH,
        "ML-KEM-1024 ciphertext",
    )?;
    pqc_kem::decapsulate(secret_key, ciphertext)
        .map(|ss| ss.to_vec())
        .map_err(|e| Error::InvalidKey(e.into()))
}

fn arr32(b: &[u8], what: &str) -> Result<[u8; 32]> {
    require_key_len(b, X25519_KEY_LENGTH, what)?;
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    Ok(a)
}

/// X25519 public key of a secret key.
pub fn x25519_public_key(secret_key: &[u8]) -> Result<Vec<u8>> {
    let sk = StaticSecret::from(arr32(secret_key, "X25519 secret key")?);
    Ok(PublicKey::from(&sk).as_bytes().to_vec())
}

/// X25519 agreement; fails with `INVALID_KEY` on an all-zero result (low-order public key).
pub fn x25519_agree(secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let sk = StaticSecret::from(arr32(secret_key, "X25519 secret key")?);
    let pk = PublicKey::from(arr32(public_key, "X25519 public key")?);
    let ss = sk.diffie_hellman(&pk);
    if is_all_zero(ss.as_bytes()) {
        return Err(Error::InvalidKey(
            "X25519 agreement gave the zero point (low-order public key)".into(),
        ));
    }
    Ok(ss.as_bytes().to_vec())
}

/// `SHA3-256("qorechain-qoreseal-hybrid-v1" || ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519)`.
pub fn hybrid_shared_secret(
    mlkem_shared_secret: &[u8],
    x25519_shared_secret: &[u8],
    x25519_ciphertext: &[u8],
    x25519_public_key: &[u8],
) -> Result<Vec<u8>> {
    require_len(mlkem_shared_secret, 32, "ML-KEM shared secret")?;
    require_len(x25519_shared_secret, 32, "X25519 shared secret")?;
    require_len(x25519_ciphertext, 32, "X25519 ephemeral public key")?;
    require_len(x25519_public_key, 32, "X25519 public key")?;
    Ok(sha3_256(&[
        HYBRID_LABEL.as_bytes(),
        mlkem_shared_secret,
        x25519_shared_secret,
        x25519_ciphertext,
        x25519_public_key,
    ])
    .to_vec())
}

/// `SHA3-256("qorechain-qoreseal-hint-v1" || salt || mlkem_public_key)[0..16]`.
pub fn recipient_hint(salt: &[u8], mlkem_public_key: &[u8]) -> Vec<u8> {
    sha3_256(&[HINT_LABEL.as_bytes(), salt, mlkem_public_key])[..HINT_LENGTH].to_vec()
}
