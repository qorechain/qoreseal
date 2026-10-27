// SPDX-License-Identifier: Apache-2.0
//
// The QoreSeal envelope: one payload encrypted once with a random data key,
// the data key wrapped for each recipient (spec section 5).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::constants::{
    check_chain_id, check_purpose, SealMode, AEAD_AES_256_GCM, ALGORITHM_ML_KEM_1024,
    DATA_KEY_LENGTH, ENVELOPE_MAGIC, ENVELOPE_TEXT_PREFIX, ENVELOPE_VERSION, FIXED_HEADER_LENGTH,
    FLAG_ANONYMOUS, HINT_LENGTH, KDF_HKDF_SHA256, MAX_RECIPIENTS, ML_KEM_1024_CIPHERTEXT_LENGTH,
    MODE_HYBRID, MODE_MLKEM, NONCE_LENGTH, SALT_LENGTH, TAG_LENGTH, WRAPPED_KEY_LENGTH,
};
use crate::errors::{Error, Result};
use crate::kem::{
    derive_key, hybrid_shared_secret, mlkem_decapsulate, mlkem_encapsulate,
    mlkem_encapsulate_derand, recipient_hint, x25519_agree, x25519_public_key,
};
use crate::keys::{
    check_key_pair, validate_mlkem_public_key, validate_x25519_public_key, SealKeyPair,
    SealRecipient,
};
use crate::util::{ct_eq, Entropy, SystemEntropy};

/// Input of [`seal`].
#[derive(Clone, Copy, Debug)]
pub struct SealArgs<'a> {
    pub chain_id: &'a str,
    /// What the data is for in your application, e.g. `chat` or `invoice` (spec section 3).
    pub purpose: &'a str,
    pub recipients: &'a [SealRecipient],
    pub plaintext: &'a [u8],
    /// Extra data authenticated but not encrypted; the recipient must pass the same bytes.
    pub aad: &'a [u8],
    /// Default hybrid. Mlkem must be chosen explicitly.
    pub mode: SealMode,
    /// Zero hints: recipients try every entry, and the envelope does not point at them.
    pub anonymous: bool,
}

impl<'a> SealArgs<'a> {
    /// Defaults: hybrid mode, no AAD, hints on.
    pub fn new(
        chain_id: &'a str,
        purpose: &'a str,
        recipients: &'a [SealRecipient],
        plaintext: &'a [u8],
    ) -> Self {
        Self {
            chain_id,
            purpose,
            recipients,
            plaintext,
            aad: &[],
            mode: SealMode::Hybrid,
            anonymous: false,
        }
    }
}

/// One recipient entry of an envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeEntry {
    pub hint: Vec<u8>,
    pub mlkem_ciphertext: Vec<u8>,
    /// X25519 ephemeral public key (hybrid mode only).
    pub x25519_ciphertext: Option<Vec<u8>>,
    pub wrapped_key: Vec<u8>,
}

/// The parts of an envelope, as read from its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedEnvelope {
    pub version: u8,
    pub mode: SealMode,
    pub anonymous: bool,
    pub salt: Vec<u8>,
    pub entries: Vec<EnvelopeEntry>,
    pub nonce: Vec<u8>,
    /// Payload ciphertext with its tag.
    pub ciphertext: Vec<u8>,
    /// Everything before the ciphertext: the payload's AAD starts with it.
    pub header: Vec<u8>,
}

/// Size in bytes of an envelope: `56 + n * W + plaintext_length`.
pub fn envelope_size(mode: SealMode, recipients: usize, plaintext_length: usize) -> usize {
    FIXED_HEADER_LENGTH
        + recipients * mode.entry_length()
        + NONCE_LENGTH
        + plaintext_length
        + TAG_LENGTH
}

fn fixed_header(mode: SealMode, anonymous: bool, salt: &[u8], n: usize) -> Vec<u8> {
    let mut h = Vec::with_capacity(FIXED_HEADER_LENGTH);
    h.extend_from_slice(&ENVELOPE_MAGIC);
    h.extend_from_slice(&[
        ENVELOPE_VERSION,
        mode.byte(),
        ALGORITHM_ML_KEM_1024,
        KDF_HKDF_SHA256,
        AEAD_AES_256_GCM,
        if anonymous { FLAG_ANONYMOUS } else { 0 },
    ]);
    h.extend_from_slice(salt);
    h.extend_from_slice(&(n as u16).to_be_bytes());
    h
}

fn entry_aad(fixed: &[u8], hint: &[u8], ct_k: &[u8], ct_x: Option<&[u8]>) -> Vec<u8> {
    let mut a = Vec::with_capacity(fixed.len() + hint.len() + ct_k.len() + 32);
    a.extend_from_slice(fixed);
    a.extend_from_slice(hint);
    a.extend_from_slice(ct_k);
    if let Some(x) = ct_x {
        a.extend_from_slice(x);
    }
    a
}

pub(crate) fn aead_seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-256-GCM encryption")
}

pub(crate) fn aead_open(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

const ZERO_NONCE: [u8; NONCE_LENGTH] = [0u8; NONCE_LENGTH];

pub(crate) fn seal_with(args: &SealArgs<'_>, entropy: &mut dyn Entropy) -> Result<Vec<u8>> {
    check_chain_id(args.chain_id)?;
    check_purpose(args.purpose)?;
    let n = args.recipients.len();
    if n == 0 || n > MAX_RECIPIENTS {
        return Err(Error::InvalidArgument(format!(
            "between 1 and {MAX_RECIPIENTS} recipients are required"
        )));
    }
    for r in args.recipients {
        validate_mlkem_public_key(&r.mlkem_public_key)?;
        if args.mode == SealMode::Hybrid {
            let Some(x) = &r.x25519_public_key else {
                return Err(Error::RecipientNeedsX25519(
                    "hybrid mode needs each recipient's X25519 key (from a recipient card); choose SealMode::Mlkem explicitly to use the on-chain key alone".into(),
                ));
            };
            validate_x25519_public_key(x)?;
        }
    }
    let salt = entropy.take(SALT_LENGTH)?;
    let dek = entropy.take(DATA_KEY_LENGTH)?;
    let fixed = fixed_header(args.mode, args.anonymous, &salt, n);
    let mut out = Vec::with_capacity(envelope_size(args.mode, n, args.plaintext.len()));
    out.extend_from_slice(&fixed);
    for r in args.recipients {
        let hint = if args.anonymous {
            vec![0u8; HINT_LENGTH]
        } else {
            recipient_hint(&salt, &r.mlkem_public_key)
        };
        let enc = if entropy.deterministic() {
            let m = entropy.take(32)?;
            mlkem_encapsulate_derand(&r.mlkem_public_key, &m)?
        } else {
            mlkem_encapsulate(&r.mlkem_public_key)?
        };
        let (shared, ct_x) = match args.mode {
            SealMode::Hybrid => {
                let pk_x = r.x25519_public_key.as_deref().unwrap_or_default();
                let e_sk = entropy.take(32)?;
                let ct_x = x25519_public_key(&e_sk)?;
                let ss_x = x25519_agree(&e_sk, pk_x)?;
                (
                    hybrid_shared_secret(&enc.shared_secret, &ss_x, &ct_x, pk_x)?,
                    Some(ct_x),
                )
            }
            SealMode::Mlkem => (enc.shared_secret.clone(), None),
        };
        let kek = derive_key(&shared, args.chain_id, args.purpose, &salt)?;
        let wrapped = aead_seal(
            &kek,
            &ZERO_NONCE,
            &dek,
            &entry_aad(&fixed, &hint, &enc.ciphertext, ct_x.as_deref()),
        );
        out.extend_from_slice(&hint);
        out.extend_from_slice(&enc.ciphertext);
        if let Some(x) = &ct_x {
            out.extend_from_slice(x);
        }
        out.extend_from_slice(&wrapped);
    }
    let nonce = entropy.take(NONCE_LENGTH)?;
    out.extend_from_slice(&nonce);
    let mut aad = out.clone();
    aad.extend_from_slice(args.aad);
    let ciphertext = aead_seal(&dek, &nonce, args.plaintext, &aad);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Encrypt `plaintext` to one or more recipients. Returns the binary envelope.
pub fn seal(args: &SealArgs<'_>) -> Result<Vec<u8>> {
    seal_with(args, &mut SystemEntropy)
}

/// Read the structure of an envelope without decrypting it.
pub fn parse_envelope(b: &[u8]) -> Result<ParsedEnvelope> {
    if b.len() < 10 || b[..4] != ENVELOPE_MAGIC {
        return Err(Error::MalformedEnvelope("not a QoreSeal envelope".into()));
    }
    if b[4] != ENVELOPE_VERSION {
        return Err(Error::UnsupportedVersion(format!(
            "unsupported envelope version {}",
            b[4]
        )));
    }
    let mode = match b[5] {
        MODE_HYBRID => SealMode::Hybrid,
        MODE_MLKEM => SealMode::Mlkem,
        _ => {
            return Err(Error::UnsupportedAlgorithm(
                "unsupported mode or algorithm in the envelope".into(),
            ))
        }
    };
    if b[6] != ALGORITHM_ML_KEM_1024 || b[7] != KDF_HKDF_SHA256 || b[8] != AEAD_AES_256_GCM {
        return Err(Error::UnsupportedAlgorithm(
            "unsupported mode or algorithm in the envelope".into(),
        ));
    }
    let flags = b[9];
    if flags & !FLAG_ANONYMOUS != 0 {
        return Err(Error::MalformedEnvelope("unknown envelope flags".into()));
    }
    if b.len() < FIXED_HEADER_LENGTH {
        return Err(Error::MalformedEnvelope("truncated envelope".into()));
    }
    let n = usize::from(u16::from_be_bytes([b[26], b[27]]));
    if n == 0 || n > MAX_RECIPIENTS {
        return Err(Error::MalformedEnvelope(format!(
            "invalid recipient count {n}"
        )));
    }
    let header_length = FIXED_HEADER_LENGTH + n * mode.entry_length() + NONCE_LENGTH;
    if b.len() < header_length + TAG_LENGTH {
        return Err(Error::MalformedEnvelope("truncated envelope".into()));
    }
    let mut entries = Vec::with_capacity(n);
    let mut off = FIXED_HEADER_LENGTH;
    let mut take = |len: usize| {
        let s = b[off..off + len].to_vec();
        off += len;
        s
    };
    for _ in 0..n {
        let hint = take(HINT_LENGTH);
        let mlkem_ciphertext = take(ML_KEM_1024_CIPHERTEXT_LENGTH);
        let x25519_ciphertext = (mode == SealMode::Hybrid).then(|| take(32));
        let wrapped_key = take(WRAPPED_KEY_LENGTH);
        entries.push(EnvelopeEntry {
            hint,
            mlkem_ciphertext,
            x25519_ciphertext,
            wrapped_key,
        });
    }
    let nonce = take(NONCE_LENGTH);
    Ok(ParsedEnvelope {
        version: ENVELOPE_VERSION,
        mode,
        anonymous: flags & FLAG_ANONYMOUS != 0,
        salt: b[10..26].to_vec(),
        entries,
        nonce,
        ciphertext: b[header_length..].to_vec(),
        header: b[..header_length].to_vec(),
    })
}

fn unwrap_entry(
    env: &ParsedEnvelope,
    e: &EnvelopeEntry,
    keys: &SealKeyPair,
    chain_id: &str,
    purpose: &str,
) -> Option<Vec<u8>> {
    let ss_k = mlkem_decapsulate(&keys.mlkem_secret_key, &e.mlkem_ciphertext).ok()?;
    let shared = match (&env.mode, &e.x25519_ciphertext) {
        (SealMode::Hybrid, Some(ct_x)) => {
            let ss_x = x25519_agree(&keys.x25519_secret_key, ct_x).ok()?;
            hybrid_shared_secret(&ss_k, &ss_x, ct_x, &keys.x25519_public_key).ok()?
        }
        _ => ss_k,
    };
    let kek = derive_key(&shared, chain_id, purpose, &env.salt).ok()?;
    let fixed = &env.header[..FIXED_HEADER_LENGTH];
    aead_open(
        &kek,
        &ZERO_NONCE,
        &e.wrapped_key,
        &entry_aad(
            fixed,
            &e.hint,
            &e.mlkem_ciphertext,
            e.x25519_ciphertext.as_deref(),
        ),
    )
}

/// Decrypt an envelope with the recipient's keys. `aad` must equal the sender's.
pub fn open(
    chain_id: &str,
    purpose: &str,
    envelope: &[u8],
    keys: &SealKeyPair,
    aad: &[u8],
) -> Result<Vec<u8>> {
    check_chain_id(chain_id)?;
    check_purpose(purpose)?;
    check_key_pair(keys)?;
    let env = parse_envelope(envelope)?;
    let my_hint = recipient_hint(&env.salt, &keys.mlkem_public_key);
    let candidates: Vec<&EnvelopeEntry> = env
        .entries
        .iter()
        .filter(|e| env.anonymous || ct_eq(&e.hint, &my_hint))
        .collect();
    if candidates.is_empty() {
        return Err(Error::NotARecipient(
            "the envelope has no entry for this key".into(),
        ));
    }
    let dek = candidates
        .iter()
        .find_map(|e| unwrap_entry(&env, e, keys, chain_id, purpose))
        .ok_or_else(|| {
            Error::DecryptionFailed(
                "no entry of the envelope opens with this key, chain id and purpose".into(),
            )
        })?;
    let mut full_aad = env.header.clone();
    full_aad.extend_from_slice(aad);
    aead_open(&dek, &env.nonce, &env.ciphertext, &full_aad)
        .ok_or_else(|| Error::DecryptionFailed("the payload does not authenticate".into()))
}

/// `"qoreseal:" + base64url(envelope)`, without padding.
pub fn envelope_to_text(envelope: &[u8]) -> String {
    format!("{ENVELOPE_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(envelope))
}

/// Inverse of [`envelope_to_text`]; strict about the alphabet, padding and trailing bits.
pub fn envelope_from_text(text: &str) -> Result<Vec<u8>> {
    let body = text.strip_prefix(ENVELOPE_TEXT_PREFIX).ok_or_else(|| {
        Error::MalformedEnvelope("text form must start with \"qoreseal:\"".into())
    })?;
    URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| Error::MalformedEnvelope("invalid base64url in the text form".into()))
}
