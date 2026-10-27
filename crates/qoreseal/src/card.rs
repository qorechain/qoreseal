// SPDX-License-Identifier: Apache-2.0
//
// Recipient cards: the X25519 key of the hybrid mode, signed by the account
// with QoreSign message signing and bound to the ML-KEM key on chain
// (spec section 7).

use qoresign::{
    parse_address, sign_message, verify_message, ClassicalKey, MessageSignature, PqKeyPair,
    VerifyMessageArgs,
};
use serde::{Deserialize, Serialize};

use crate::constants::check_chain_id;
use crate::errors::{Error, Result};
use crate::keys::{validate_mlkem_public_key, validate_x25519_public_key, SealRecipient};
use crate::util::{ct_eq, sha3_256};

pub const RECIPIENT_CARD_VERSION: u32 = 1;
pub const RECIPIENT_CARD_TITLE: &str = "QoreSeal recipient card v1";

/// The fields a card signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientCardFields {
    pub chain_id: String,
    /// The `qor1` account the card belongs to.
    pub address: String,
    /// Hex SHA3-256 of the ML-KEM-1024 key registered on chain.
    pub mlkem_key_sha3: String,
    /// Hex X25519 public key.
    pub x25519_public_key: String,
    /// `YYYY-MM-DDTHH:MM:SSZ`.
    pub issued_at: String,
}

/// A signed recipient card, in the JSON shape shared by every implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientCard {
    pub version: u32,
    pub chain_id: String,
    pub address: String,
    pub mlkem_key_sha3: String,
    pub x25519_public_key: String,
    pub issued_at: String,
    pub signature: MessageSignature,
}

impl RecipientCard {
    pub fn fields(&self) -> RecipientCardFields {
        RecipientCardFields {
            chain_id: self.chain_id.clone(),
            address: self.address.clone(),
            mlkem_key_sha3: self.mlkem_key_sha3.clone(),
            x25519_public_key: self.x25519_public_key.clone(),
            issued_at: self.issued_at.clone(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("card JSON")
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::CardInvalid(format!("card JSON: {e}")))
    }
}

fn invalid(m: &str) -> Error {
    Error::CardInvalid(m.into())
}

fn is_hex32(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_issued_at(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

fn check_fields(f: &RecipientCardFields) -> Result<()> {
    check_chain_id(&f.chain_id).map_err(|_| invalid("invalid chain id"))?;
    let addr = parse_address(&f.address).map_err(|_| invalid("invalid address"))?;
    if addr.bech32 != f.address {
        return Err(invalid("the address must be the qor1 form"));
    }
    if !is_hex32(&f.mlkem_key_sha3) {
        return Err(invalid("mlkemKeySha3 must be 64 lowercase hex characters"));
    }
    if !is_hex32(&f.x25519_public_key) {
        return Err(invalid(
            "x25519PublicKey must be 64 lowercase hex characters",
        ));
    }
    if !is_issued_at(&f.issued_at) {
        return Err(invalid("issuedAt must be YYYY-MM-DDTHH:MM:SSZ"));
    }
    Ok(())
}

/// The exact text the account signs (spec section 7).
pub fn recipient_card_text(f: &RecipientCardFields) -> Result<String> {
    check_fields(f)?;
    Ok([
        RECIPIENT_CARD_TITLE.to_owned(),
        format!("Chain ID: {}", f.chain_id),
        format!("Address: {}", f.address),
        format!("ML-KEM-1024 key SHA3-256: {}", f.mlkem_key_sha3),
        format!("X25519 key: {}", f.x25519_public_key),
        format!("Issued at: {}", f.issued_at),
    ]
    .join("\n"))
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix time in seconds.
pub fn format_issued_at(unix_seconds: u64) -> String {
    let days = (unix_seconds / 86_400) as i64;
    let secs = unix_seconds % 86_400;
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn now_issued_at() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_issued_at(secs)
}

/// The card fields for a key pair. `issued_at` defaults to now.
pub fn recipient_card_fields(
    chain_id: &str,
    address: &str,
    mlkem_public_key: &[u8],
    x25519_public_key: &[u8],
    issued_at: Option<&str>,
) -> Result<RecipientCardFields> {
    validate_mlkem_public_key(mlkem_public_key)?;
    validate_x25519_public_key(x25519_public_key)?;
    let f = RecipientCardFields {
        chain_id: chain_id.to_owned(),
        address: address.to_owned(),
        mlkem_key_sha3: hex::encode(sha3_256(&[mlkem_public_key])),
        x25519_public_key: hex::encode(x25519_public_key),
        issued_at: issued_at.map(str::to_owned).unwrap_or_else(now_issued_at),
    };
    check_fields(&f)?;
    Ok(f)
}

/// Attach a signature produced elsewhere (for example by a wallet) to card fields.
pub fn assemble_recipient_card(
    f: &RecipientCardFields,
    signature: MessageSignature,
) -> Result<RecipientCard> {
    check_fields(f)?;
    Ok(RecipientCard {
        version: RECIPIENT_CARD_VERSION,
        chain_id: f.chain_id.clone(),
        address: f.address.clone(),
        mlkem_key_sha3: f.mlkem_key_sha3.clone(),
        x25519_public_key: f.x25519_public_key.clone(),
        issued_at: f.issued_at.clone(),
        signature,
    })
}

/// Sign a recipient card with the account's classical and ML-DSA-87 keys
/// (QoreSign `sign_message`, deterministic).
pub fn sign_recipient_card(
    f: &RecipientCardFields,
    classical_key: &ClassicalKey,
    pq_key: &PqKeyPair,
) -> Result<RecipientCard> {
    let text = recipient_card_text(f)?;
    let signature = sign_message(
        &f.chain_id,
        &f.address,
        text.as_bytes(),
        classical_key,
        Some(pq_key),
        false,
    )
    .map_err(|e| Error::InvalidArgument(format!("{}: {}", e.code(), e.message())))?;
    assemble_recipient_card(f, signature)
}

/// Input of [`verify_recipient_card`].
#[derive(Clone, Copy, Debug)]
pub struct VerifyCardArgs<'a> {
    pub card: &'a RecipientCard,
    pub chain_id: &'a str,
    /// Expected account; `None` accepts the card's own.
    pub address: Option<&'a str>,
    /// ML-DSA-87 key registered for the account (`/qorechain/pqc/v1/account/{address}`).
    pub pq_public_key: &'a [u8],
    /// ML-KEM-1024 key registered for the account (`/qorechain/pqc/v1/kem/{address}`).
    pub mlkem_public_key: &'a [u8],
}

/// Verify a card against the keys the account has on chain and return the
/// hybrid recipient. Fails with `CARD_INVALID`.
pub fn verify_recipient_card(args: &VerifyCardArgs<'_>) -> Result<SealRecipient> {
    let c = args.card;
    if c.version != RECIPIENT_CARD_VERSION {
        return Err(invalid("unsupported card version"));
    }
    let f = c.fields();
    check_fields(&f)?;
    if c.chain_id != args.chain_id {
        return Err(Error::CardInvalid(format!(
            "the card is for chain {}, not {}",
            c.chain_id, args.chain_id
        )));
    }
    if let Some(a) = args.address {
        if c.address != a {
            return Err(Error::CardInvalid(format!(
                "the card is for {}, not {a}",
                c.address
            )));
        }
    }
    validate_mlkem_public_key(args.mlkem_public_key)
        .map_err(|_| invalid("the registered ML-KEM-1024 key is not valid"))?;
    let expected = hex::decode(&c.mlkem_key_sha3).map_err(|_| invalid("bad mlkemKeySha3"))?;
    if !ct_eq(&sha3_256(&[args.mlkem_public_key]), &expected) {
        return Err(invalid(
            "the card names a different ML-KEM-1024 key than the registered one",
        ));
    }
    let x = hex::decode(&c.x25519_public_key).map_err(|_| invalid("bad x25519PublicKey"))?;
    validate_x25519_public_key(&x).map_err(|_| invalid("the card's X25519 key is not valid"))?;
    let text = recipient_card_text(&f)?;
    let mut v = VerifyMessageArgs::new(
        &c.chain_id,
        &c.address,
        text.as_bytes(),
        &c.signature,
        Some(args.pq_public_key),
    );
    v.require_pq = true;
    verify_message(&v).map_err(|e| {
        Error::CardInvalid(format!("the card signature does not verify ({})", e.code()))
    })?;
    Ok(SealRecipient {
        mlkem_public_key: args.mlkem_public_key.to_vec(),
        x25519_public_key: Some(x),
    })
}
