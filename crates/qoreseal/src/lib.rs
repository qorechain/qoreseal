// SPDX-License-Identifier: Apache-2.0
//
// qorechain-qoreseal: ML-KEM-1024 (FIPS 203) encryption of data to QoreChain
// accounts. Offline only.

//! ML-KEM-1024 (FIPS 203) encryption of data to QoreChain accounts.
//!
//! A recipient publishes its ML-KEM-1024 key in the chain's KEM key registry
//! (`MsgRegisterKEMKey`, available on testnet; on mainnet from the v3.2.5
//! upgrade). A sender encrypts the payload once with a random data key and
//! wraps that key for every recipient. The default `hybrid` mode adds an
//! X25519 agreement, with the recipient's X25519 key taken from a recipient
//! card the account signs; `mlkem` mode uses the on-chain key alone.
//!
//! This crate is offline. Its output is byte-identical to the other QoreSeal
//! implementations; `vectors/qoreseal-v1.json` in the repository is the
//! shared contract and `spec/qoreseal-v1.md` the format.
//!
//! QoreSeal protects payload content only: addresses, amounts, timing and
//! sizes stay public, there is no zero-knowledge proof, and losing the seed
//! loses access to the data.
//!
//! ```
//! use qoreseal::{generate_seal_keys, open, seal, SealArgs};
//!
//! let alice = generate_seal_keys();
//! let recipients = [alice.recipient()];
//! let envelope = seal(&SealArgs::new("qorechain-diana", "chat", &recipients, b"hello"))?;
//! let plaintext = open("qorechain-diana", "chat", &envelope, &alice, &[])?;
//! assert_eq!(plaintext, b"hello");
//! # Ok::<(), qoreseal::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod batch;
pub mod card;
pub mod constants;
pub mod envelope;
pub mod errors;
pub mod group;
pub mod kem;
pub mod keys;
pub mod registry;
pub mod testing;
mod util;

pub use batch::{
    batch_plaintext_commitment, batch_size, keys_from_list, open_batch, parse_batch_header,
    seal_batch, BatchHeader, OpenedBatch, PrivateBatchCodec, SealedBatch, BATCH_MAGIC,
    BATCH_VERSION,
};
pub use card::{
    assemble_recipient_card, format_issued_at, recipient_card_fields, recipient_card_text,
    sign_recipient_card, verify_recipient_card, RecipientCard, RecipientCardFields, VerifyCardArgs,
    RECIPIENT_CARD_TITLE, RECIPIENT_CARD_VERSION,
};
pub use constants::*;
pub use envelope::{
    envelope_from_text, envelope_size, envelope_to_text, open, parse_envelope, seal, EnvelopeEntry,
    ParsedEnvelope, SealArgs,
};
pub use errors::{Error, Result};
pub use group::{
    decode_epoch_key, encode_epoch_key, open_epoch_key, seal_epoch_key, EpochKey, EpochKeyManager,
    EpochRotation, EPOCH_KEY_MAGIC, EPOCH_KEY_PAYLOAD_LENGTH, EPOCH_KEY_VERSION,
};
pub use kem::{
    derive_key, hybrid_shared_secret, kdf_info, mlkem_decapsulate, mlkem_encapsulate,
    recipient_hint, x25519_agree, x25519_public_key, Encapsulation,
};
pub use keys::{
    derive_seal_keys, generate_seal_keys, seal_keys_from_seed, seal_seed_from_mnemonic,
    validate_mlkem_public_key, validate_x25519_public_key, SealKeyPair, SealRecipient,
};
pub use registry::{
    build_register_kem_key_message, build_remove_kem_key_message, describe_kem_registry_error,
    KEM_REGISTRY_ERRORS, MSG_REGISTER_KEM_KEY_TYPE_URL, MSG_REMOVE_KEM_KEY_TYPE_URL,
};

/// QoreSign types used in this crate's API (cards and registry messages).
pub use qoresign;
