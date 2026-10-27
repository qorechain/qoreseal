// SPDX-License-Identifier: Apache-2.0
//
// UniFFI surface of QoreSeal for the Swift, Kotlin and Python packages.
// Thin conversions over the `qoreseal` crate; no logic of its own.

use std::sync::Mutex;

use qoreseal as core;
use qoreseal::qoresign;

uniffi::setup_scaffolding!();

// ---------------------------------------------------------------- errors

/// Every failure carries the stable code shared by all QoreSeal
/// implementations (for example `NOT_A_RECIPIENT`) and a human-readable
/// detail. (The field is not named `message`: that clashes with
/// `Throwable.message` in the Kotlin bindings.)
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum QoreSealError {
    #[error("{code}: {detail}")]
    Failure { code: String, detail: String },
}

impl From<core::Error> for QoreSealError {
    fn from(e: core::Error) -> Self {
        QoreSealError::Failure {
            code: e.code().to_owned(),
            detail: e.message().to_owned(),
        }
    }
}

type Result<T> = std::result::Result<T, QoreSealError>;

fn failure(code: &str, detail: impl Into<String>) -> QoreSealError {
    QoreSealError::Failure {
        code: code.to_owned(),
        detail: detail.into(),
    }
}

// ---------------------------------------------------------------- keys

/// `Hybrid` (default): ML-KEM-1024 plus X25519. `Mlkem`: ML-KEM-1024 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum SealMode {
    Hybrid,
    Mlkem,
}

impl From<SealMode> for core::SealMode {
    fn from(m: SealMode) -> Self {
        match m {
            SealMode::Hybrid => core::SealMode::Hybrid,
            SealMode::Mlkem => core::SealMode::Mlkem,
        }
    }
}

impl From<core::SealMode> for SealMode {
    fn from(m: core::SealMode) -> Self {
        match m {
            core::SealMode::Hybrid => SealMode::Hybrid,
            core::SealMode::Mlkem => SealMode::Mlkem,
        }
    }
}

/// A recipient's keys. Keep `seed` (or the mnemonic it came from) secret and backed up.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SealKeyPair {
    pub seed: Vec<u8>,
    /// ML-KEM-1024 encapsulation key (1568 bytes): the key registered on chain.
    pub mlkem_public_key: Vec<u8>,
    pub mlkem_secret_key: Vec<u8>,
    /// X25519 public key (32 bytes), published in a recipient card.
    pub x25519_public_key: Vec<u8>,
    pub x25519_secret_key: Vec<u8>,
}

impl From<core::SealKeyPair> for SealKeyPair {
    fn from(k: core::SealKeyPair) -> Self {
        SealKeyPair {
            seed: k.seed,
            mlkem_public_key: k.mlkem_public_key,
            mlkem_secret_key: k.mlkem_secret_key,
            x25519_public_key: k.x25519_public_key,
            x25519_secret_key: k.x25519_secret_key,
        }
    }
}

impl From<SealKeyPair> for core::SealKeyPair {
    fn from(k: SealKeyPair) -> Self {
        core::SealKeyPair {
            seed: k.seed,
            mlkem_public_key: k.mlkem_public_key,
            mlkem_secret_key: k.mlkem_secret_key,
            x25519_public_key: k.x25519_public_key,
            x25519_secret_key: k.x25519_secret_key,
        }
    }
}

/// What a sender needs to seal to someone. `x25519_public_key` is required by the hybrid mode.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SealRecipient {
    pub mlkem_public_key: Vec<u8>,
    #[uniffi(default = None)]
    pub x25519_public_key: Option<Vec<u8>>,
}

impl From<SealRecipient> for core::SealRecipient {
    fn from(r: SealRecipient) -> Self {
        core::SealRecipient {
            mlkem_public_key: r.mlkem_public_key,
            x25519_public_key: r.x25519_public_key,
        }
    }
}

impl From<core::SealRecipient> for SealRecipient {
    fn from(r: core::SealRecipient) -> Self {
        SealRecipient {
            mlkem_public_key: r.mlkem_public_key,
            x25519_public_key: r.x25519_public_key,
        }
    }
}

fn recipients(rs: Vec<SealRecipient>) -> Vec<core::SealRecipient> {
    rs.into_iter().map(Into::into).collect()
}

/// Derive both key pairs from a 32-byte seed.
#[uniffi::export]
pub fn seal_keys_from_seed(seed: Vec<u8>) -> Result<SealKeyPair> {
    Ok(core::seal_keys_from_seed(&seed)?.into())
}

/// New key pairs from a fresh random seed.
#[uniffi::export]
pub fn generate_seal_keys() -> SealKeyPair {
    core::generate_seal_keys().into()
}

/// The 32-byte seed for `index` derived from a BIP-39 mnemonic.
#[uniffi::export(default(passphrase = "", index = 0))]
pub fn seal_seed_from_mnemonic(
    mnemonic: String,
    passphrase: String,
    index: u32,
) -> Result<Vec<u8>> {
    Ok(core::seal_seed_from_mnemonic(
        &mnemonic,
        &passphrase,
        index,
    )?)
}

/// Key pairs derived from a BIP-39 mnemonic. Move to the next `index` to rotate.
#[uniffi::export(default(passphrase = "", index = 0))]
pub fn derive_seal_keys(mnemonic: String, passphrase: String, index: u32) -> Result<SealKeyPair> {
    Ok(core::derive_seal_keys(&mnemonic, &passphrase, index)?.into())
}

/// The public half of a key pair, as a recipient.
#[uniffi::export]
pub fn recipient_of(keys: SealKeyPair) -> SealRecipient {
    core::SealKeyPair::from(keys).recipient().into()
}

/// The checks the chain applies to a registered ML-KEM-1024 key.
#[uniffi::export]
pub fn validate_mlkem_public_key(public_key: Vec<u8>) -> Result<()> {
    Ok(core::validate_mlkem_public_key(&public_key)?)
}

#[uniffi::export]
pub fn validate_x25519_public_key(public_key: Vec<u8>) -> Result<()> {
    Ok(core::validate_x25519_public_key(&public_key)?)
}

// ---------------------------------------------------------------- primitives

/// `"qorechain-kem-v1|" + chain_id + "|" + purpose`.
#[uniffi::export]
pub fn kdf_info(chain_id: String, purpose: String) -> Result<String> {
    Ok(core::kdf_info(&chain_id, &purpose)?)
}

/// HKDF-SHA-256 of a shared secret into a 32-byte key bound to the chain and purpose.
#[uniffi::export]
pub fn derive_key(
    shared: Vec<u8>,
    chain_id: String,
    purpose: String,
    salt: Vec<u8>,
) -> Result<Vec<u8>> {
    Ok(core::derive_key(&shared, &chain_id, &purpose, &salt)?)
}

/// Result of an ML-KEM-1024 encapsulation.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Encapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl From<core::Encapsulation> for Encapsulation {
    fn from(e: core::Encapsulation) -> Self {
        Encapsulation {
            ciphertext: e.ciphertext,
            shared_secret: e.shared_secret,
        }
    }
}

#[uniffi::export]
pub fn mlkem_encapsulate(public_key: Vec<u8>) -> Result<Encapsulation> {
    Ok(core::mlkem_encapsulate(&public_key)?.into())
}

#[uniffi::export]
pub fn mlkem_decapsulate(secret_key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
    Ok(core::mlkem_decapsulate(&secret_key, &ciphertext)?)
}

#[uniffi::export]
pub fn x25519_public_key(secret_key: Vec<u8>) -> Result<Vec<u8>> {
    Ok(core::x25519_public_key(&secret_key)?)
}

#[uniffi::export]
pub fn x25519_agree(secret_key: Vec<u8>, public_key: Vec<u8>) -> Result<Vec<u8>> {
    Ok(core::x25519_agree(&secret_key, &public_key)?)
}

/// `SHA3-256("qorechain-qoreseal-hybrid-v1" || ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519)`.
#[uniffi::export]
pub fn hybrid_shared_secret(
    mlkem_shared_secret: Vec<u8>,
    x25519_shared_secret: Vec<u8>,
    x25519_ciphertext: Vec<u8>,
    x25519_public_key: Vec<u8>,
) -> Result<Vec<u8>> {
    Ok(core::hybrid_shared_secret(
        &mlkem_shared_secret,
        &x25519_shared_secret,
        &x25519_ciphertext,
        &x25519_public_key,
    )?)
}

#[uniffi::export]
pub fn recipient_hint(salt: Vec<u8>, mlkem_public_key: Vec<u8>) -> Vec<u8> {
    core::recipient_hint(&salt, &mlkem_public_key)
}

// ---------------------------------------------------------------- envelopes

/// Encrypt `plaintext` to one or more recipients. Default: hybrid mode, no AAD, hints on.
#[uniffi::export(default(aad = [], mode = None, anonymous = false))]
pub fn seal_envelope(
    chain_id: String,
    purpose: String,
    recipients: Vec<SealRecipient>,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
    mode: Option<SealMode>,
    anonymous: bool,
) -> Result<Vec<u8>> {
    let rs = self::recipients(recipients);
    let mut args = core::SealArgs::new(&chain_id, &purpose, &rs, &plaintext);
    args.aad = &aad;
    args.mode = mode.unwrap_or(SealMode::Hybrid).into();
    args.anonymous = anonymous;
    Ok(core::seal(&args)?)
}

/// Decrypt an envelope with the recipient's keys. `aad` must equal the sender's.
#[uniffi::export(default(aad = []))]
pub fn open_envelope(
    chain_id: String,
    purpose: String,
    envelope: Vec<u8>,
    keys: SealKeyPair,
    aad: Vec<u8>,
) -> Result<Vec<u8>> {
    Ok(core::open(
        &chain_id,
        &purpose,
        &envelope,
        &keys.into(),
        &aad,
    )?)
}

/// One recipient entry of an envelope.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnvelopeEntry {
    pub hint: Vec<u8>,
    pub mlkem_ciphertext: Vec<u8>,
    pub x25519_ciphertext: Option<Vec<u8>>,
    pub wrapped_key: Vec<u8>,
}

/// The parts of an envelope, as read from its bytes.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ParsedEnvelope {
    pub version: u8,
    pub mode: SealMode,
    pub anonymous: bool,
    pub salt: Vec<u8>,
    pub entries: Vec<EnvelopeEntry>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub header: Vec<u8>,
}

/// Read the structure of an envelope without decrypting it.
#[uniffi::export]
pub fn parse_envelope(envelope: Vec<u8>) -> Result<ParsedEnvelope> {
    let p = core::parse_envelope(&envelope)?;
    Ok(ParsedEnvelope {
        version: p.version,
        mode: p.mode.into(),
        anonymous: p.anonymous,
        salt: p.salt,
        entries: p
            .entries
            .into_iter()
            .map(|e| EnvelopeEntry {
                hint: e.hint,
                mlkem_ciphertext: e.mlkem_ciphertext,
                x25519_ciphertext: e.x25519_ciphertext,
                wrapped_key: e.wrapped_key,
            })
            .collect(),
        nonce: p.nonce,
        ciphertext: p.ciphertext,
        header: p.header,
    })
}

/// Size in bytes of an envelope: `56 + n * W + plaintext_length`.
#[uniffi::export]
pub fn envelope_size(mode: SealMode, recipients: u32, plaintext_length: u64) -> u64 {
    core::envelope_size(mode.into(), recipients as usize, plaintext_length as usize) as u64
}

/// `"qoreseal:" + base64url(envelope)`, without padding.
#[uniffi::export]
pub fn envelope_to_text(envelope: Vec<u8>) -> String {
    core::envelope_to_text(&envelope)
}

#[uniffi::export]
pub fn envelope_from_text(text: String) -> Result<Vec<u8>> {
    Ok(core::envelope_from_text(&text)?)
}

// ---------------------------------------------------------------- cards

/// The fields a recipient card signs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecipientCardFields {
    pub chain_id: String,
    pub address: String,
    pub mlkem_key_sha3: String,
    pub x25519_public_key: String,
    pub issued_at: String,
}

impl From<core::RecipientCardFields> for RecipientCardFields {
    fn from(f: core::RecipientCardFields) -> Self {
        RecipientCardFields {
            chain_id: f.chain_id,
            address: f.address,
            mlkem_key_sha3: f.mlkem_key_sha3,
            x25519_public_key: f.x25519_public_key,
            issued_at: f.issued_at,
        }
    }
}

impl From<RecipientCardFields> for core::RecipientCardFields {
    fn from(f: RecipientCardFields) -> Self {
        core::RecipientCardFields {
            chain_id: f.chain_id,
            address: f.address,
            mlkem_key_sha3: f.mlkem_key_sha3,
            x25519_public_key: f.x25519_public_key,
            issued_at: f.issued_at,
        }
    }
}

/// Card fields for a key pair. `issued_at` (`YYYY-MM-DDTHH:MM:SSZ`) defaults to now.
#[uniffi::export(default(issued_at = None))]
pub fn recipient_card_fields(
    chain_id: String,
    address: String,
    mlkem_public_key: Vec<u8>,
    x25519_public_key: Vec<u8>,
    issued_at: Option<String>,
) -> Result<RecipientCardFields> {
    Ok(core::recipient_card_fields(
        &chain_id,
        &address,
        &mlkem_public_key,
        &x25519_public_key,
        issued_at.as_deref(),
    )?
    .into())
}

/// The exact text the account signs.
#[uniffi::export]
pub fn recipient_card_text(fields: RecipientCardFields) -> Result<String> {
    Ok(core::recipient_card_text(&fields.into())?)
}

/// The account keys a card is signed with, derived from the account mnemonic
/// as QoreChain wallets do (secp256k1 at m/44'/118'/0'/0/index and the
/// canonical ML-DSA-87 key registered on chain).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountKeys {
    pub address: String,
    pub classical_private_key: Vec<u8>,
    pub classical_public_key: Vec<u8>,
    pub pq_public_key: Vec<u8>,
    pub pq_secret_key: Vec<u8>,
}

#[uniffi::export(default(index = 0))]
pub fn account_keys_from_mnemonic(mnemonic: String, index: u32) -> Result<AccountKeys> {
    let ty = qoresign::ClassicalKeyType::Secp256k1;
    let map =
        |e: qoresign::Error| failure("INVALID_ARGUMENT", format!("{}: {}", e.code(), e.message()));
    let classical = qoresign::derive_classical_key(&mnemonic, ty, index).map_err(map)?;
    let address = qoresign::address_from_public_key(&classical.public_key, ty)
        .map_err(map)?
        .bech32;
    let pq = qoresign::derive_canonical_pq_key(&mnemonic, &address).map_err(map)?;
    Ok(AccountKeys {
        address,
        classical_private_key: classical.private_key.to_vec(),
        classical_public_key: classical.public_key.to_vec(),
        pq_public_key: pq.public_key,
        pq_secret_key: pq.secret_key,
    })
}

/// Sign card fields with the account's secp256k1 key (`secp256k1` or
/// `eth_secp256k1` account) and ML-DSA-87 secret key. Returns the card JSON.
#[uniffi::export(default(classical_key_type = "secp256k1"))]
pub fn sign_recipient_card(
    fields: RecipientCardFields,
    classical_private_key: Vec<u8>,
    pq_secret_key: Vec<u8>,
    classical_key_type: String,
) -> Result<String> {
    let ty = match classical_key_type.as_str() {
        "secp256k1" => qoresign::ClassicalKeyType::Secp256k1,
        "eth_secp256k1" => qoresign::ClassicalKeyType::EthSecp256k1,
        other => {
            return Err(failure(
                "INVALID_ARGUMENT",
                format!("unknown key type {other:?}"),
            ))
        }
    };
    let classical = qoresign::classical_key_from_private(&classical_private_key, ty)
        .map_err(|e| failure("INVALID_ARGUMENT", e.message()))?;
    let pq = qoresign::PqKeyPair {
        algorithm_id: qoresign::ALGORITHM_ML_DSA_87,
        public_key: Vec::new(),
        secret_key: pq_secret_key,
    };
    Ok(core::sign_recipient_card(&fields.into(), &classical, &pq)?.to_json())
}

/// Attach a QoreSign message signature (its JSON) produced elsewhere, for
/// example by a wallet, to card fields. Returns the card JSON.
#[uniffi::export]
pub fn assemble_recipient_card(
    fields: RecipientCardFields,
    signature_json: String,
) -> Result<String> {
    let sig: qoresign::MessageSignature = serde_json::from_str(&signature_json)
        .map_err(|e| failure("CARD_INVALID", format!("signature JSON: {e}")))?;
    Ok(core::assemble_recipient_card(&fields.into(), sig)?.to_json())
}

/// The fields of a card JSON, without verifying it.
#[uniffi::export]
pub fn recipient_card_from_json(card_json: String) -> Result<RecipientCardFields> {
    Ok(core::RecipientCard::from_json(&card_json)?.fields().into())
}

/// Verify a card JSON against the keys the account has on chain and return
/// the hybrid recipient. Fails with `CARD_INVALID`.
#[uniffi::export(default(address = None))]
pub fn verify_recipient_card(
    card_json: String,
    chain_id: String,
    pq_public_key: Vec<u8>,
    mlkem_public_key: Vec<u8>,
    address: Option<String>,
) -> Result<SealRecipient> {
    let card = core::RecipientCard::from_json(&card_json)?;
    Ok(core::verify_recipient_card(&core::VerifyCardArgs {
        card: &card,
        chain_id: &chain_id,
        address: address.as_deref(),
        pq_public_key: &pq_public_key,
        mlkem_public_key: &mlkem_public_key,
    })?
    .into())
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix time in seconds.
#[uniffi::export]
pub fn format_issued_at(unix_seconds: u64) -> String {
    core::format_issued_at(unix_seconds)
}

// ---------------------------------------------------------------- registry

/// A protobuf `Any`, ready to put in a transaction body.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EncodedMessage {
    pub type_url: String,
    pub value: Vec<u8>,
}

/// `MsgRegisterKEMKey { sender, algorithm_id: 2, public_key }`.
#[uniffi::export]
pub fn build_register_kem_key_message(
    sender: String,
    mlkem_public_key: Vec<u8>,
) -> Result<EncodedMessage> {
    let m = core::build_register_kem_key_message(&sender, &mlkem_public_key)?;
    Ok(EncodedMessage {
        type_url: m.type_url,
        value: m.value,
    })
}

/// `MsgRemoveKEMKey { sender }`.
#[uniffi::export]
pub fn build_remove_kem_key_message(sender: String) -> Result<EncodedMessage> {
    let m = core::build_remove_kem_key_message(&sender)?;
    Ok(EncodedMessage {
        type_url: m.type_url,
        value: m.value,
    })
}

/// Explain a refusal of a registry transaction (codespace `pqc`, codes 250 to 254).
#[uniffi::export]
pub fn describe_kem_registry_error(codespace: String, code: u32) -> Option<String> {
    core::describe_kem_registry_error(&codespace, code).map(str::to_owned)
}

// ---------------------------------------------------------------- groups

/// An epoch number (from 1) and its 32-byte key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EpochKey {
    pub epoch: u64,
    pub key: Vec<u8>,
}

impl From<EpochKey> for core::EpochKey {
    fn from(k: EpochKey) -> Self {
        core::EpochKey {
            epoch: k.epoch,
            key: k.key,
        }
    }
}

impl From<core::EpochKey> for EpochKey {
    fn from(k: core::EpochKey) -> Self {
        EpochKey {
            epoch: k.epoch,
            key: k.key,
        }
    }
}

#[uniffi::export]
pub fn encode_epoch_key(epoch_key: EpochKey) -> Result<Vec<u8>> {
    Ok(core::encode_epoch_key(&epoch_key.into())?)
}

#[uniffi::export]
pub fn decode_epoch_key(payload: Vec<u8>) -> Result<EpochKey> {
    Ok(core::decode_epoch_key(&payload)?.into())
}

/// Seal an epoch key to the members of a group.
#[uniffi::export(default(mode = None))]
pub fn seal_epoch_key(
    chain_id: String,
    purpose: String,
    epoch_key: EpochKey,
    recipients: Vec<SealRecipient>,
    mode: Option<SealMode>,
) -> Result<Vec<u8>> {
    Ok(core::seal_epoch_key(
        &chain_id,
        &purpose,
        &epoch_key.into(),
        &self::recipients(recipients),
        mode.unwrap_or(SealMode::Hybrid).into(),
    )?)
}

#[uniffi::export]
pub fn open_epoch_key(
    chain_id: String,
    purpose: String,
    envelope: Vec<u8>,
    keys: SealKeyPair,
) -> Result<EpochKey> {
    Ok(core::open_epoch_key(&chain_id, &purpose, &envelope, &keys.into())?.into())
}

/// A member of a group.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GroupMember {
    pub id: String,
    pub recipient: SealRecipient,
}

/// What a membership change produced.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EpochRotation {
    pub epoch: u64,
    /// Envelope for the members; none when the group has no members left.
    pub envelope: Option<Vec<u8>>,
    pub members: Vec<String>,
}

impl From<core::EpochRotation> for EpochRotation {
    fn from(r: core::EpochRotation) -> Self {
        EpochRotation {
            epoch: r.epoch,
            envelope: r.envelope,
            members: r.members,
        }
    }
}

/// Keeps the epoch keys of a group on the operator's side. Safe to share between threads.
#[derive(Debug, uniffi::Object)]
pub struct EpochKeyManager {
    inner: Mutex<core::EpochKeyManager>,
}

impl EpochKeyManager {
    fn lock(&self) -> std::sync::MutexGuard<'_, core::EpochKeyManager> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[uniffi::export]
impl EpochKeyManager {
    /// A manager at epoch 1, or at the last epoch of `history` (oldest first).
    #[uniffi::constructor(default(mode = None, history = []))]
    pub fn new(
        chain_id: String,
        purpose: String,
        members: Vec<GroupMember>,
        mode: Option<SealMode>,
        history: Vec<EpochKey>,
    ) -> Result<Self> {
        let inner = core::EpochKeyManager::new(
            &chain_id,
            &purpose,
            mode.unwrap_or(SealMode::Hybrid).into(),
            members
                .into_iter()
                .map(|m| (m.id, m.recipient.into()))
                .collect(),
            history.into_iter().map(Into::into).collect(),
        )?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.lock().epoch()
    }

    pub fn current_key(&self) -> EpochKey {
        self.lock().current_key().into()
    }

    pub fn key_for(&self, epoch: u64) -> Option<Vec<u8>> {
        self.lock().key_for(epoch)
    }

    /// Every epoch key, oldest first. Store it encrypted.
    pub fn export_keys(&self) -> Vec<EpochKey> {
        self.lock()
            .export_keys()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    pub fn members(&self) -> Vec<String> {
        self.lock().members()
    }

    pub fn distribution(&self) -> Result<Vec<u8>> {
        Ok(self.lock().distribution()?)
    }

    pub fn rotate(&self) -> Result<EpochRotation> {
        Ok(self.lock().rotate()?.into())
    }

    pub fn add_member(&self, id: String, recipient: SealRecipient) -> Result<EpochRotation> {
        Ok(self.lock().add_member(&id, recipient.into())?.into())
    }

    pub fn remove_member(&self, id: String) -> Result<EpochRotation> {
        Ok(self.lock().remove_member(&id)?.into())
    }

    /// Seal batch data under the current epoch key.
    pub fn seal_batch(
        &self,
        context: String,
        batch_index: u64,
        data: Vec<u8>,
    ) -> Result<SealedBatch> {
        let key = self.lock().current_key();
        Ok(core::seal_batch(&key, &context, batch_index, &data)?.into())
    }

    /// Open a batch with the key of its epoch.
    pub fn open_batch(&self, blob: Vec<u8>) -> Result<OpenedBatch> {
        let mgr = self.lock();
        Ok(core::open_batch(&blob, |e| mgr.key_for(e))?.into())
    }
}

// ---------------------------------------------------------------- batches

/// An encrypted batch and its commitments.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SealedBatch {
    pub blob: Vec<u8>,
    pub epoch: u64,
    pub batch_index: u64,
    pub ciphertext_commitment: Vec<u8>,
    pub plaintext_commitment: Vec<u8>,
}

impl From<core::SealedBatch> for SealedBatch {
    fn from(b: core::SealedBatch) -> Self {
        SealedBatch {
            blob: b.blob,
            epoch: b.epoch,
            batch_index: b.batch_index,
            ciphertext_commitment: b.ciphertext_commitment,
            plaintext_commitment: b.plaintext_commitment,
        }
    }
}

/// A decrypted batch.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OpenedBatch {
    pub epoch: u64,
    pub batch_index: u64,
    pub context: String,
    pub data: Vec<u8>,
    pub ciphertext_commitment: Vec<u8>,
    pub plaintext_commitment: Vec<u8>,
}

impl From<core::OpenedBatch> for OpenedBatch {
    fn from(b: core::OpenedBatch) -> Self {
        OpenedBatch {
            epoch: b.epoch,
            batch_index: b.batch_index,
            context: b.context,
            data: b.data,
            ciphertext_commitment: b.ciphertext_commitment,
            plaintext_commitment: b.plaintext_commitment,
        }
    }
}

/// A batch blob's header.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BatchHeader {
    pub epoch: u64,
    pub batch_index: u64,
    pub context: String,
    pub nonce: Vec<u8>,
}

/// Encrypt batch data under an epoch key. `context` names the batch stream, for example the rollup id.
#[uniffi::export]
pub fn seal_batch(
    epoch_key: EpochKey,
    context: String,
    batch_index: u64,
    data: Vec<u8>,
) -> Result<SealedBatch> {
    Ok(core::seal_batch(&epoch_key.into(), &context, batch_index, &data)?.into())
}

/// Decrypt a batch blob with the key of its epoch, taken from `keys`.
#[uniffi::export]
pub fn open_batch(blob: Vec<u8>, keys: Vec<EpochKey>) -> Result<OpenedBatch> {
    let keys: Vec<core::EpochKey> = keys.into_iter().map(Into::into).collect();
    Ok(core::open_batch(&blob, core::keys_from_list(&keys))?.into())
}

#[uniffi::export]
pub fn parse_batch_header(blob: Vec<u8>) -> Result<BatchHeader> {
    let h = core::parse_batch_header(&blob)?;
    Ok(BatchHeader {
        epoch: h.epoch,
        batch_index: h.batch_index,
        context: h.context,
        nonce: h.nonce,
    })
}

/// Size of a batch blob: `83 + context length + data length`.
#[uniffi::export]
pub fn batch_size(context_length: u32, data_length: u64) -> u64 {
    core::batch_size(context_length as usize, data_length as usize) as u64
}

// ---------------------------------------------------------------- testing

/// `seal_envelope` with all of its randomness given (spec section 9).
/// For test vectors only: never use with real data.
#[allow(clippy::too_many_arguments)]
#[uniffi::export(default(aad = [], mode = None, anonymous = false))]
pub fn testing_seal_with_entropy(
    chain_id: String,
    purpose: String,
    recipients: Vec<SealRecipient>,
    plaintext: Vec<u8>,
    entropy: Vec<u8>,
    aad: Vec<u8>,
    mode: Option<SealMode>,
    anonymous: bool,
) -> Result<Vec<u8>> {
    let rs = self::recipients(recipients);
    let mut args = core::SealArgs::new(&chain_id, &purpose, &rs, &plaintext);
    args.aad = &aad;
    args.mode = mode.unwrap_or(SealMode::Hybrid).into();
    args.anonymous = anonymous;
    Ok(core::testing::seal_with_entropy(&args, &entropy)?)
}

/// `seal_batch` with its nonce (12) and commitment salt (32) given. For test vectors only.
#[uniffi::export]
pub fn testing_seal_batch_with_entropy(
    epoch_key: EpochKey,
    context: String,
    batch_index: u64,
    data: Vec<u8>,
    entropy: Vec<u8>,
) -> Result<SealedBatch> {
    Ok(core::testing::seal_batch_with_entropy(
        &epoch_key.into(),
        &context,
        batch_index,
        &data,
        &entropy,
    )?
    .into())
}

/// ML-KEM-1024 encapsulation with explicit randomness. For test vectors only.
#[uniffi::export]
pub fn testing_mlkem_encapsulate_with_randomness(
    public_key: Vec<u8>,
    m: Vec<u8>,
) -> Result<Encapsulation> {
    Ok(core::testing::mlkem_encapsulate_with_randomness(&public_key, &m)?.into())
}

/// Bytes of entropy a seal consumes.
#[uniffi::export]
pub fn testing_seal_entropy_length(mode: SealMode, recipients: u32) -> u64 {
    core::testing::seal_entropy_length(mode.into(), recipients as usize) as u64
}
