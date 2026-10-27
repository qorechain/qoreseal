// SPDX-License-Identifier: Apache-2.0
//
// Private batch codec (spec section 8.2): batch data encrypted under the
// group's epoch key, with a ciphertext commitment and a salted plaintext
// commitment ready to anchor on QoreChain.

use crate::constants::{
    check_purpose, AEAD_AES_256_GCM, BATCH_COMMITMENT_LABEL, DATA_KEY_LENGTH, NONCE_LENGTH,
    TAG_LENGTH,
};
use crate::envelope::{aead_open, aead_seal};
use crate::errors::{Error, Result};
use crate::group::{EpochKey, EpochKeyManager};
use crate::util::{require_len, sha3_256, Entropy, SystemEntropy};

/// `"QSBT"`.
pub const BATCH_MAGIC: [u8; 4] = *b"QSBT";
pub const BATCH_VERSION: u8 = 1;
const COMMIT_SALT_LENGTH: usize = 32;

/// An encrypted batch and its commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBatch {
    /// The encrypted batch, to publish (for example as a data-availability blob).
    pub blob: Vec<u8>,
    pub epoch: u64,
    pub batch_index: u64,
    /// SHA3-256 of the blob.
    pub ciphertext_commitment: Vec<u8>,
    /// Salted SHA3-256 of the batch data; members can recompute it after decrypting.
    pub plaintext_commitment: Vec<u8>,
}

/// A decrypted batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedBatch {
    pub epoch: u64,
    pub batch_index: u64,
    pub context: String,
    pub data: Vec<u8>,
    pub ciphertext_commitment: Vec<u8>,
    pub plaintext_commitment: Vec<u8>,
}

/// A batch blob's header, readable without the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchHeader {
    pub epoch: u64,
    pub batch_index: u64,
    pub context: String,
    pub nonce: Vec<u8>,
    pub header_length: usize,
}

/// Size of a batch blob: `83 + context length + data length`.
pub fn batch_size(context_length: usize, data_length: usize) -> usize {
    35 + context_length + COMMIT_SALT_LENGTH + data_length + TAG_LENGTH
}

pub fn batch_plaintext_commitment(commit_salt: &[u8], data: &[u8]) -> Vec<u8> {
    sha3_256(&[BATCH_COMMITMENT_LABEL.as_bytes(), commit_salt, data]).to_vec()
}

pub(crate) fn seal_batch_with(
    epoch_key: &EpochKey,
    context: &str,
    batch_index: u64,
    data: &[u8],
    entropy: &mut dyn Entropy,
) -> Result<SealedBatch> {
    check_purpose(context)
        .map_err(|_| Error::InvalidArgument(format!("invalid context {context:?}")))?;
    if epoch_key.epoch == 0 {
        return Err(Error::InvalidArgument("epochs start at 1".into()));
    }
    require_len(&epoch_key.key, DATA_KEY_LENGTH, "epoch key")?;
    let nonce = entropy.take(NONCE_LENGTH)?;
    let commit_salt = entropy.take(COMMIT_SALT_LENGTH)?;
    let mut blob = Vec::with_capacity(batch_size(context.len(), data.len()));
    blob.extend_from_slice(&BATCH_MAGIC);
    blob.extend_from_slice(&[BATCH_VERSION, AEAD_AES_256_GCM]);
    blob.extend_from_slice(&epoch_key.epoch.to_be_bytes());
    blob.extend_from_slice(&batch_index.to_be_bytes());
    blob.push(context.len() as u8);
    blob.extend_from_slice(context.as_bytes());
    blob.extend_from_slice(&nonce);
    let mut inner = commit_salt.clone();
    inner.extend_from_slice(data);
    let ct = aead_seal(&epoch_key.key, &nonce, &inner, &blob);
    blob.extend_from_slice(&ct);
    Ok(SealedBatch {
        ciphertext_commitment: sha3_256(&[&blob]).to_vec(),
        plaintext_commitment: batch_plaintext_commitment(&commit_salt, data),
        blob,
        epoch: epoch_key.epoch,
        batch_index,
    })
}

/// Encrypt batch data under an epoch key. `context` names the batch stream, for example the rollup id.
pub fn seal_batch(
    epoch_key: &EpochKey,
    context: &str,
    batch_index: u64,
    data: &[u8],
) -> Result<SealedBatch> {
    seal_batch_with(epoch_key, context, batch_index, data, &mut SystemEntropy)
}

/// Read a batch blob's header without decrypting it.
pub fn parse_batch_header(blob: &[u8]) -> Result<BatchHeader> {
    if blob.len() < 6 || blob[..4] != BATCH_MAGIC {
        return Err(Error::MalformedBatch("not a QoreSeal batch".into()));
    }
    if blob[4] != BATCH_VERSION {
        return Err(Error::UnsupportedVersion(format!(
            "unsupported batch version {}",
            blob[4]
        )));
    }
    if blob[5] != AEAD_AES_256_GCM {
        return Err(Error::UnsupportedAlgorithm(
            "unsupported batch cipher".into(),
        ));
    }
    if blob.len() < 23 {
        return Err(Error::MalformedBatch("truncated batch".into()));
    }
    let c = usize::from(blob[22]);
    let header_length = 23 + c + NONCE_LENGTH;
    if c == 0 || c > 128 || blob.len() < header_length + COMMIT_SALT_LENGTH + TAG_LENGTH {
        return Err(Error::MalformedBatch("truncated batch".into()));
    }
    let context = std::str::from_utf8(&blob[23..23 + c])
        .ok()
        .filter(|s| check_purpose(s).is_ok())
        .ok_or_else(|| Error::MalformedBatch("invalid batch context".into()))?
        .to_owned();
    Ok(BatchHeader {
        epoch: u64::from_be_bytes(blob[6..14].try_into().expect("8 bytes")),
        batch_index: u64::from_be_bytes(blob[14..22].try_into().expect("8 bytes")),
        context,
        nonce: blob[23 + c..header_length].to_vec(),
        header_length,
    })
}

/// Decrypt a batch blob; `key_for` returns the key of an epoch, if known.
pub fn open_batch(blob: &[u8], key_for: impl Fn(u64) -> Option<Vec<u8>>) -> Result<OpenedBatch> {
    let h = parse_batch_header(blob)?;
    let key = key_for(h.epoch)
        .ok_or_else(|| Error::UnknownEpoch(format!("no key for epoch {}", h.epoch)))?;
    require_len(&key, DATA_KEY_LENGTH, "epoch key")?;
    let inner = aead_open(
        &key,
        &h.nonce,
        &blob[h.header_length..],
        &blob[..h.header_length],
    )
    .ok_or_else(|| {
        Error::DecryptionFailed("the batch does not authenticate under the key of its epoch".into())
    })?;
    let (salt, data) = inner.split_at(COMMIT_SALT_LENGTH);
    Ok(OpenedBatch {
        epoch: h.epoch,
        batch_index: h.batch_index,
        context: h.context,
        ciphertext_commitment: sha3_256(&[blob]).to_vec(),
        plaintext_commitment: batch_plaintext_commitment(salt, data),
        data: data.to_vec(),
    })
}

/// Look a key up in a list of epoch keys.
pub fn keys_from_list(keys: &[EpochKey]) -> impl Fn(u64) -> Option<Vec<u8>> + '_ {
    move |epoch| {
        keys.iter()
            .find(|k| k.epoch == epoch)
            .map(|k| k.key.clone())
    }
}

/// [`seal_batch`] and [`open_batch`] bound to one context and an [`EpochKeyManager`].
#[derive(Debug)]
pub struct PrivateBatchCodec<'a> {
    pub context: String,
    manager: &'a EpochKeyManager,
}

impl<'a> PrivateBatchCodec<'a> {
    pub fn new(context: &str, manager: &'a EpochKeyManager) -> Result<Self> {
        check_purpose(context)
            .map_err(|_| Error::InvalidArgument(format!("invalid context {context:?}")))?;
        Ok(Self {
            context: context.to_owned(),
            manager,
        })
    }

    /// Seal under the current epoch key.
    pub fn seal(&self, batch_index: u64, data: &[u8]) -> Result<SealedBatch> {
        seal_batch(
            &self.manager.current_key(),
            &self.context,
            batch_index,
            data,
        )
    }

    pub fn open(&self, blob: &[u8]) -> Result<OpenedBatch> {
        let opened = open_batch(blob, |e| self.manager.key_for(e))?;
        if opened.context != self.context {
            return Err(Error::DecryptionFailed(format!(
                "the batch belongs to {}",
                opened.context
            )));
        }
        Ok(opened)
    }
}
