// SPDX-License-Identifier: Apache-2.0
//
// Epoch keys for private groups and sidechains (spec section 8.1): one shared
// 32-byte key per epoch, replaced and sealed to the current members on every
// membership change.

use std::collections::BTreeMap;
use std::fmt;

use crate::constants::{SealMode, DATA_KEY_LENGTH, MAX_RECIPIENTS};
use crate::envelope::{open, seal_with, SealArgs};
use crate::errors::{Error, Result};
use crate::keys::{validate_mlkem_public_key, SealKeyPair, SealRecipient};
use crate::util::{require_len, Entropy, SystemEntropy};

/// `"QSEK"`.
pub const EPOCH_KEY_MAGIC: [u8; 4] = *b"QSEK";
pub const EPOCH_KEY_VERSION: u8 = 1;
pub const EPOCH_KEY_PAYLOAD_LENGTH: usize = 45;

/// An epoch number (from 1) and its 32-byte key.
#[derive(Clone, PartialEq, Eq)]
pub struct EpochKey {
    pub epoch: u64,
    pub key: Vec<u8>,
}

impl fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpochKey")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// The 45-byte payload that carries an epoch key inside an envelope.
pub fn encode_epoch_key(k: &EpochKey) -> Result<Vec<u8>> {
    if k.epoch == 0 {
        return Err(Error::InvalidArgument("epochs start at 1".into()));
    }
    require_len(&k.key, DATA_KEY_LENGTH, "epoch key")?;
    let mut out = Vec::with_capacity(EPOCH_KEY_PAYLOAD_LENGTH);
    out.extend_from_slice(&EPOCH_KEY_MAGIC);
    out.push(EPOCH_KEY_VERSION);
    out.extend_from_slice(&k.epoch.to_be_bytes());
    out.extend_from_slice(&k.key);
    Ok(out)
}

pub fn decode_epoch_key(payload: &[u8]) -> Result<EpochKey> {
    if payload.len() != EPOCH_KEY_PAYLOAD_LENGTH || payload[..4] != EPOCH_KEY_MAGIC {
        return Err(Error::MalformedEnvelope(
            "the envelope does not carry an epoch key".into(),
        ));
    }
    if payload[4] != EPOCH_KEY_VERSION {
        return Err(Error::UnsupportedVersion(format!(
            "unsupported epoch key version {}",
            payload[4]
        )));
    }
    let epoch = u64::from_be_bytes(payload[5..13].try_into().expect("8 bytes"));
    if epoch == 0 {
        return Err(Error::MalformedEnvelope("epoch 0 is not valid".into()));
    }
    Ok(EpochKey {
        epoch,
        key: payload[13..].to_vec(),
    })
}

/// Seal an epoch key to the members of a group.
pub fn seal_epoch_key(
    chain_id: &str,
    purpose: &str,
    epoch_key: &EpochKey,
    recipients: &[SealRecipient],
    mode: SealMode,
) -> Result<Vec<u8>> {
    let payload = encode_epoch_key(epoch_key)?;
    let mut args = SealArgs::new(chain_id, purpose, recipients, &payload);
    args.mode = mode;
    seal_with(&args, &mut SystemEntropy)
}

/// Open an epoch key sealed with [`seal_epoch_key`] or by an [`EpochKeyManager`].
pub fn open_epoch_key(
    chain_id: &str,
    purpose: &str,
    envelope: &[u8],
    keys: &SealKeyPair,
) -> Result<EpochKey> {
    decode_epoch_key(&open(chain_id, purpose, envelope, keys, &[])?)
}

/// What a membership change produced: the new epoch and its key sealed to the current members.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRotation {
    pub epoch: u64,
    /// Envelope for the members; `None` when the group has no members left.
    pub envelope: Option<Vec<u8>>,
    pub members: Vec<String>,
}

/// Keeps the epoch keys of a group on the operator's side. Every membership
/// change starts a new epoch with a fresh random key; removed members cannot
/// read later epochs, new members cannot read earlier ones.
pub struct EpochKeyManager {
    chain_id: String,
    purpose: String,
    mode: SealMode,
    members: Vec<(String, SealRecipient)>,
    keys: BTreeMap<u64, Vec<u8>>,
    current: u64,
}

impl fmt::Debug for EpochKeyManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpochKeyManager")
            .field("purpose", &self.purpose)
            .field("epoch", &self.current)
            .field("members", &self.members())
            .finish_non_exhaustive()
    }
}

impl EpochKeyManager {
    /// A manager at epoch 1 (or at the last epoch of `history`, oldest first).
    pub fn new(
        chain_id: &str,
        purpose: &str,
        mode: SealMode,
        members: Vec<(String, SealRecipient)>,
        history: Vec<EpochKey>,
    ) -> Result<Self> {
        crate::constants::check_chain_id(chain_id)?;
        crate::constants::check_purpose(purpose)?;
        let mut m = Self {
            chain_id: chain_id.to_owned(),
            purpose: purpose.to_owned(),
            mode,
            members: Vec::new(),
            keys: BTreeMap::new(),
            current: 0,
        };
        for (id, r) in members {
            m.set_member(&id, r)?;
        }
        for k in history {
            require_len(&k.key, DATA_KEY_LENGTH, "epoch key")?;
            if k.epoch <= m.current {
                return Err(Error::InvalidArgument(
                    "history must be in increasing epoch order".into(),
                ));
            }
            m.current = k.epoch;
            m.keys.insert(k.epoch, k.key);
        }
        if m.current == 0 {
            m.new_epoch(&mut SystemEntropy)?;
        }
        Ok(m)
    }

    fn set_member(&mut self, id: &str, r: SealRecipient) -> Result<()> {
        if id.is_empty() {
            return Err(Error::InvalidArgument(
                "member id must be a non-empty string".into(),
            ));
        }
        validate_mlkem_public_key(&r.mlkem_public_key)?;
        if self.mode == SealMode::Hybrid && r.x25519_public_key.is_none() {
            return Err(Error::RecipientNeedsX25519(format!(
                "member {id} has no X25519 key; use SealMode::Mlkem or a recipient card"
            )));
        }
        if let Some(slot) = self.members.iter_mut().find(|(m, _)| m == id) {
            slot.1 = r;
            return Ok(());
        }
        if self.members.len() >= MAX_RECIPIENTS {
            return Err(Error::InvalidArgument(format!(
                "a group has at most {MAX_RECIPIENTS} members"
            )));
        }
        self.members.push((id.to_owned(), r));
        Ok(())
    }

    fn new_epoch(&mut self, entropy: &mut dyn Entropy) -> Result<()> {
        self.current += 1;
        let key = entropy.take(DATA_KEY_LENGTH)?;
        self.keys.insert(self.current, key);
        Ok(())
    }

    /// The current epoch number.
    pub fn epoch(&self) -> u64 {
        self.current
    }

    pub fn current_key(&self) -> EpochKey {
        EpochKey {
            epoch: self.current,
            key: self.keys[&self.current].clone(),
        }
    }

    /// The key of an epoch this manager knows.
    pub fn key_for(&self, epoch: u64) -> Option<Vec<u8>> {
        self.keys.get(&epoch).cloned()
    }

    /// Every epoch key, oldest first. Store it encrypted: it opens every batch of the group.
    pub fn export_keys(&self) -> Vec<EpochKey> {
        self.keys
            .iter()
            .map(|(epoch, key)| EpochKey {
                epoch: *epoch,
                key: key.clone(),
            })
            .collect()
    }

    pub fn members(&self) -> Vec<String> {
        self.members.iter().map(|(id, _)| id.clone()).collect()
    }

    /// The current epoch key sealed to the current members.
    pub fn distribution(&self) -> Result<Vec<u8>> {
        if self.members.is_empty() {
            return Err(Error::InvalidArgument("the group has no members".into()));
        }
        let recipients: Vec<SealRecipient> = self.members.iter().map(|(_, r)| r.clone()).collect();
        seal_epoch_key(
            &self.chain_id,
            &self.purpose,
            &self.current_key(),
            &recipients,
            self.mode,
        )
    }

    fn rotation(&self) -> Result<EpochRotation> {
        Ok(EpochRotation {
            epoch: self.current,
            envelope: if self.members.is_empty() {
                None
            } else {
                Some(self.distribution()?)
            },
            members: self.members(),
        })
    }

    /// Start a new epoch without a membership change (for example on a schedule).
    pub fn rotate(&mut self) -> Result<EpochRotation> {
        self.new_epoch(&mut SystemEntropy)?;
        self.rotation()
    }

    /// Add or replace a member and start a new epoch.
    pub fn add_member(&mut self, id: &str, recipient: SealRecipient) -> Result<EpochRotation> {
        self.set_member(id, recipient)?;
        self.rotate()
    }

    /// Remove a member and start a new epoch it cannot read.
    pub fn remove_member(&mut self, id: &str) -> Result<EpochRotation> {
        let before = self.members.len();
        self.members.retain(|(m, _)| m != id);
        if self.members.len() == before {
            return Err(Error::InvalidArgument(format!("no member {id:?}")));
        }
        self.rotate()
    }
}
