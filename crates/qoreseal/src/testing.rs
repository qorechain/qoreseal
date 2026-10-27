// SPDX-License-Identifier: Apache-2.0
//
// Deterministic entry points for the shared test vectors (spec section 9).
// Never use them with real data: the same entropy gives the same ciphertexts
// and exposes the data keys.

use crate::batch::{seal_batch_with, SealedBatch};
use crate::constants::SealMode;
use crate::envelope::{seal_with, SealArgs};
use crate::errors::Result;
use crate::group::EpochKey;
use crate::kem::{mlkem_encapsulate_derand, Encapsulation};
use crate::util::StreamEntropy;

/// Bytes of entropy a seal consumes: 60 + 32 per recipient (64 in hybrid mode).
pub fn seal_entropy_length(mode: SealMode, recipients: usize) -> usize {
    60 + recipients
        * match mode {
            SealMode::Hybrid => 64,
            SealMode::Mlkem => 32,
        }
}

/// [`crate::seal`] with all of its randomness given. For test vectors only.
pub fn seal_with_entropy(args: &SealArgs<'_>, entropy: &[u8]) -> Result<Vec<u8>> {
    let mut s = StreamEntropy {
        bytes: entropy,
        off: 0,
    };
    let out = seal_with(args, &mut s)?;
    s.done()?;
    Ok(out)
}

/// [`crate::seal_batch`] with its nonce (12) and commitment salt (32) given. For test vectors only.
pub fn seal_batch_with_entropy(
    epoch_key: &EpochKey,
    context: &str,
    batch_index: u64,
    data: &[u8],
    entropy: &[u8],
) -> Result<SealedBatch> {
    let mut s = StreamEntropy {
        bytes: entropy,
        off: 0,
    };
    let out = seal_batch_with(epoch_key, context, batch_index, data, &mut s)?;
    s.done()?;
    Ok(out)
}

/// FIPS 203 ML-KEM.Encaps_internal with explicit randomness. For test vectors only.
pub fn mlkem_encapsulate_with_randomness(public_key: &[u8], m: &[u8]) -> Result<Encapsulation> {
    mlkem_encapsulate_derand(public_key, m)
}
