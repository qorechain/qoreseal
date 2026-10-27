// SPDX-License-Identifier: Apache-2.0

use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

use crate::errors::{Error, Result};

pub(crate) fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    // Lengths used here are far below the HKDF limit of 255 * 32 bytes.
    hk.expand(info, &mut out).expect("HKDF output length");
    out
}

/// Constant-time comparison of equal-length byte strings.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

pub(crate) fn is_all_zero(b: &[u8]) -> bool {
    b.iter().fold(0u8, |d, x| d | x) == 0
}

pub(crate) fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    getrandom::getrandom(&mut out).expect("the operating system random number generator failed");
    out
}

pub(crate) fn require_len(b: &[u8], len: usize, what: &str) -> Result<()> {
    if b.len() == len {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "{what} must be {len} bytes, got {}",
            b.len()
        )))
    }
}

pub(crate) fn require_key_len(b: &[u8], len: usize, what: &str) -> Result<()> {
    if b.len() == len {
        Ok(())
    } else {
        Err(Error::InvalidKey(format!(
            "{what} must be {len} bytes, got {}",
            b.len()
        )))
    }
}

/// Source of the randomness a seal consumes (spec section 9).
pub(crate) trait Entropy {
    fn deterministic(&self) -> bool;
    fn take(&mut self, n: usize) -> Result<Vec<u8>>;
}

pub(crate) struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn deterministic(&self) -> bool {
        false
    }
    fn take(&mut self, n: usize) -> Result<Vec<u8>> {
        Ok(random_bytes(n))
    }
}

/// Exact byte stream for the test vectors.
pub(crate) struct StreamEntropy<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) off: usize,
}

impl Entropy for StreamEntropy<'_> {
    fn deterministic(&self) -> bool {
        true
    }
    fn take(&mut self, n: usize) -> Result<Vec<u8>> {
        if self.off + n > self.bytes.len() {
            return Err(Error::InvalidArgument("not enough test entropy".into()));
        }
        let out = self.bytes[self.off..self.off + n].to_vec();
        self.off += n;
        Ok(out)
    }
}

impl StreamEntropy<'_> {
    pub(crate) fn done(&self) -> Result<()> {
        if self.off == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::InvalidArgument(
                "test entropy has unused bytes".into(),
            ))
        }
    }
}
