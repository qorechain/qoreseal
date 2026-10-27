// SPDX-License-Identifier: Apache-2.0
//
// QoreSeal key pairs: an ML-KEM-1024 key pair and an X25519 key pair derived
// from one 32-byte seed (spec section 4).

import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { mlkem1024 } from "@qorechain/pqc";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { isAllZero, requireBytes, utf8 } from "./bytes.js";
import {
  KEYS_LABEL_MLKEM,
  KEYS_LABEL_X25519,
  ML_KEM_1024_PUBLIC_KEY_LENGTH,
  ML_KEM_1024_SECRET_KEY_LENGTH,
  MNEMONIC_LABEL,
  SEED_LENGTH,
  X25519_KEY_LENGTH,
} from "./constants.js";
import { QoreSealError } from "./errors.js";

/** A recipient's keys. Keep `seed` (or the mnemonic it came from) secret and backed up. */
export interface SealKeyPair {
  /** 32-byte seed both key pairs derive from. */
  seed: Uint8Array;
  /** ML-KEM-1024 encapsulation key (1568 bytes): the key registered on chain. */
  mlkemPublicKey: Uint8Array;
  /** ML-KEM-1024 decapsulation key (3168 bytes). */
  mlkemSecretKey: Uint8Array;
  /** X25519 public key (32 bytes), published in a recipient card. */
  x25519PublicKey: Uint8Array;
  /** X25519 secret key (32 bytes). */
  x25519SecretKey: Uint8Array;
}

/** What a sender needs to seal to someone. `x25519PublicKey` is required by the hybrid mode. */
export interface SealRecipient {
  mlkemPublicKey: Uint8Array;
  x25519PublicKey?: Uint8Array;
}

/** Derive both key pairs from a 32-byte seed. */
export function sealKeysFromSeed(seed: Uint8Array): SealKeyPair {
  requireBytes(seed, SEED_LENGTH, "seed");
  const mlkemSeed = hkdf(sha256, seed, new Uint8Array(0), utf8(KEYS_LABEL_MLKEM), 64);
  const kem = mlkem1024.keygen(mlkemSeed);
  const x25519SecretKey = hkdf(sha256, seed, new Uint8Array(0), utf8(KEYS_LABEL_X25519), 32);
  return {
    seed: Uint8Array.from(seed),
    mlkemPublicKey: kem.publicKey,
    mlkemSecretKey: kem.secretKey,
    x25519PublicKey: x25519.getPublicKey(x25519SecretKey),
    x25519SecretKey,
  };
}

/** New key pairs from a fresh random seed. */
export function generateSealKeys(): SealKeyPair {
  return sealKeysFromSeed(randomBytes(SEED_LENGTH));
}

/** The 32-byte seed for `index` derived from a BIP-39 mnemonic (spec section 4). */
export function sealSeedFromMnemonic(args: { mnemonic: string; passphrase?: string; index?: number }): Uint8Array {
  const index = args.index ?? 0;
  if (!Number.isInteger(index) || index < 0 || index > 0x7fffffff) {
    throw new QoreSealError("INVALID_ARGUMENT", `index must be an integer from 0 to 2^31-1, got ${index}`);
  }
  const mnemonic = args.mnemonic.normalize("NFKD").trim().split(/\s+/).join(" ");
  if (!validateMnemonic(mnemonic, wordlist)) throw new QoreSealError("INVALID_ARGUMENT", "invalid BIP-39 mnemonic");
  const bip39Seed = mnemonicToSeedSync(mnemonic, args.passphrase ?? "");
  return hkdf(sha256, bip39Seed, new Uint8Array(0), utf8(`${MNEMONIC_LABEL}${index}`), SEED_LENGTH);
}

/** Key pairs derived from a BIP-39 mnemonic. Move to the next `index` to rotate. */
export function deriveSealKeys(args: { mnemonic: string; passphrase?: string; index?: number }): SealKeyPair {
  return sealKeysFromSeed(sealSeedFromMnemonic(args));
}

/** The public half of a key pair, as a recipient. */
export function recipientOf(keys: Pick<SealKeyPair, "mlkemPublicKey" | "x25519PublicKey">): SealRecipient {
  return { mlkemPublicKey: keys.mlkemPublicKey, x25519PublicKey: keys.x25519PublicKey };
}

/**
 * The checks the chain applies to a registered key: 1568 bytes, every 12-bit
 * coefficient of t_hat below 3329 (FIPS 203 modulus check), t_hat not all
 * zero. Throws `INVALID_KEY`.
 */
export function validateMlkemPublicKey(publicKey: Uint8Array): void {
  requireBytes(publicKey, ML_KEM_1024_PUBLIC_KEY_LENGTH, "ML-KEM-1024 public key", "INVALID_KEY");
  let nonZero = false;
  for (let i = 0; i < 1536; i += 3) {
    const b0 = publicKey[i] ?? 0;
    const b1 = publicKey[i + 1] ?? 0;
    const b2 = publicKey[i + 2] ?? 0;
    const c0 = b0 | ((b1 & 0x0f) << 8);
    const c1 = (b1 >> 4) | (b2 << 4);
    if (c0 >= 3329 || c1 >= 3329) {
      throw new QoreSealError("INVALID_KEY", "the ML-KEM-1024 public key fails the FIPS 203 modulus check");
    }
    if (c0 !== 0 || c1 !== 0) nonZero = true;
  }
  if (!nonZero) throw new QoreSealError("INVALID_KEY", "the ML-KEM-1024 public key is degenerate (t_hat is zero)");
}

export function validateX25519PublicKey(publicKey: Uint8Array): void {
  requireBytes(publicKey, X25519_KEY_LENGTH, "X25519 public key", "INVALID_KEY");
  if (isAllZero(publicKey)) throw new QoreSealError("INVALID_KEY", "the X25519 public key is zero");
}

export function checkKeyPair(keys: SealKeyPair): void {
  requireBytes(keys.mlkemSecretKey, ML_KEM_1024_SECRET_KEY_LENGTH, "ML-KEM-1024 secret key", "INVALID_KEY");
  requireBytes(keys.mlkemPublicKey, ML_KEM_1024_PUBLIC_KEY_LENGTH, "ML-KEM-1024 public key", "INVALID_KEY");
  requireBytes(keys.x25519SecretKey, X25519_KEY_LENGTH, "X25519 secret key", "INVALID_KEY");
}
