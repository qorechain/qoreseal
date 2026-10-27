// SPDX-License-Identifier: Apache-2.0
//
// Building blocks of an envelope entry: encapsulation, the hybrid combiner,
// the key-encryption key and the recipient hint (spec sections 3 and 5.2).

import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { mlkem1024 } from "@qorechain/pqc";
import { concat, isAllZero, requireBytes, utf8 } from "./bytes.js";
import {
  checkChainId,
  checkPurpose,
  HINT_LABEL,
  HINT_LENGTH,
  HYBRID_LABEL,
  KDF_INFO_PREFIX,
  ML_KEM_1024_CIPHERTEXT_LENGTH,
  ML_KEM_1024_SECRET_KEY_LENGTH,
  X25519_KEY_LENGTH,
} from "./constants.js";
import { QoreSealError } from "./errors.js";
import { validateMlkemPublicKey } from "./keys.js";

/** `"qorechain-kem-v1|" + chainId + "|" + purpose`, the HKDF info of every key-encryption key. */
export function kdfInfo(chainId: string, purpose: string): string {
  checkChainId(chainId);
  checkPurpose(purpose);
  return `${KDF_INFO_PREFIX}${chainId}|${purpose}`;
}

/** HKDF-SHA-256 of a shared secret into a 32-byte key bound to the chain and purpose. */
export function deriveKey(args: { shared: Uint8Array; chainId: string; purpose: string; salt?: Uint8Array }): Uint8Array {
  requireBytes(args.shared, 32, "shared secret");
  const info = utf8(kdfInfo(args.chainId, args.purpose));
  return hkdf(sha256, args.shared, args.salt ?? new Uint8Array(0), info, 32);
}

/**
 * ML-KEM-1024 encapsulation to a validated key. `m` is only for test vectors
 * (FIPS 203 ML-KEM.Encaps_internal); production calls leave it out.
 */
export function mlkemEncapsulate(publicKey: Uint8Array, m?: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array } {
  validateMlkemPublicKey(publicKey);
  if (m === undefined) return mlkem1024.encapsulate(publicKey);
  requireBytes(m, 32, "encapsulation randomness");
  return ml_kem1024.encapsulate(publicKey, m);
}

export function mlkemDecapsulate(secretKey: Uint8Array, cipherText: Uint8Array): Uint8Array {
  requireBytes(secretKey, ML_KEM_1024_SECRET_KEY_LENGTH, "ML-KEM-1024 secret key", "INVALID_KEY");
  requireBytes(cipherText, ML_KEM_1024_CIPHERTEXT_LENGTH, "ML-KEM-1024 ciphertext");
  return mlkem1024.decapsulate(secretKey, cipherText);
}

/** X25519 agreement; throws `INVALID_KEY` on an all-zero result (low-order public key). */
export function x25519Agree(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  requireBytes(secretKey, X25519_KEY_LENGTH, "X25519 secret key", "INVALID_KEY");
  requireBytes(publicKey, X25519_KEY_LENGTH, "X25519 public key", "INVALID_KEY");
  let out: Uint8Array;
  try {
    out = x25519.getSharedSecret(secretKey, publicKey);
  } catch {
    throw new QoreSealError("INVALID_KEY", "X25519 agreement gave the zero point (low-order public key)");
  }
  if (isAllZero(out)) throw new QoreSealError("INVALID_KEY", "X25519 agreement gave the zero point (low-order public key)");
  return out;
}

export function x25519PublicKey(secretKey: Uint8Array): Uint8Array {
  requireBytes(secretKey, X25519_KEY_LENGTH, "X25519 secret key", "INVALID_KEY");
  return x25519.getPublicKey(secretKey);
}

/** `SHA3-256("qorechain-qoreseal-hybrid-v1" || ssMlkem || ssX25519 || ctX25519 || pkX25519)`. */
export function hybridSharedSecret(args: {
  mlkemSharedSecret: Uint8Array;
  x25519SharedSecret: Uint8Array;
  x25519Ciphertext: Uint8Array;
  x25519PublicKey: Uint8Array;
}): Uint8Array {
  requireBytes(args.mlkemSharedSecret, 32, "ML-KEM shared secret");
  requireBytes(args.x25519SharedSecret, 32, "X25519 shared secret");
  requireBytes(args.x25519Ciphertext, 32, "X25519 ephemeral public key");
  requireBytes(args.x25519PublicKey, 32, "X25519 public key");
  return sha3_256(
    concat(utf8(HYBRID_LABEL), args.mlkemSharedSecret, args.x25519SharedSecret, args.x25519Ciphertext, args.x25519PublicKey),
  );
}

/** `SHA3-256("qorechain-qoreseal-hint-v1" || salt || mlkemPublicKey)[0..16]`. */
export function recipientHint(salt: Uint8Array, mlkemPublicKey: Uint8Array): Uint8Array {
  return sha3_256(concat(utf8(HINT_LABEL), salt, mlkemPublicKey)).slice(0, HINT_LENGTH);
}
