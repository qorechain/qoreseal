// SPDX-License-Identifier: Apache-2.0
//
// Wire constants of QoreSeal v1 (spec/qoreseal-v1.md).

import { QoreSealError } from "./errors.js";

/** Algorithm id of ML-KEM-1024 in the chain's KEM key registry and in envelopes. */
export const ALGORITHM_ML_KEM_1024 = 2;
export const ML_KEM_1024_PUBLIC_KEY_LENGTH = 1568;
export const ML_KEM_1024_SECRET_KEY_LENGTH = 3168;
export const ML_KEM_1024_CIPHERTEXT_LENGTH = 1568;
export const X25519_KEY_LENGTH = 32;
export const SEED_LENGTH = 32;

export const ENVELOPE_VERSION = 1;
export const ENVELOPE_MAGIC = Uint8Array.of(0x51, 0x53, 0x45, 0x4c); // "QSEL"
export const ENVELOPE_TEXT_PREFIX = "qoreseal:";
export const MODE_HYBRID = 0x01;
export const MODE_MLKEM = 0x02;
export const KDF_HKDF_SHA256 = 0x01;
export const AEAD_AES_256_GCM = 0x01;
export const FLAG_ANONYMOUS = 0x01;
export const FIXED_HEADER_LENGTH = 28;
export const SALT_LENGTH = 16;
export const HINT_LENGTH = 16;
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;
export const DATA_KEY_LENGTH = 32;
export const WRAPPED_KEY_LENGTH = DATA_KEY_LENGTH + TAG_LENGTH;
export const MAX_RECIPIENTS = 1024;
/** Size of one recipient entry. */
export const ENTRY_LENGTH = { hybrid: 1664, mlkem: 1632 } as const;

/** `"qorechain-kem-v1|"`: prefix of the HKDF info of every key-encryption key. */
export const KDF_INFO_PREFIX = "qorechain-kem-v1|";
export const HYBRID_LABEL = "qorechain-qoreseal-hybrid-v1";
export const HINT_LABEL = "qorechain-qoreseal-hint-v1";
export const KEYS_LABEL_MLKEM = "qorechain-qoreseal-keys-v1|ml-kem-1024";
export const KEYS_LABEL_X25519 = "qorechain-qoreseal-keys-v1|x25519";
export const MNEMONIC_LABEL = "qorechain-qoreseal-mnemonic-v1|";
export const BATCH_COMMITMENT_LABEL = "qorechain-qoreseal-batch-v1";

/** `hybrid` (default): ML-KEM-1024 plus X25519. `mlkem`: ML-KEM-1024 only. */
export type SealMode = "hybrid" | "mlkem";

const CHAIN_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const PURPOSE_RE = /^[A-Za-z0-9._:/-]{1,128}$/;

export function checkChainId(chainId: string): void {
  if (typeof chainId !== "string" || !CHAIN_ID_RE.test(chainId)) {
    throw new QoreSealError("INVALID_ARGUMENT", `invalid chain id ${JSON.stringify(chainId)}`);
  }
}

export function checkPurpose(purpose: string, what = "purpose"): void {
  if (typeof purpose !== "string" || !PURPOSE_RE.test(purpose)) {
    throw new QoreSealError("INVALID_ARGUMENT", `invalid ${what} ${JSON.stringify(purpose)}`);
  }
}

export function modeByte(mode: SealMode): number {
  if (mode === "hybrid") return MODE_HYBRID;
  if (mode === "mlkem") return MODE_MLKEM;
  throw new QoreSealError("INVALID_ARGUMENT", `unknown mode ${JSON.stringify(mode)}`);
}
