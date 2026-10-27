// SPDX-License-Identifier: Apache-2.0
//
// Private batch codec (spec section 8.2): batch data encrypted under the
// group's epoch key, with a ciphertext commitment and a salted plaintext
// commitment ready to anchor on QoreChain.

import { gcm } from "@noble/ciphers/aes.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { concat, equalBytes, readU64, requireBytes, u64, utf8 } from "./bytes.js";
import { AEAD_AES_256_GCM, BATCH_COMMITMENT_LABEL, checkPurpose, DATA_KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH } from "./constants.js";
import { systemEntropy, type Entropy } from "./envelope.js";
import { QoreSealError } from "./errors.js";
import { toU64, type EpochKey, type EpochKeyManager } from "./group.js";

export const BATCH_MAGIC = Uint8Array.of(0x51, 0x53, 0x42, 0x54); // "QSBT"
export const BATCH_VERSION = 1;
const COMMIT_SALT_LENGTH = 32;

export interface SealedBatch {
  /** The encrypted batch, to publish (for example as a data-availability blob). */
  blob: Uint8Array;
  epoch: bigint;
  batchIndex: bigint;
  /** SHA3-256 of the blob. */
  ciphertextCommitment: Uint8Array;
  /** Salted SHA3-256 of the batch data; members can recompute it after decrypting. */
  plaintextCommitment: Uint8Array;
}

export interface OpenedBatch extends SealedBatch {
  context: string;
  data: Uint8Array;
}

export interface BatchHeader {
  epoch: bigint;
  batchIndex: bigint;
  context: string;
  nonce: Uint8Array;
  headerLength: number;
}

/** Size of a batch blob: `83 + context length + data length`. */
export function batchSize(contextLength: number, dataLength: number): number {
  return 35 + contextLength + COMMIT_SALT_LENGTH + dataLength + TAG_LENGTH;
}

export function batchPlaintextCommitment(commitSalt: Uint8Array, data: Uint8Array): Uint8Array {
  return sha3_256(concat(utf8(BATCH_COMMITMENT_LABEL), commitSalt, data));
}

/** @internal */
export function sealBatchWith(
  args: { epochKey: EpochKey; context: string; batchIndex: bigint | number; data: Uint8Array },
  entropy: Entropy,
): SealedBatch {
  checkPurpose(args.context, "context");
  const epoch = toU64(args.epochKey.epoch, "epoch");
  if (epoch === 0n) throw new QoreSealError("INVALID_ARGUMENT", "epochs start at 1");
  requireBytes(args.epochKey.key, DATA_KEY_LENGTH, "epoch key");
  const batchIndex = toU64(args.batchIndex, "batch index");
  requireBytes(args.data, undefined, "data");
  const ctx = utf8(args.context);
  const nonce = entropy.take(NONCE_LENGTH);
  const commitSalt = entropy.take(COMMIT_SALT_LENGTH);
  const header = concat(BATCH_MAGIC, Uint8Array.of(BATCH_VERSION, AEAD_AES_256_GCM), u64(epoch), u64(batchIndex), Uint8Array.of(ctx.length), ctx, nonce);
  const ciphertext = gcm(args.epochKey.key, nonce, header).encrypt(concat(commitSalt, args.data));
  const blob = concat(header, ciphertext);
  return {
    blob,
    epoch,
    batchIndex,
    ciphertextCommitment: sha3_256(blob),
    plaintextCommitment: batchPlaintextCommitment(commitSalt, args.data),
  };
}

/** Encrypt batch data under an epoch key. `context` names the batch stream, for example the rollup id. */
export function sealBatch(args: { epochKey: EpochKey; context: string; batchIndex: bigint | number; data: Uint8Array }): SealedBatch {
  return sealBatchWith(args, systemEntropy);
}

/** Read a batch blob's header without decrypting it. */
export function parseBatchHeader(blob: Uint8Array): BatchHeader {
  requireBytes(blob, undefined, "batch blob");
  if (blob.length < 6 || !equalBytes(blob.subarray(0, 4), BATCH_MAGIC)) throw new QoreSealError("MALFORMED_BATCH", "not a QoreSeal batch");
  if (blob[4] !== BATCH_VERSION) throw new QoreSealError("UNSUPPORTED_VERSION", `unsupported batch version ${blob[4]}`);
  if (blob[5] !== AEAD_AES_256_GCM) throw new QoreSealError("UNSUPPORTED_ALGORITHM", "unsupported batch cipher");
  if (blob.length < 23) throw new QoreSealError("MALFORMED_BATCH", "truncated batch");
  const c = blob[22] ?? 0;
  const headerLength = 23 + c + NONCE_LENGTH;
  if (c === 0 || c > 128 || blob.length < headerLength + COMMIT_SALT_LENGTH + TAG_LENGTH) {
    throw new QoreSealError("MALFORMED_BATCH", "truncated batch");
  }
  const context = new TextDecoder().decode(blob.subarray(23, 23 + c));
  try {
    checkPurpose(context, "context");
  } catch {
    throw new QoreSealError("MALFORMED_BATCH", "invalid batch context");
  }
  return {
    epoch: readU64(blob, 6),
    batchIndex: readU64(blob, 14),
    context,
    nonce: blob.slice(23 + c, headerLength),
    headerLength,
  };
}

export type EpochKeySource = EpochKey[] | EpochKeyManager | ((epoch: bigint) => Uint8Array | undefined);

function lookup(source: EpochKeySource, epoch: bigint): Uint8Array | undefined {
  if (typeof source === "function") return source(epoch);
  if (Array.isArray(source)) return source.find((k) => k.epoch === epoch)?.key;
  return source.keyFor(epoch);
}

/** Decrypt a batch blob with the key of its epoch. */
export function openBatch(args: { blob: Uint8Array; keys: EpochKeySource }): OpenedBatch {
  const h = parseBatchHeader(args.blob);
  const key = lookup(args.keys, h.epoch);
  if (!key) throw new QoreSealError("UNKNOWN_EPOCH", `no key for epoch ${h.epoch}`);
  requireBytes(key, DATA_KEY_LENGTH, "epoch key");
  let inner: Uint8Array;
  try {
    inner = gcm(key, h.nonce, args.blob.subarray(0, h.headerLength)).decrypt(args.blob.subarray(h.headerLength));
  } catch {
    throw new QoreSealError("DECRYPTION_FAILED", "the batch does not authenticate under the key of its epoch");
  }
  const commitSalt = inner.subarray(0, COMMIT_SALT_LENGTH);
  const data = inner.slice(COMMIT_SALT_LENGTH);
  return {
    blob: args.blob,
    epoch: h.epoch,
    batchIndex: h.batchIndex,
    context: h.context,
    data,
    ciphertextCommitment: sha3_256(args.blob),
    plaintextCommitment: batchPlaintextCommitment(commitSalt, data),
  };
}

/** {@link sealBatch} and {@link openBatch} bound to one context and key source. */
export class PrivateBatchCodec {
  constructor(
    readonly context: string,
    private readonly keys: EpochKeyManager | { currentKey: EpochKey; keyFor(epoch: bigint): Uint8Array | undefined },
  ) {
    checkPurpose(context, "context");
  }

  /** Seal under the current epoch key. */
  seal(batchIndex: bigint | number, data: Uint8Array): SealedBatch {
    return sealBatch({ epochKey: this.keys.currentKey, context: this.context, batchIndex, data });
  }

  open(blob: Uint8Array): OpenedBatch {
    const opened = openBatch({ blob, keys: (e) => this.keys.keyFor(e) });
    if (opened.context !== this.context) throw new QoreSealError("DECRYPTION_FAILED", `the batch belongs to ${opened.context}`);
    return opened;
  }
}
