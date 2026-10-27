// SPDX-License-Identifier: Apache-2.0
//
// Epoch keys for private groups and sidechains (spec section 8.1): one shared
// 32-byte key per epoch, replaced and sealed to the current members on every
// membership change.

import { concat, equalBytes, readU64, requireBytes, u64 } from "./bytes.js";
import { DATA_KEY_LENGTH, MAX_RECIPIENTS, type SealMode } from "./constants.js";
import { systemEntropy, open, sealWith, type Entropy } from "./envelope.js";
import { QoreSealError } from "./errors.js";
import { validateMlkemPublicKey, type SealKeyPair, type SealRecipient } from "./keys.js";

export const EPOCH_KEY_MAGIC = Uint8Array.of(0x51, 0x53, 0x45, 0x4b); // "QSEK"
export const EPOCH_KEY_VERSION = 1;
export const EPOCH_KEY_PAYLOAD_LENGTH = 45;
const MAX_U64 = (1n << 64n) - 1n;

/** An epoch number (from 1) and its 32-byte key. */
export interface EpochKey {
  epoch: bigint;
  key: Uint8Array;
}

export function toU64(v: bigint | number, what: string): bigint {
  const n = typeof v === "number" ? (Number.isSafeInteger(v) ? BigInt(v) : -1n) : v;
  if (typeof n !== "bigint" || n < 0n || n > MAX_U64) throw new QoreSealError("INVALID_ARGUMENT", `${what} must be an unsigned 64-bit integer`);
  return n;
}

/** The 45-byte payload that carries an epoch key inside an envelope. */
export function encodeEpochKey(k: EpochKey): Uint8Array {
  const epoch = toU64(k.epoch, "epoch");
  if (epoch === 0n) throw new QoreSealError("INVALID_ARGUMENT", "epochs start at 1");
  requireBytes(k.key, DATA_KEY_LENGTH, "epoch key");
  return concat(EPOCH_KEY_MAGIC, Uint8Array.of(EPOCH_KEY_VERSION), u64(epoch), k.key);
}

export function decodeEpochKey(payload: Uint8Array): EpochKey {
  if (payload.length !== EPOCH_KEY_PAYLOAD_LENGTH || !equalBytes(payload.subarray(0, 4), EPOCH_KEY_MAGIC)) {
    throw new QoreSealError("MALFORMED_ENVELOPE", "the envelope does not carry an epoch key");
  }
  if (payload[4] !== EPOCH_KEY_VERSION) throw new QoreSealError("UNSUPPORTED_VERSION", `unsupported epoch key version ${payload[4]}`);
  const epoch = readU64(payload, 5);
  if (epoch === 0n) throw new QoreSealError("MALFORMED_ENVELOPE", "epoch 0 is not valid");
  return { epoch, key: payload.slice(13, 45) };
}

/** Seal an epoch key to the members of a group. */
export function sealEpochKey(args: {
  chainId: string;
  purpose: string;
  epochKey: EpochKey;
  recipients: SealRecipient[];
  mode?: SealMode;
}): Uint8Array {
  return sealWith({ ...args, plaintext: encodeEpochKey(args.epochKey) }, systemEntropy);
}

/** Open an epoch key sealed with {@link sealEpochKey} or by an {@link EpochKeyManager}. */
export function openEpochKey(args: { chainId: string; purpose: string; envelope: Uint8Array; keys: SealKeyPair }): EpochKey {
  return decodeEpochKey(open(args));
}

/** What a membership change produced: the new epoch and its key sealed to the current members. */
export interface EpochRotation {
  epoch: bigint;
  /** Envelope for the members; null when the group has no members left. */
  envelope: Uint8Array | null;
  members: string[];
}

export interface EpochKeyManagerOptions {
  chainId: string;
  /** Envelope purpose, for example `epoch-key:my-rollup`. */
  purpose: string;
  mode?: SealMode;
  members?: Record<string, SealRecipient>;
  /** Keys of earlier epochs to restore (the last one is current). */
  history?: EpochKey[];
}

/**
 * Keeps the epoch keys of a group on the operator's side. Every membership
 * change starts a new epoch with a fresh random key; removed members cannot
 * read later epochs, new members cannot read earlier ones.
 */
export class EpochKeyManager {
  readonly chainId: string;
  readonly purpose: string;
  readonly mode: SealMode;
  private readonly memberKeys = new Map<string, SealRecipient>();
  private readonly keys = new Map<bigint, Uint8Array>();
  private current: bigint;
  private readonly entropy: Entropy;

  constructor(opts: EpochKeyManagerOptions, entropy: Entropy = systemEntropy) {
    this.chainId = opts.chainId;
    this.purpose = opts.purpose;
    this.mode = opts.mode ?? "hybrid";
    this.entropy = entropy;
    for (const [id, r] of Object.entries(opts.members ?? {})) this.setMember(id, r);
    this.current = 0n;
    for (const k of opts.history ?? []) {
      const epoch = toU64(k.epoch, "epoch");
      requireBytes(k.key, DATA_KEY_LENGTH, "epoch key");
      if (epoch <= this.current) throw new QoreSealError("INVALID_ARGUMENT", "history must be in increasing epoch order");
      this.keys.set(epoch, Uint8Array.from(k.key));
      this.current = epoch;
    }
    if (this.current === 0n) this.newEpoch();
  }

  private setMember(id: string, r: SealRecipient): void {
    if (typeof id !== "string" || id.length === 0) throw new QoreSealError("INVALID_ARGUMENT", "member id must be a non-empty string");
    validateMlkemPublicKey(r.mlkemPublicKey);
    if (this.mode === "hybrid" && !r.x25519PublicKey) {
      throw new QoreSealError("RECIPIENT_NEEDS_X25519", `member ${id} has no X25519 key; use mode 'mlkem' or a recipient card`);
    }
    if (!this.memberKeys.has(id) && this.memberKeys.size >= MAX_RECIPIENTS) {
      throw new QoreSealError("INVALID_ARGUMENT", `a group has at most ${MAX_RECIPIENTS} members`);
    }
    this.memberKeys.set(id, r);
  }

  private newEpoch(): void {
    this.current += 1n;
    this.keys.set(this.current, this.entropy.take(DATA_KEY_LENGTH));
  }

  /** The current epoch number. */
  get epoch(): bigint {
    return this.current;
  }

  get currentKey(): EpochKey {
    return { epoch: this.current, key: Uint8Array.from(this.keys.get(this.current) as Uint8Array) };
  }

  /** The key of an epoch this manager knows, or undefined. */
  keyFor(epoch: bigint | number): Uint8Array | undefined {
    const k = this.keys.get(toU64(epoch, "epoch"));
    return k ? Uint8Array.from(k) : undefined;
  }

  /** Every epoch key, oldest first. Store it encrypted: it opens every batch of the group. */
  exportKeys(): EpochKey[] {
    return [...this.keys.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([epoch, key]) => ({ epoch, key: Uint8Array.from(key) }));
  }

  members(): string[] {
    return [...this.memberKeys.keys()];
  }

  /** The current epoch key sealed to the current members. */
  distribution(): Uint8Array {
    if (this.memberKeys.size === 0) throw new QoreSealError("INVALID_ARGUMENT", "the group has no members");
    return sealWith(
      {
        chainId: this.chainId,
        purpose: this.purpose,
        mode: this.mode,
        recipients: [...this.memberKeys.values()],
        plaintext: encodeEpochKey(this.currentKey),
      },
      this.entropy,
    );
  }

  private rotation(): EpochRotation {
    return { epoch: this.current, envelope: this.memberKeys.size ? this.distribution() : null, members: this.members() };
  }

  /** Start a new epoch without a membership change (for example on a schedule). */
  rotate(): EpochRotation {
    this.newEpoch();
    return this.rotation();
  }

  /** Add or replace a member and start a new epoch. */
  addMember(id: string, recipient: SealRecipient): EpochRotation {
    this.setMember(id, recipient);
    return this.rotate();
  }

  /** Remove a member and start a new epoch it cannot read. */
  removeMember(id: string): EpochRotation {
    if (!this.memberKeys.delete(id)) throw new QoreSealError("INVALID_ARGUMENT", `no member ${JSON.stringify(id)}`);
    return this.rotate();
  }
}
