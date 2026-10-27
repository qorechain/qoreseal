// SPDX-License-Identifier: Apache-2.0
//
// The QoreSeal envelope: one payload encrypted once with a random data key,
// the data key wrapped for each recipient (spec section 5).

import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { concat, equalBytes, fromBase64Url, readU16, requireBytes, toBase64Url, u16 } from "./bytes.js";
import {
  AEAD_AES_256_GCM,
  ALGORITHM_ML_KEM_1024,
  checkChainId,
  checkPurpose,
  DATA_KEY_LENGTH,
  ENTRY_LENGTH,
  ENVELOPE_MAGIC,
  ENVELOPE_TEXT_PREFIX,
  ENVELOPE_VERSION,
  FIXED_HEADER_LENGTH,
  FLAG_ANONYMOUS,
  HINT_LENGTH,
  KDF_HKDF_SHA256,
  MAX_RECIPIENTS,
  ML_KEM_1024_CIPHERTEXT_LENGTH,
  MODE_HYBRID,
  MODE_MLKEM,
  modeByte,
  NONCE_LENGTH,
  SALT_LENGTH,
  TAG_LENGTH,
  WRAPPED_KEY_LENGTH,
  type SealMode,
} from "./constants.js";
import { QoreSealError } from "./errors.js";
import { checkKeyPair, validateMlkemPublicKey, validateX25519PublicKey, type SealKeyPair, type SealRecipient } from "./keys.js";
import {
  deriveKey,
  hybridSharedSecret,
  mlkemDecapsulate,
  mlkemEncapsulate,
  recipientHint,
  x25519Agree,
  x25519PublicKey,
} from "./kem.js";

export interface SealArgs {
  chainId: string;
  /** What the data is for in your application, e.g. `chat` or `invoice` (spec section 3). */
  purpose: string;
  recipients: SealRecipient[];
  plaintext: Uint8Array;
  /** Extra data authenticated but not encrypted; the recipient must pass the same bytes. */
  aad?: Uint8Array;
  /** Default `hybrid`. `mlkem` must be chosen explicitly. */
  mode?: SealMode;
  /** Zero hints: recipients try every entry, and the envelope does not point at them. */
  anonymous?: boolean;
}

export interface OpenArgs {
  chainId: string;
  purpose: string;
  envelope: Uint8Array;
  keys: SealKeyPair;
  aad?: Uint8Array;
}

export interface EnvelopeEntry {
  hint: Uint8Array;
  mlkemCiphertext: Uint8Array;
  /** X25519 ephemeral public key (hybrid mode only). */
  x25519Ciphertext?: Uint8Array;
  wrappedKey: Uint8Array;
}

/** The parts of an envelope, as read from its bytes. */
export interface ParsedEnvelope {
  version: number;
  mode: SealMode;
  anonymous: boolean;
  salt: Uint8Array;
  entries: EnvelopeEntry[];
  nonce: Uint8Array;
  /** Payload ciphertext with its tag. */
  ciphertext: Uint8Array;
  /** Everything before the ciphertext: the payload's AAD starts with it. */
  header: Uint8Array;
}

/** Source of the randomness a seal consumes (spec section 9). */
export interface Entropy {
  deterministic: boolean;
  take(n: number): Uint8Array;
}

export const systemEntropy: Entropy = { deterministic: false, take: (n) => randomBytes(n) };

/** Size in bytes of an envelope: `56 + n * W + plaintextLength`. */
export function envelopeSize(args: { mode?: SealMode; recipients: number; plaintextLength: number }): number {
  const w = ENTRY_LENGTH[args.mode ?? "hybrid"];
  if (w === undefined) throw new QoreSealError("INVALID_ARGUMENT", `unknown mode ${JSON.stringify(args.mode)}`);
  return FIXED_HEADER_LENGTH + args.recipients * w + NONCE_LENGTH + args.plaintextLength + TAG_LENGTH;
}

function fixedHeader(mode: number, anonymous: boolean, salt: Uint8Array, n: number): Uint8Array {
  return concat(
    ENVELOPE_MAGIC,
    Uint8Array.of(ENVELOPE_VERSION, mode, ALGORITHM_ML_KEM_1024, KDF_HKDF_SHA256, AEAD_AES_256_GCM, anonymous ? FLAG_ANONYMOUS : 0),
    salt,
    u16(n),
  );
}

function entryAad(fixed: Uint8Array, hint: Uint8Array, ctK: Uint8Array, ctX?: Uint8Array): Uint8Array {
  return ctX ? concat(fixed, hint, ctK, ctX) : concat(fixed, hint, ctK);
}

const ZERO_NONCE = new Uint8Array(NONCE_LENGTH);

/** @internal Seal with an explicit entropy source. */
export function sealWith(args: SealArgs, entropy: Entropy): Uint8Array {
  checkChainId(args.chainId);
  checkPurpose(args.purpose);
  const mode = args.mode ?? "hybrid";
  const mb = modeByte(mode);
  requireBytes(args.plaintext, undefined, "plaintext");
  const aad = args.aad ?? new Uint8Array(0);
  requireBytes(aad, undefined, "aad");
  const recipients = args.recipients;
  if (!Array.isArray(recipients) || recipients.length === 0 || recipients.length > MAX_RECIPIENTS) {
    throw new QoreSealError("INVALID_ARGUMENT", `between 1 and ${MAX_RECIPIENTS} recipients are required`);
  }
  for (const r of recipients) {
    validateMlkemPublicKey(r.mlkemPublicKey);
    if (mode === "hybrid") {
      if (!r.x25519PublicKey) {
        throw new QoreSealError(
          "RECIPIENT_NEEDS_X25519",
          "hybrid mode needs each recipient's X25519 key (from a recipient card); choose mode 'mlkem' explicitly to use the on-chain key alone",
        );
      }
      validateX25519PublicKey(r.x25519PublicKey);
    }
  }
  const anonymous = args.anonymous === true;
  const salt = entropy.take(SALT_LENGTH);
  const dek = entropy.take(DATA_KEY_LENGTH);
  const fixed = fixedHeader(mb, anonymous, salt, recipients.length);
  const parts: Uint8Array[] = [fixed];
  for (const r of recipients) {
    const hint = anonymous ? new Uint8Array(HINT_LENGTH) : recipientHint(salt, r.mlkemPublicKey);
    const m = entropy.deterministic ? entropy.take(32) : undefined;
    const { cipherText: ctK, sharedSecret: ssK } = mlkemEncapsulate(r.mlkemPublicKey, m);
    let shared = ssK;
    let ctX: Uint8Array | undefined;
    if (mode === "hybrid") {
      const pkX = r.x25519PublicKey as Uint8Array;
      const eSk = entropy.take(32);
      ctX = x25519PublicKey(eSk);
      const ssX = x25519Agree(eSk, pkX);
      shared = hybridSharedSecret({ mlkemSharedSecret: ssK, x25519SharedSecret: ssX, x25519Ciphertext: ctX, x25519PublicKey: pkX });
    }
    const kek = deriveKey({ shared, chainId: args.chainId, purpose: args.purpose, salt });
    const wrapped = gcm(kek, ZERO_NONCE, entryAad(fixed, hint, ctK, ctX)).encrypt(dek);
    parts.push(hint, ctK);
    if (ctX) parts.push(ctX);
    parts.push(wrapped);
  }
  const nonce = entropy.take(NONCE_LENGTH);
  parts.push(nonce);
  const header = concat(...parts);
  const ciphertext = gcm(dek, nonce, concat(header, aad)).encrypt(args.plaintext);
  return concat(header, ciphertext);
}

/** Encrypt `plaintext` to one or more recipients. Returns the binary envelope. */
export function seal(args: SealArgs): Uint8Array {
  return sealWith(args, systemEntropy);
}

/** Read the structure of an envelope without decrypting it. */
export function parseEnvelope(envelope: Uint8Array): ParsedEnvelope {
  requireBytes(envelope, undefined, "envelope");
  const b = envelope;
  if (b.length < 10 || !equalBytes(b.subarray(0, 4), ENVELOPE_MAGIC)) {
    throw new QoreSealError("MALFORMED_ENVELOPE", "not a QoreSeal envelope");
  }
  if (b[4] !== ENVELOPE_VERSION) throw new QoreSealError("UNSUPPORTED_VERSION", `unsupported envelope version ${b[4]}`);
  const mb = b[5];
  if ((mb !== MODE_HYBRID && mb !== MODE_MLKEM) || b[6] !== ALGORITHM_ML_KEM_1024 || b[7] !== KDF_HKDF_SHA256 || b[8] !== AEAD_AES_256_GCM) {
    throw new QoreSealError("UNSUPPORTED_ALGORITHM", "unsupported mode or algorithm in the envelope");
  }
  const flags = b[9] ?? 0;
  if ((flags & ~FLAG_ANONYMOUS) !== 0) throw new QoreSealError("MALFORMED_ENVELOPE", "unknown envelope flags");
  if (b.length < FIXED_HEADER_LENGTH) throw new QoreSealError("MALFORMED_ENVELOPE", "truncated envelope");
  const mode: SealMode = mb === MODE_HYBRID ? "hybrid" : "mlkem";
  const n = readU16(b, 26);
  if (n === 0 || n > MAX_RECIPIENTS) throw new QoreSealError("MALFORMED_ENVELOPE", `invalid recipient count ${n}`);
  const w = ENTRY_LENGTH[mode];
  const headerLength = FIXED_HEADER_LENGTH + n * w + NONCE_LENGTH;
  if (b.length < headerLength + TAG_LENGTH) throw new QoreSealError("MALFORMED_ENVELOPE", "truncated envelope");
  const entries: EnvelopeEntry[] = [];
  let off = FIXED_HEADER_LENGTH;
  for (let i = 0; i < n; i++) {
    const hint = b.slice(off, off + HINT_LENGTH);
    off += HINT_LENGTH;
    const mlkemCiphertext = b.slice(off, off + ML_KEM_1024_CIPHERTEXT_LENGTH);
    off += ML_KEM_1024_CIPHERTEXT_LENGTH;
    let x25519Ciphertext: Uint8Array | undefined;
    if (mode === "hybrid") {
      x25519Ciphertext = b.slice(off, off + 32);
      off += 32;
    }
    const wrappedKey = b.slice(off, off + WRAPPED_KEY_LENGTH);
    off += WRAPPED_KEY_LENGTH;
    entries.push(x25519Ciphertext ? { hint, mlkemCiphertext, x25519Ciphertext, wrappedKey } : { hint, mlkemCiphertext, wrappedKey });
  }
  return {
    version: ENVELOPE_VERSION,
    mode,
    anonymous: (flags & FLAG_ANONYMOUS) !== 0,
    salt: b.slice(10, 26),
    entries,
    nonce: b.slice(off, off + NONCE_LENGTH),
    ciphertext: b.slice(headerLength),
    header: b.slice(0, headerLength),
  };
}

function tryOpen(fn: () => Uint8Array): Uint8Array | undefined {
  try {
    return fn();
  } catch {
    return undefined;
  }
}

/** Decrypt an envelope with the recipient's keys. */
export function open(args: OpenArgs): Uint8Array {
  checkChainId(args.chainId);
  checkPurpose(args.purpose);
  checkKeyPair(args.keys);
  const aad = args.aad ?? new Uint8Array(0);
  requireBytes(aad, undefined, "aad");
  const env = parseEnvelope(args.envelope);
  const fixed = env.header.subarray(0, FIXED_HEADER_LENGTH);
  const myHint = recipientHint(env.salt, args.keys.mlkemPublicKey);
  const candidates = env.anonymous ? env.entries : env.entries.filter((e) => equalBytes(e.hint, myHint));
  if (candidates.length === 0) throw new QoreSealError("NOT_A_RECIPIENT", "the envelope has no entry for this key");
  let dek: Uint8Array | undefined;
  for (const e of candidates) {
    dek = tryOpen(() => {
      const ssK = mlkemDecapsulate(args.keys.mlkemSecretKey, e.mlkemCiphertext);
      let shared = ssK;
      if (env.mode === "hybrid") {
        const ctX = e.x25519Ciphertext as Uint8Array;
        const ssX = x25519Agree(args.keys.x25519SecretKey, ctX);
        shared = hybridSharedSecret({
          mlkemSharedSecret: ssK,
          x25519SharedSecret: ssX,
          x25519Ciphertext: ctX,
          x25519PublicKey: args.keys.x25519PublicKey,
        });
      }
      const kek = deriveKey({ shared, chainId: args.chainId, purpose: args.purpose, salt: env.salt });
      return gcm(kek, ZERO_NONCE, entryAad(fixed, e.hint, e.mlkemCiphertext, e.x25519Ciphertext)).decrypt(e.wrappedKey);
    });
    if (dek) break;
  }
  if (!dek) throw new QoreSealError("DECRYPTION_FAILED", "no entry of the envelope opens with this key, chain id and purpose");
  const key = dek;
  const plaintext = tryOpen(() => gcm(key, env.nonce, concat(env.header, aad)).decrypt(env.ciphertext));
  if (!plaintext) throw new QoreSealError("DECRYPTION_FAILED", "the payload does not authenticate");
  return plaintext;
}

/** `"qoreseal:" + base64url(envelope)`, without padding. */
export function envelopeToText(envelope: Uint8Array): string {
  return ENVELOPE_TEXT_PREFIX + toBase64Url(envelope);
}

/** Inverse of {@link envelopeToText}; strict about the alphabet, padding and trailing bits. */
export function envelopeFromText(text: string): Uint8Array {
  if (typeof text !== "string" || !text.startsWith(ENVELOPE_TEXT_PREFIX)) {
    throw new QoreSealError("MALFORMED_ENVELOPE", "text form must start with \"qoreseal:\"");
  }
  try {
    return fromBase64Url(text.slice(ENVELOPE_TEXT_PREFIX.length));
  } catch {
    throw new QoreSealError("MALFORMED_ENVELOPE", "invalid base64url in the text form");
  }
}
