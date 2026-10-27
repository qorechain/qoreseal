// SPDX-License-Identifier: Apache-2.0
//
// Recipient cards: the X25519 key of the hybrid mode, signed by the account
// with QoreSign message signing and bound to the ML-KEM key on chain
// (spec section 7).

import { sha3_256 } from "@noble/hashes/sha3.js";
import {
  parseAddress,
  signMessage,
  verifyMessage,
  type ClassicalKey,
  type MessageSignature,
  type PqKeyPair,
} from "@qorechain/qoresign";
import { equalBytes, fromHex, toHex, utf8 } from "./bytes.js";
import { checkChainId } from "./constants.js";
import { QoreSealError } from "./errors.js";
import { validateMlkemPublicKey, validateX25519PublicKey, type SealKeyPair, type SealRecipient } from "./keys.js";

export const RECIPIENT_CARD_VERSION = 1;
export const RECIPIENT_CARD_TITLE = "QoreSeal recipient card v1";

/** A signed recipient card, in its JSON shape. */
export interface RecipientCard {
  version: 1;
  chainId: string;
  /** The `qor1` account the card belongs to. */
  address: string;
  /** Hex SHA3-256 of the ML-KEM-1024 key registered on chain. */
  mlkemKeySha3: string;
  /** Hex X25519 public key. */
  x25519PublicKey: string;
  /** `YYYY-MM-DDTHH:MM:SSZ`. */
  issuedAt: string;
  /** QoreSign message signature over {@link recipientCardSignBytes}. */
  signature: MessageSignature;
}

export type RecipientCardFields = Omit<RecipientCard, "signature" | "version">;

const ISSUED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const HEX32_RE = /^[0-9a-f]{64}$/;

function invalid(message: string): QoreSealError {
  return new QoreSealError("CARD_INVALID", message);
}

function checkFields(f: RecipientCardFields): void {
  try {
    checkChainId(f.chainId);
  } catch {
    throw invalid("invalid chain id");
  }
  let bech32: string;
  try {
    bech32 = parseAddress(f.address).bech32;
  } catch {
    throw invalid("invalid address");
  }
  if (bech32 !== f.address) throw invalid("the address must be the qor1 form");
  if (typeof f.mlkemKeySha3 !== "string" || !HEX32_RE.test(f.mlkemKeySha3)) throw invalid("mlkemKeySha3 must be 64 lowercase hex characters");
  if (typeof f.x25519PublicKey !== "string" || !HEX32_RE.test(f.x25519PublicKey)) {
    throw invalid("x25519PublicKey must be 64 lowercase hex characters");
  }
  if (typeof f.issuedAt !== "string" || !ISSUED_AT_RE.test(f.issuedAt)) throw invalid("issuedAt must be YYYY-MM-DDTHH:MM:SSZ");
}

/** The exact text the account signs (spec section 7). */
export function recipientCardText(f: RecipientCardFields): string {
  checkFields(f);
  return [
    RECIPIENT_CARD_TITLE,
    `Chain ID: ${f.chainId}`,
    `Address: ${f.address}`,
    `ML-KEM-1024 key SHA3-256: ${f.mlkemKeySha3}`,
    `X25519 key: ${f.x25519PublicKey}`,
    `Issued at: ${f.issuedAt}`,
  ].join("\n");
}

export function recipientCardSignBytes(f: RecipientCardFields): Uint8Array {
  return utf8(recipientCardText(f));
}

/** The card fields for a key pair; sign them with {@link signRecipientCard} or a wallet's `signArbitrary`. */
export function recipientCardFields(args: {
  chainId: string;
  address: string;
  keys: Pick<SealKeyPair, "mlkemPublicKey" | "x25519PublicKey">;
  issuedAt?: Date | string;
}): RecipientCardFields {
  validateMlkemPublicKey(args.keys.mlkemPublicKey);
  validateX25519PublicKey(args.keys.x25519PublicKey);
  const issued = args.issuedAt ?? new Date();
  const issuedAt = typeof issued === "string" ? issued : issued.toISOString().replace(/\.\d{3}Z$/, "Z");
  const fields: RecipientCardFields = {
    chainId: args.chainId,
    address: args.address,
    mlkemKeySha3: toHex(sha3_256(args.keys.mlkemPublicKey)),
    x25519PublicKey: toHex(args.keys.x25519PublicKey),
    issuedAt,
  };
  checkFields(fields);
  return fields;
}

/** Sign a recipient card with the account's classical and ML-DSA-87 keys (QoreSign `signMessage`). */
export function signRecipientCard(args: {
  chainId: string;
  address: string;
  keys: Pick<SealKeyPair, "mlkemPublicKey" | "x25519PublicKey">;
  classicalKey: ClassicalKey;
  pqKey: Pick<PqKeyPair, "secretKey">;
  issuedAt?: Date | string;
}): RecipientCard {
  const fields = recipientCardFields(args);
  const signature = signMessage({
    chainId: fields.chainId,
    signer: fields.address,
    data: recipientCardSignBytes(fields),
    classicalKey: args.classicalKey,
    pqKey: args.pqKey,
  });
  return { version: RECIPIENT_CARD_VERSION, ...fields, signature };
}

/** Attach a signature produced elsewhere (for example by a wallet) to card fields. */
export function assembleRecipientCard(fields: RecipientCardFields, signature: MessageSignature): RecipientCard {
  checkFields(fields);
  return { version: RECIPIENT_CARD_VERSION, ...fields, signature };
}

/**
 * Verify a card against the keys the account has on chain and return the
 * hybrid recipient. Throws `CARD_INVALID`.
 */
export function verifyRecipientCard(args: {
  card: RecipientCard;
  chainId: string;
  /** Expected account; defaults to the card's own. */
  address?: string;
  /** ML-DSA-87 key registered for the account (`/qorechain/pqc/v1/account/{address}`). */
  pqPublicKey: Uint8Array;
  /** ML-KEM-1024 key registered for the account (`/qorechain/pqc/v1/kem/{address}`). */
  mlkemPublicKey: Uint8Array;
}): SealRecipient {
  const c = args.card;
  if (!c || typeof c !== "object" || c.version !== RECIPIENT_CARD_VERSION) throw invalid("unsupported card version");
  checkFields(c);
  if (c.chainId !== args.chainId) throw invalid(`the card is for chain ${c.chainId}, not ${args.chainId}`);
  if (args.address !== undefined && c.address !== args.address) throw invalid(`the card is for ${c.address}, not ${args.address}`);
  try {
    validateMlkemPublicKey(args.mlkemPublicKey);
  } catch {
    throw invalid("the registered ML-KEM-1024 key is not valid");
  }
  if (!equalBytes(sha3_256(args.mlkemPublicKey), fromHex(c.mlkemKeySha3))) {
    throw invalid("the card names a different ML-KEM-1024 key than the registered one");
  }
  const x = fromHex(c.x25519PublicKey);
  try {
    validateX25519PublicKey(x);
  } catch {
    throw invalid("the card's X25519 key is not valid");
  }
  try {
    verifyMessage({
      chainId: c.chainId,
      signer: c.address,
      data: recipientCardSignBytes(c),
      signature: c.signature,
      pqPublicKey: args.pqPublicKey,
      requirePq: true,
    });
  } catch (err) {
    const code = (err as { code?: string }).code;
    throw new QoreSealError("CARD_INVALID", `the card signature does not verify${code ? ` (${code})` : ""}`);
  }
  return { mlkemPublicKey: Uint8Array.from(args.mlkemPublicKey), x25519PublicKey: x };
}
