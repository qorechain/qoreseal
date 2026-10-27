// SPDX-License-Identifier: Apache-2.0
//
// Messages of the chain's KEM key registry (`qorechain.pqc.v1`). Sign the
// transaction that carries them hybrid, with QoreSign `signHybrid`.

import { parseAddress } from "@qorechain/qoresign";
import { concat, utf8 } from "./bytes.js";
import { ALGORITHM_ML_KEM_1024 } from "./constants.js";
import { QoreSealError } from "./errors.js";
import { validateMlkemPublicKey } from "./keys.js";

export const MSG_REGISTER_KEM_KEY_TYPE_URL = "/qorechain.pqc.v1.MsgRegisterKEMKey";
export const MSG_REMOVE_KEM_KEY_TYPE_URL = "/qorechain.pqc.v1.MsgRemoveKEMKey";

/** A protobuf `Any`, ready to put in a transaction body. */
export interface EncodedMessage {
  typeUrl: string;
  value: Uint8Array;
}

function varint(n: number): Uint8Array {
  const out: number[] = [];
  let v = n;
  do {
    let b = v & 0x7f;
    v = Math.floor(v / 128);
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return Uint8Array.from(out);
}

function lenField(field: number, payload: Uint8Array): Uint8Array {
  return concat(varint((field << 3) | 2), varint(payload.length), payload);
}

function sender(address: string): string {
  try {
    return parseAddress(address).bech32;
  } catch {
    throw new QoreSealError("INVALID_ARGUMENT", `invalid account address ${JSON.stringify(address)}`);
  }
}

/** `MsgRegisterKEMKey { sender, algorithm_id: 2, public_key }`. Registering again replaces the key. */
export function buildRegisterKemKeyMessage(args: { sender: string; mlkemPublicKey: Uint8Array }): EncodedMessage {
  validateMlkemPublicKey(args.mlkemPublicKey);
  const value = concat(
    lenField(1, utf8(sender(args.sender))),
    Uint8Array.of(0x10, ALGORITHM_ML_KEM_1024),
    lenField(3, args.mlkemPublicKey),
  );
  return { typeUrl: MSG_REGISTER_KEM_KEY_TYPE_URL, value };
}

/** `MsgRemoveKEMKey { sender }`. */
export function buildRemoveKemKeyMessage(args: { sender: string }): EncodedMessage {
  return { typeUrl: MSG_REMOVE_KEM_KEY_TYPE_URL, value: lenField(1, utf8(sender(args.sender))) };
}

/** Errors of the KEM key registry (codespace `pqc`). */
export const KEM_REGISTRY_ERRORS: Readonly<Record<number, string>> = Object.freeze({
  250: "the KEM key registry is not enabled on this chain yet",
  251: "invalid KEM public key",
  252: "no KEM key published for this account",
  253: "this KEM key is already published for this account",
  254: "publishing a KEM key needs a registered post-quantum signature key",
});

/** Explain a refusal of a registry transaction, or undefined when it is not one. */
export function describeKemRegistryError(codespace: string, code: number): string | undefined {
  return codespace === "pqc" ? KEM_REGISTRY_ERRORS[code] : undefined;
}
