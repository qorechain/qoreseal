// SPDX-License-Identifier: Apache-2.0

import { base64urlnopad, hex } from "@scure/base";
import { QoreSealError } from "./errors.js";

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export function toHex(b: Uint8Array): string {
  return hex.encode(b);
}

export function fromHex(s: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/.test(s)) throw new QoreSealError("INVALID_ARGUMENT", "expected lowercase hex");
  return hex.decode(s);
}

export function toBase64Url(b: Uint8Array): string {
  return base64urlnopad.encode(b);
}

export function fromBase64Url(s: string): Uint8Array {
  return base64urlnopad.decode(s);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function u16(n: number): Uint8Array {
  return Uint8Array.of((n >>> 8) & 0xff, n & 0xff);
}

export function u64(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n);
  return out;
}

export function readU16(b: Uint8Array, off: number): number {
  return ((b[off] ?? 0) << 8) | (b[off + 1] ?? 0);
}

export function readU64(b: Uint8Array, off: number): bigint {
  return new DataView(b.buffer, b.byteOffset + off, 8).getBigUint64(0);
}

/** Constant-time comparison of two byte strings of equal length. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return d === 0;
}

export function isAllZero(b: Uint8Array): boolean {
  let d = 0;
  for (const x of b) d |= x;
  return d === 0;
}

export function requireBytes(v: unknown, len: number | undefined, what: string, code: "INVALID_ARGUMENT" | "INVALID_KEY" = "INVALID_ARGUMENT"): asserts v is Uint8Array {
  if (!(v instanceof Uint8Array)) throw new QoreSealError(code, `${what} must be a Uint8Array`);
  if (len !== undefined && v.length !== len) throw new QoreSealError(code, `${what} must be ${len} bytes, got ${v.length}`);
}
