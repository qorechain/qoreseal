// SPDX-License-Identifier: Apache-2.0
//
// `@qorechain/qoreseal/testing`: deterministic entry points for the shared
// test vectors (spec section 9). Never use them with real data: the same
// entropy gives the same ciphertexts and exposes the data keys.

import { QoreSealError } from "./errors.js";
import { sealWith, type Entropy, type SealArgs } from "./envelope.js";
import { sealBatchWith, type SealedBatch } from "./batch.js";
import type { EpochKey } from "./group.js";
import { ENTRY_LENGTH } from "./constants.js";

/** Bytes of entropy a seal consumes: 60 + 32 per recipient (64 in hybrid mode). */
export function sealEntropyLength(mode: keyof typeof ENTRY_LENGTH, recipients: number): number {
  return 60 + recipients * (mode === "hybrid" ? 64 : 32);
}

function stream(bytes: Uint8Array): Entropy & { done(): void } {
  let off = 0;
  return {
    deterministic: true,
    take(n: number): Uint8Array {
      if (off + n > bytes.length) throw new QoreSealError("INVALID_ARGUMENT", "not enough test entropy");
      const out = bytes.slice(off, off + n);
      off += n;
      return out;
    },
    done(): void {
      if (off !== bytes.length) throw new QoreSealError("INVALID_ARGUMENT", "test entropy has unused bytes");
    },
  };
}

/** {@link seal} with all of its randomness given. For test vectors only. */
export function sealWithEntropy(args: SealArgs, entropy: Uint8Array): Uint8Array {
  const s = stream(entropy);
  const out = sealWith(args, s);
  s.done();
  return out;
}

/** {@link sealBatch} with its nonce (12) and commitment salt (32) given. For test vectors only. */
export function sealBatchWithEntropy(
  args: { epochKey: EpochKey; context: string; batchIndex: bigint | number; data: Uint8Array },
  entropy: Uint8Array,
): SealedBatch {
  const s = stream(entropy);
  const out = sealBatchWith(args, s);
  s.done();
  return out;
}
