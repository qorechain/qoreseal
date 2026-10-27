// SPDX-License-Identifier: Apache-2.0
//
// The TypeScript package against vectors/qoreseal-v1.json.

import { sha3_256 } from "@noble/hashes/sha3.js";
import { deriveCanonicalPqKey, deriveClassicalKey } from "@qorechain/qoresign";
import { describe, expect, it } from "vitest";
import * as qs from "../src/index.js";
import { sealBatchWithEntropy, sealWithEntropy } from "../src/testing.js";
import { codeOf, vectors as v } from "./helpers.js";

const hex = qs.toHex;
const unhex = qs.fromHex;
const keys = v.keys.map((k: { seed: string }) => qs.sealKeysFromSeed(unhex(k.seed)));

describe("keys", () => {
  it("derives both key pairs from a seed", () => {
    v.keys.forEach((k: Record<string, string>, i: number) => {
      expect(hex(keys[i].mlkemPublicKey)).toBe(k.mlkemPublicKey);
      expect(hex(sha3_256(keys[i].mlkemSecretKey))).toBe(k.mlkemSecretKeySha3);
      expect(hex(keys[i].x25519PublicKey)).toBe(k.x25519PublicKey);
      expect(hex(keys[i].x25519SecretKey)).toBe(k.x25519SecretKey);
    });
  });

  it("derives seeds from a mnemonic", () => {
    for (const m of v.mnemonicSeeds) {
      const seed = qs.sealSeedFromMnemonic(m);
      expect(hex(seed)).toBe(m.seed);
      expect(hex(sha3_256(qs.sealKeysFromSeed(seed).mlkemPublicKey))).toBe(m.mlkemPublicKeySha3);
    }
  });
});

describe("primitives", () => {
  it("encapsulates and decapsulates", () => {
    const e = v.encapsulation;
    const out = qs.mlkemEncapsulate(keys[e.recipient].mlkemPublicKey, unhex(e.m));
    expect(hex(out.cipherText)).toBe(e.ciphertext);
    expect(hex(out.sharedSecret)).toBe(e.sharedSecret);
    expect(hex(qs.mlkemDecapsulate(keys[e.recipient].mlkemSecretKey, unhex(e.ciphertext)))).toBe(e.sharedSecret);
  });

  it("agrees on X25519", () => {
    const x = v.x25519;
    expect(hex(qs.x25519PublicKey(unhex(x.ephemeralSecretKey)))).toBe(x.ephemeralPublicKey);
    expect(hex(qs.x25519Agree(unhex(x.ephemeralSecretKey), keys[x.recipient].x25519PublicKey))).toBe(x.sharedSecret);
    expect(hex(qs.x25519Agree(keys[x.recipient].x25519SecretKey, unhex(x.ephemeralPublicKey)))).toBe(x.sharedSecret);
  });

  it("combines the hybrid secret", () => {
    const h = v.hybrid;
    expect(qs.HYBRID_LABEL).toBe(h.label);
    const shared = qs.hybridSharedSecret({
      mlkemSharedSecret: unhex(h.mlkemSharedSecret),
      x25519SharedSecret: unhex(h.x25519SharedSecret),
      x25519Ciphertext: unhex(h.x25519Ciphertext),
      x25519PublicKey: unhex(h.x25519PublicKey),
    });
    expect(hex(shared)).toBe(h.shared);
  });

  it("derives keys", () => {
    for (const k of v.kdf) {
      expect(qs.kdfInfo(k.chainId, k.purpose)).toBe(k.info);
      expect(hex(qs.deriveKey({ shared: unhex(k.shared), chainId: k.chainId, purpose: k.purpose, salt: unhex(k.salt) }))).toBe(k.key);
    }
  });

  it("computes the hint", () => {
    expect(hex(qs.recipientHint(unhex(v.hint.salt), keys[v.hint.recipient].mlkemPublicKey))).toBe(v.hint.hint);
  });
});

describe("envelopes", () => {
  for (const e of v.envelopes) {
    it(`${e.name}: seals byte for byte and opens for every recipient`, () => {
      const env = sealWithEntropy(
        {
          chainId: v.chainId,
          purpose: v.purpose,
          mode: e.mode,
          anonymous: e.anonymous,
          recipients: e.recipients.map((i: number) => qs.recipientOf(keys[i])),
          plaintext: unhex(e.plaintext),
          aad: unhex(e.aad),
        },
        unhex(e.entropy),
      );
      expect(hex(env)).toBe(e.envelope);
      expect(env.length).toBe(e.size);
      expect(qs.envelopeToText(env)).toBe(e.text);
      expect(hex(qs.envelopeFromText(e.text))).toBe(e.envelope);
      for (const i of e.recipients) {
        expect(hex(qs.open({ chainId: v.chainId, purpose: v.purpose, envelope: env, keys: keys[i], aad: unhex(e.aad) }))).toBe(e.plaintext);
      }
      const parsed = qs.parseEnvelope(env);
      expect(parsed.mode).toBe(e.mode);
      expect(parsed.anonymous).toBe(e.anonymous);
      expect(parsed.entries.length).toBe(e.recipients.length);
    });
  }

  it("reports the expected error for every negative case", () => {
    const byName = Object.fromEntries(v.envelopes.map((e: { name: string }) => [e.name, e]));
    for (const n of v.negative) {
      const base = byName[n.base];
      let env = Uint8Array.from(unhex(base.envelope));
      if (n.flip !== undefined) env[n.flip] = env[n.flip]! ^ 0x01;
      if (n.set) env[n.set[0]] = n.set[1];
      if (n.truncate !== undefined) env = env.slice(0, n.truncate);
      const code = codeOf(() =>
        qs.open({
          chainId: n.chainId ?? v.chainId,
          purpose: n.purpose ?? v.purpose,
          envelope: env,
          keys: keys[n.key],
          aad: unhex(n.aad ?? base.aad),
        }),
      );
      expect(code, n.name).toBe(n.error);
    }
    for (const t of v.textNegative) expect(codeOf(() => qs.envelopeFromText(t.text)), t.name).toBe(t.error);
  });

  it("matches the size table", () => {
    for (const s of v.sizes) expect(qs.envelopeSize(s)).toBe(s.size);
  });
});

describe("recipient card", () => {
  const c = v.card;
  const classical = deriveClassicalKey({ mnemonic: c.mnemonic });
  const pq = deriveCanonicalPqKey({ mnemonic: c.mnemonic, address: c.address });
  const sealKeys = qs.deriveSealKeys({ mnemonic: c.mnemonic, index: c.sealKeysIndex });

  it("signs the card byte for byte", () => {
    expect(hex(pq.publicKey)).toBe(c.pqPublicKey);
    const card = qs.signRecipientCard({
      chainId: v.chainId,
      address: c.address,
      keys: sealKeys,
      classicalKey: classical,
      pqKey: pq,
      issuedAt: c.card.issuedAt,
    });
    expect(qs.recipientCardText(card)).toBe(c.text);
    expect(card).toEqual(c.card);
  });

  it("verifies the card against the keys on chain", () => {
    const r = qs.verifyRecipientCard({
      card: c.card,
      chainId: v.chainId,
      address: c.address,
      pqPublicKey: unhex(c.pqPublicKey),
      mlkemPublicKey: sealKeys.mlkemPublicKey,
    });
    expect(hex(r.x25519PublicKey!)).toBe(hex(sealKeys.x25519PublicKey));
  });

  it("refuses the negative cases", () => {
    for (const n of c.negative) {
      const card = { ...c.card, ...(n.x25519PublicKey ? { x25519PublicKey: n.x25519PublicKey } : {}) };
      const code = codeOf(() =>
        qs.verifyRecipientCard({
          card,
          chainId: n.chainId ?? v.chainId,
          address: n.address,
          pqPublicKey: unhex(c.pqPublicKey),
          mlkemPublicKey: n.mlkemKey !== undefined ? keys[n.mlkemKey].mlkemPublicKey : sealKeys.mlkemPublicKey,
        }),
      );
      expect(code, n.name).toBe(n.error);
    }
  });
});

describe("registry, epochs and batches", () => {
  it("encodes the registry messages", () => {
    const r = v.registry;
    const sealKeys = qs.deriveSealKeys({ mnemonic: v.card.mnemonic });
    const reg = qs.buildRegisterKemKeyMessage({ sender: r.sender, mlkemPublicKey: sealKeys.mlkemPublicKey });
    expect(reg.typeUrl).toBe(r.register.typeUrl);
    expect(hex(reg.value)).toBe(r.register.value);
    const rem = qs.buildRemoveKemKeyMessage({ sender: r.sender });
    expect(rem.typeUrl).toBe(r.remove.typeUrl);
    expect(hex(rem.value)).toBe(r.remove.value);
  });

  it("seals and opens the epoch key", () => {
    const e = v.epoch;
    const epochKey = { epoch: BigInt(e.epoch), key: unhex(e.key) };
    expect(hex(qs.encodeEpochKey(epochKey))).toBe(e.payload);
    const env = sealWithEntropy(
      {
        chainId: v.chainId,
        purpose: e.purpose,
        recipients: e.recipients.map((i: number) => qs.recipientOf(keys[i])),
        plaintext: qs.encodeEpochKey(epochKey),
      },
      unhex(e.entropy),
    );
    expect(hex(env)).toBe(e.envelope);
    for (const i of e.recipients) {
      const got = qs.openEpochKey({ chainId: v.chainId, purpose: e.purpose, envelope: env, keys: keys[i] });
      expect(got.epoch).toBe(1n);
      expect(hex(got.key)).toBe(e.key);
    }
  });

  it("seals and opens the batch", () => {
    const b = v.batch;
    const epochKey = { epoch: BigInt(b.epoch), key: unhex(b.key) };
    const sealed = sealBatchWithEntropy(
      { epochKey, context: b.context, batchIndex: BigInt(b.batchIndex), data: unhex(b.data) },
      unhex(b.entropy),
    );
    expect(hex(sealed.blob)).toBe(b.blob);
    expect(hex(sealed.ciphertextCommitment)).toBe(b.ciphertextCommitment);
    expect(hex(sealed.plaintextCommitment)).toBe(b.plaintextCommitment);
    const opened = qs.openBatch({ blob: sealed.blob, keys: [epochKey] });
    expect(hex(opened.data)).toBe(b.data);
    expect(opened.batchIndex).toBe(7n);
    expect(opened.context).toBe(b.context);
    expect(hex(opened.plaintextCommitment)).toBe(b.plaintextCommitment);
    expect(sealed.blob.length).toBe(qs.batchSize(b.context.length, unhex(b.data).length));
  });
});
