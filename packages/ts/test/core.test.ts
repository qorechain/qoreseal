// SPDX-License-Identifier: Apache-2.0
//
// Behaviour beyond the vectors: random round trips, input checks, groups,
// batches and the network helpers (against a stub endpoint).

import { deriveCanonicalPqKey, deriveClassicalKey, toBase64 } from "@qorechain/qoresign";
import { describe, expect, it } from "vitest";
import * as qs from "../src/index.js";
import { fetchKemKey, resolveRecipient, sealToAddresses, type FetchLike } from "../src/network.js";
import { sealEntropyLength, sealWithEntropy } from "../src/testing.js";
import { asyncCodeOf, codeOf, enc, vectors as v } from "./helpers.js";

const CHAIN = "qorechain-diana";
const alice = qs.generateSealKeys();
const bob = qs.generateSealKeys();
const carol = qs.generateSealKeys();

describe("seal and open", () => {
  it("round trips in both modes, with and without hints", () => {
    for (const mode of ["hybrid", "mlkem"] as const) {
      for (const anonymous of [false, true]) {
        const env = qs.seal({
          chainId: CHAIN,
          purpose: "chat",
          mode,
          anonymous,
          recipients: [qs.recipientOf(alice), qs.recipientOf(bob)],
          plaintext: enc("hello"),
        });
        expect(env.length).toBe(qs.envelopeSize({ mode, recipients: 2, plaintextLength: 5 }));
        for (const k of [alice, bob]) {
          expect(new TextDecoder().decode(qs.open({ chainId: CHAIN, purpose: "chat", envelope: env, keys: k }))).toBe("hello");
        }
        expect(codeOf(() => qs.open({ chainId: CHAIN, purpose: "chat", envelope: env, keys: carol }))).toBe(
          anonymous ? "DECRYPTION_FAILED" : "NOT_A_RECIPIENT",
        );
      }
    }
  });

  it("two seals of the same data differ", () => {
    const args = { chainId: CHAIN, purpose: "chat", recipients: [qs.recipientOf(alice)], plaintext: enc("x") };
    expect(qs.toHex(qs.seal(args))).not.toBe(qs.toHex(qs.seal(args)));
  });

  it("hybrid is the default and needs the X25519 key", () => {
    const onlyKem = { mlkemPublicKey: alice.mlkemPublicKey };
    expect(codeOf(() => qs.seal({ chainId: CHAIN, purpose: "chat", recipients: [onlyKem], plaintext: enc("x") }))).toBe(
      "RECIPIENT_NEEDS_X25519",
    );
    const env = qs.seal({ chainId: CHAIN, purpose: "chat", mode: "mlkem", recipients: [onlyKem], plaintext: enc("x") });
    expect(qs.parseEnvelope(env).mode).toBe("mlkem");
  });

  it("checks keys and arguments", () => {
    const bad = Uint8Array.from(alice.mlkemPublicKey);
    bad[0] = 0xff;
    bad[1] = 0x0f;
    expect(codeOf(() => qs.validateMlkemPublicKey(bad))).toBe("INVALID_KEY");
    const zero = new Uint8Array(1568);
    expect(codeOf(() => qs.validateMlkemPublicKey(zero))).toBe("INVALID_KEY");
    expect(codeOf(() => qs.validateMlkemPublicKey(new Uint8Array(1567)))).toBe("INVALID_KEY");
    const r = qs.recipientOf(alice);
    const seal = (over: Partial<qs.SealArgs>) => () =>
      qs.seal({ chainId: CHAIN, purpose: "chat", recipients: [r], plaintext: enc("x"), ...over });
    expect(codeOf(seal({ recipients: [{ ...r, mlkemPublicKey: bad }] }))).toBe("INVALID_KEY");
    // A low-order X25519 point gives an all-zero agreement.
    const lowOrder = new Uint8Array(32);
    lowOrder[0] = 1;
    expect(codeOf(seal({ recipients: [{ ...r, x25519PublicKey: lowOrder }] }))).toBe("INVALID_KEY");
    expect(codeOf(seal({ recipients: [{ ...r, x25519PublicKey: new Uint8Array(32) }] }))).toBe("INVALID_KEY");
    expect(codeOf(seal({ recipients: [] }))).toBe("INVALID_ARGUMENT");
    expect(codeOf(seal({ chainId: "bad|chain" }))).toBe("INVALID_ARGUMENT");
    expect(codeOf(seal({ purpose: "" }))).toBe("INVALID_ARGUMENT");
    expect(codeOf(seal({ purpose: "a b" }))).toBe("INVALID_ARGUMENT");
    expect(codeOf(seal({ mode: "rsa" as qs.SealMode }))).toBe("INVALID_ARGUMENT");
    expect(codeOf(() => qs.sealKeysFromSeed(new Uint8Array(31)))).toBe("INVALID_ARGUMENT");
    expect(codeOf(() => qs.deriveSealKeys({ mnemonic: "not a mnemonic" }))).toBe("INVALID_ARGUMENT");
    expect(codeOf(() => qs.deriveSealKeys({ mnemonic: v.card.mnemonic, index: -1 }))).toBe("INVALID_ARGUMENT");
  });

  it("test entropy must be exact", () => {
    const args = { chainId: CHAIN, purpose: "chat", recipients: [qs.recipientOf(alice)], plaintext: enc("x") };
    const n = sealEntropyLength("hybrid", 1);
    expect(n).toBe(124);
    expect(codeOf(() => sealWithEntropy(args, new Uint8Array(n - 1).fill(7)))).toBe("INVALID_ARGUMENT");
    expect(codeOf(() => sealWithEntropy(args, new Uint8Array(n + 1).fill(7)))).toBe("INVALID_ARGUMENT");
  });

  it("parses short or foreign input as malformed", () => {
    expect(codeOf(() => qs.parseEnvelope(new Uint8Array(3)))).toBe("MALFORMED_ENVELOPE");
    expect(codeOf(() => qs.parseEnvelope(enc("QSEL\x01\x01\x02\x01\x01\x00")))).toBe("MALFORMED_ENVELOPE");
  });

  it("describes registry refusals", () => {
    expect(qs.describeKemRegistryError("pqc", 254)).toMatch(/signature key/);
    expect(qs.describeKemRegistryError("sdk", 254)).toBeUndefined();
    expect(codeOf(() => qs.buildRegisterKemKeyMessage({ sender: "nope", mlkemPublicKey: alice.mlkemPublicKey }))).toBe("INVALID_ARGUMENT");
  });
});

describe("private groups", () => {
  it("rotates on membership changes and shuts removed members out", () => {
    const mgr = new qs.EpochKeyManager({
      chainId: CHAIN,
      purpose: "epoch-key:demo-rollup",
      members: { alice: qs.recipientOf(alice), bob: qs.recipientOf(bob) },
    });
    expect(mgr.epoch).toBe(1n);
    const codec = new qs.PrivateBatchCodec("demo-rollup", mgr);
    const b1 = codec.seal(1, enc("batch one"));

    const join = mgr.addMember("carol", qs.recipientOf(carol));
    expect(join.epoch).toBe(2n);
    const carolKey = qs.openEpochKey({ chainId: CHAIN, purpose: "epoch-key:demo-rollup", envelope: join.envelope!, keys: carol });
    expect(carolKey.epoch).toBe(2n);
    // carol joined at epoch 2: batch one (epoch 1) is not hers.
    expect(codeOf(() => qs.openBatch({ blob: b1.blob, keys: [carolKey] }))).toBe("UNKNOWN_EPOCH");

    const leave = mgr.removeMember("bob");
    expect(leave.epoch).toBe(3n);
    expect(leave.members).toEqual(["alice", "carol"]);
    expect(codeOf(() => qs.openEpochKey({ chainId: CHAIN, purpose: "epoch-key:demo-rollup", envelope: leave.envelope!, keys: bob }))).toBe(
      "NOT_A_RECIPIENT",
    );
    const b3 = codec.seal(3, enc("batch three"));
    const aliceKey = qs.openEpochKey({ chainId: CHAIN, purpose: "epoch-key:demo-rollup", envelope: leave.envelope!, keys: alice });
    const opened = qs.openBatch({ blob: b3.blob, keys: [aliceKey] });
    expect(new TextDecoder().decode(opened.data)).toBe("batch three");
    expect(qs.toHex(opened.plaintextCommitment)).toBe(qs.toHex(b3.plaintextCommitment));
    expect(codec.open(b1.blob).batchIndex).toBe(1n);

    // History round trip.
    const restored = new qs.EpochKeyManager({ chainId: CHAIN, purpose: "epoch-key:demo-rollup", history: mgr.exportKeys() });
    expect(restored.epoch).toBe(3n);
    expect(qs.toHex(restored.keyFor(1n)!)).toBe(qs.toHex(mgr.keyFor(1n)!));
  });

  it("refuses tampered or foreign batches", () => {
    const epochKey = { epoch: 4n, key: new Uint8Array(32).fill(9) };
    const b = qs.sealBatch({ epochKey, context: "demo-rollup", batchIndex: 2n, data: enc("data") });
    const t = Uint8Array.from(b.blob);
    t[t.length - 1] = t[t.length - 1]! ^ 1;
    expect(codeOf(() => qs.openBatch({ blob: t, keys: [epochKey] }))).toBe("DECRYPTION_FAILED");
    const h = Uint8Array.from(b.blob);
    h[21] = h[21]! ^ 1; // batch index
    expect(codeOf(() => qs.openBatch({ blob: h, keys: [epochKey] }))).toBe("DECRYPTION_FAILED");
    const ver = Uint8Array.from(b.blob);
    ver[4] = 9;
    expect(codeOf(() => qs.openBatch({ blob: ver, keys: [epochKey] }))).toBe("UNSUPPORTED_VERSION");
    expect(codeOf(() => qs.openBatch({ blob: enc("nope"), keys: [epochKey] }))).toBe("MALFORMED_BATCH");
    expect(codeOf(() => qs.openBatch({ blob: b.blob, keys: [{ epoch: 4n, key: new Uint8Array(32) }] }))).toBe("DECRYPTION_FAILED");
    expect(codeOf(() => qs.sealBatch({ epochKey, context: "bad context", batchIndex: 1, data: enc("x") }))).toBe("INVALID_ARGUMENT");
  });
});

describe("network helpers", () => {
  const mnemonic = v.card.mnemonic;
  const sealKeys = qs.deriveSealKeys({ mnemonic });
  const classical = deriveClassicalKey({ mnemonic });
  const address = v.card.address;
  const pq = deriveCanonicalPqKey({ mnemonic, address });
  const card = qs.signRecipientCard({ chainId: CHAIN, address, keys: sealKeys, classicalKey: classical, pqKey: pq });

  function stub(routes: Record<string, [number, unknown]>): FetchLike {
    return async (url) => {
      const path = new URL(url).pathname;
      const [status, body] = routes[path] ?? [404, { code: 5, message: "not found" }];
      return { ok: status < 400, status, json: async () => body };
    };
  }
  const kemBody = {
    found: true,
    key: { address, algorithm_id: 2, algorithm_name: "ml-kem-1024", public_key: toBase64(sealKeys.mlkemPublicKey), registered_height: "1234" },
  };
  const pqBody = { found: true, account: { public_key: toBase64(pq.publicKey), algorithm_id: 1, key_type: "hybrid", possession_proven: true } };
  const fetch = stub({
    [`/qorechain/pqc/v1/kem/${address}`]: [200, kemBody],
    [`/qorechain/pqc/v1/account/${address}`]: [200, pqBody],
  });
  const rest = "https://rest.example";

  it("reads the KEM key", async () => {
    const s = await fetchKemKey({ rest, fetch, address });
    expect(s.registered).toBe(true);
    expect(s.registeredHeight).toBe(1234n);
    expect(qs.toHex(s.publicKey!)).toBe(qs.toHex(sealKeys.mlkemPublicKey));
    const none = await fetchKemKey({ rest, fetch: stub({ [`/qorechain/pqc/v1/kem/${address}`]: [200, { found: false }] }), address });
    expect(none.registered).toBe(false);
    expect(await asyncCodeOf(() => fetchKemKey({ rest, fetch: stub({}), address }))).toBe("KEM_REGISTRY_UNAVAILABLE");
  });

  it("resolves hybrid recipients through their card and seals to addresses", async () => {
    const r = await resolveRecipient({ rest, fetch, chainId: CHAIN, address, card });
    expect(qs.toHex(r.x25519PublicKey!)).toBe(qs.toHex(sealKeys.x25519PublicKey));
    expect(await asyncCodeOf(() => resolveRecipient({ rest, fetch, chainId: CHAIN, address }))).toBe("RECIPIENT_NEEDS_X25519");
    const kemOnly = await resolveRecipient({ rest, fetch, chainId: CHAIN, address, mode: "mlkem" });
    expect(kemOnly.x25519PublicKey).toBeUndefined();
    const env = await sealToAddresses({ rest, fetch, chainId: CHAIN, purpose: "chat", recipients: [{ address, card }], plaintext: enc("hi") });
    expect(new TextDecoder().decode(qs.open({ chainId: CHAIN, purpose: "chat", envelope: env, keys: sealKeys }))).toBe("hi");
    const stale = stub({
      [`/qorechain/pqc/v1/kem/${address}`]: [200, { ...kemBody, key: { ...kemBody.key, public_key: toBase64(alice.mlkemPublicKey) } }],
      [`/qorechain/pqc/v1/account/${address}`]: [200, pqBody],
    });
    expect(await asyncCodeOf(() => resolveRecipient({ rest, fetch: stale, chainId: CHAIN, address, card }))).toBe("CARD_INVALID");
  });
});
