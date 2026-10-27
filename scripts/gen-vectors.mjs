// SPDX-License-Identifier: Apache-2.0
//
// Regenerates vectors/qoreseal-v1.json from the TypeScript reference
// implementation. Every other language checks itself against this file.
// Run after `pnpm build`: node scripts/gen-vectors.mjs

import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const pkg = join(root, "packages/ts");
// Resolve dependencies the way the package itself does.
const req = createRequire(join(pkg, "package.json"));
const imp = (name) => import(pathToFileURL(req.resolve(name)).href);

const qs = await import(pathToFileURL(join(pkg, "dist/index.js")).href);
const testing = await import(pathToFileURL(join(pkg, "dist/testing.js")).href);
const qsign = await imp("@qorechain/qoresign");
const { sha3_256, shake256 } = await imp("@noble/hashes/sha3.js");

const hex = qs.toHex;
const enc = (s) => new TextEncoder().encode(s);
const det = (label, n) => shake256(enc(`qoreseal-vectors|${label}`), { dkLen: n });

const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const CHAIN_ID = "qorechain-diana";
const PURPOSE = "qoreseal-vectors";

// ---------------------------------------------------------------- keys
const keys = [0, 1, 2].map((i) => qs.sealKeysFromSeed(det(`seed-${i}`, 32)));
const keyVectors = keys.map((k) => ({
  seed: hex(k.seed),
  mlkemPublicKey: hex(k.mlkemPublicKey),
  mlkemSecretKeySha3: hex(sha3_256(k.mlkemSecretKey)),
  x25519PublicKey: hex(k.x25519PublicKey),
  x25519SecretKey: hex(k.x25519SecretKey),
}));

const mnemonicVectors = [
  { mnemonic: MNEMONIC, passphrase: "", index: 0 },
  { mnemonic: MNEMONIC, passphrase: "", index: 1 },
  { mnemonic: MNEMONIC, passphrase: "TREZOR", index: 0 },
].map((m) => {
  const seed = qs.sealSeedFromMnemonic(m);
  return { ...m, seed: hex(seed), mlkemPublicKeySha3: hex(sha3_256(qs.sealKeysFromSeed(seed).mlkemPublicKey)) };
});

// ---------------------------------------------------------------- primitives
const m = det("encaps-m", 32);
const encaps = qs.mlkemEncapsulate(keys[0].mlkemPublicKey, m);
const eSk = det("x25519-ephemeral", 32);
const ctX = qs.x25519PublicKey(eSk);
const ssX = qs.x25519Agree(eSk, keys[0].x25519PublicKey);
const combined = qs.hybridSharedSecret({
  mlkemSharedSecret: encaps.sharedSecret,
  x25519SharedSecret: ssX,
  x25519Ciphertext: ctX,
  x25519PublicKey: keys[0].x25519PublicKey,
});
const salt = det("salt", 16);
const kdf = [
  { shared: combined, chainId: CHAIN_ID, purpose: PURPOSE, salt },
  { shared: encaps.sharedSecret, chainId: "qorechain-vladi", purpose: "chat", salt: new Uint8Array(0) },
  { shared: combined, chainId: CHAIN_ID, purpose: "epoch-key:my-rollup", salt },
].map((k) => ({
  shared: hex(k.shared),
  chainId: k.chainId,
  purpose: k.purpose,
  salt: hex(k.salt),
  info: qs.kdfInfo(k.chainId, k.purpose),
  key: hex(qs.deriveKey(k)),
}));

// ---------------------------------------------------------------- envelopes
const plaintext = enc("QoreSeal test vector: the payload is encrypted, the transaction is not.");
const aad = enc("invoice-42");
const envelopeCases = [
  { name: "single-hybrid", mode: "hybrid", recipients: [0], anonymous: false, plaintext, aad },
  { name: "single-mlkem", mode: "mlkem", recipients: [0], anonymous: false, plaintext, aad: new Uint8Array(0) },
  { name: "multi-hybrid", mode: "hybrid", recipients: [0, 1, 2], anonymous: false, plaintext, aad },
  { name: "multi-mlkem-anonymous", mode: "mlkem", recipients: [2, 0], anonymous: true, plaintext: new Uint8Array(0), aad },
];
const envelopes = envelopeCases.map((c) => {
  const entropy = det(`entropy-${c.name}`, testing.sealEntropyLength(c.mode, c.recipients.length));
  const env = testing.sealWithEntropy(
    {
      chainId: CHAIN_ID,
      purpose: PURPOSE,
      mode: c.mode,
      anonymous: c.anonymous,
      recipients: c.recipients.map((i) => qs.recipientOf(keys[i])),
      plaintext: c.plaintext,
      aad: c.aad,
    },
    entropy,
  );
  for (const i of c.recipients) {
    const out = qs.open({ chainId: CHAIN_ID, purpose: PURPOSE, envelope: env, keys: keys[i], aad: c.aad });
    if (hex(out) !== hex(c.plaintext)) throw new Error(`round trip failed for ${c.name}`);
  }
  return {
    name: c.name,
    mode: c.mode,
    anonymous: c.anonymous,
    recipients: c.recipients,
    plaintext: hex(c.plaintext),
    aad: hex(c.aad),
    entropy: hex(entropy),
    size: env.length,
    envelope: hex(env),
    text: qs.envelopeToText(env),
  };
});
const byName = Object.fromEntries(envelopes.map((e) => [e.name, e]));

// Negative cases: a mutation of a vector envelope, the key that opens it and
// the error every implementation must report.
const single = byName["single-hybrid"];
const singleLen = single.size;
const negative = [
  { name: "wrong key", base: "single-hybrid", key: 1, error: "NOT_A_RECIPIENT" },
  { name: "wrong key, anonymous", base: "multi-mlkem-anonymous", key: 1, error: "DECRYPTION_FAILED" },
  { name: "wrong chain id", base: "single-hybrid", key: 0, chainId: "qorechain-vladi", error: "DECRYPTION_FAILED" },
  { name: "wrong purpose", base: "single-hybrid", key: 0, purpose: "chat", error: "DECRYPTION_FAILED" },
  { name: "wrong aad", base: "single-hybrid", key: 0, aad: hex(enc("invoice-43")), error: "DECRYPTION_FAILED" },
  { name: "missing aad", base: "single-hybrid", key: 0, aad: "", error: "DECRYPTION_FAILED" },
  { name: "tampered ciphertext", base: "single-hybrid", key: 0, flip: singleLen - 1, error: "DECRYPTION_FAILED" },
  { name: "tampered nonce", base: "single-hybrid", key: 0, flip: 28 + 1664, error: "DECRYPTION_FAILED" },
  { name: "tampered ML-KEM ciphertext", base: "single-hybrid", key: 0, flip: 28 + 16 + 100, error: "DECRYPTION_FAILED" },
  { name: "tampered X25519 key", base: "single-hybrid", key: 0, flip: 28 + 16 + 1568, error: "DECRYPTION_FAILED" },
  { name: "tampered wrapped key", base: "single-hybrid", key: 0, flip: 28 + 16 + 1568 + 32, error: "DECRYPTION_FAILED" },
  { name: "tampered salt", base: "single-hybrid", key: 0, flip: 10, error: "NOT_A_RECIPIENT" },
  { name: "tampered hint", base: "single-hybrid", key: 0, flip: 28, error: "NOT_A_RECIPIENT" },
  { name: "tampered other recipient", base: "multi-hybrid", key: 0, flip: 28 + 1664 + 500, error: "DECRYPTION_FAILED" },
  { name: "anonymous flag set", base: "single-hybrid", key: 0, set: [9, 1], error: "DECRYPTION_FAILED" },
  { name: "unknown version", base: "single-hybrid", key: 0, set: [4, 2], error: "UNSUPPORTED_VERSION" },
  { name: "unknown mode", base: "single-hybrid", key: 0, set: [5, 3], error: "UNSUPPORTED_ALGORITHM" },
  { name: "unknown KEM", base: "single-hybrid", key: 0, set: [6, 1], error: "UNSUPPORTED_ALGORITHM" },
  { name: "unknown flags", base: "single-hybrid", key: 0, set: [9, 2], error: "MALFORMED_ENVELOPE" },
  { name: "bad magic", base: "single-hybrid", key: 0, set: [0, 0x58], error: "MALFORMED_ENVELOPE" },
  { name: "zero recipients", base: "single-hybrid", key: 0, set: [27, 0], error: "MALFORMED_ENVELOPE" },
  { name: "too many recipients", base: "single-hybrid", key: 0, set: [27, 2], error: "MALFORMED_ENVELOPE" },
  { name: "truncated", base: "single-hybrid", key: 0, truncate: singleLen - plaintext.length - 1, error: "MALFORMED_ENVELOPE" },
  { name: "mode switched to mlkem", base: "single-hybrid", key: 0, set: [5, 2], error: "DECRYPTION_FAILED" },
];
// Run every negative case here so the file never records a wrong expectation.
for (const n of negative) {
  const env = qs.fromHex(byName[n.base].envelope);
  let e = Uint8Array.from(env);
  if (n.flip !== undefined) e[n.flip] ^= 0x01;
  if (n.set) e[n.set[0]] = n.set[1];
  if (n.truncate !== undefined) e = e.slice(0, n.truncate);
  let code = "none";
  try {
    qs.open({
      chainId: n.chainId ?? CHAIN_ID,
      purpose: n.purpose ?? PURPOSE,
      envelope: e,
      keys: keys[n.key],
      aad: n.aad !== undefined ? qs.fromHex(n.aad) : qs.fromHex(byName[n.base].aad),
    });
  } catch (err) {
    code = err.code;
  }
  if (code !== n.error) throw new Error(`negative case "${n.name}": expected ${n.error}, got ${code}`);
}

const textNegative = [
  { name: "padding", text: single.text + "=", error: "MALFORMED_ENVELOPE" },
  { name: "standard alphabet", text: single.text.replace(/-/g, "+").replace(/_/g, "/"), error: "MALFORMED_ENVELOPE" },
  { name: "missing prefix", text: single.text.slice("qoreseal:".length), error: "MALFORMED_ENVELOPE" },
  { name: "non-zero trailing bits", text: "qoreseal:AB", error: "MALFORMED_ENVELOPE" },
].filter((t) => t.text !== single.text);
for (const t of textNegative) {
  let code = "none";
  try {
    qs.envelopeFromText(t.text);
  } catch (err) {
    code = err.code;
  }
  if (code !== t.error) throw new Error(`text case "${t.name}": expected ${t.error}, got ${code}`);
}

// ---------------------------------------------------------------- card
const classical = qsign.deriveClassicalKey({ mnemonic: MNEMONIC });
const address = qsign.addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
const pq = qsign.deriveCanonicalPqKey({ mnemonic: MNEMONIC, address });
const cardKeys = qs.deriveSealKeys({ mnemonic: MNEMONIC });
const card = qs.signRecipientCard({
  chainId: CHAIN_ID,
  address,
  keys: cardKeys,
  classicalKey: classical,
  pqKey: pq,
  issuedAt: "2026-10-27T12:00:00Z",
});
qs.verifyRecipientCard({ card, chainId: CHAIN_ID, pqPublicKey: pq.publicKey, mlkemPublicKey: cardKeys.mlkemPublicKey });

// ---------------------------------------------------------------- registry
const register = qs.buildRegisterKemKeyMessage({ sender: address, mlkemPublicKey: cardKeys.mlkemPublicKey });
const remove = qs.buildRemoveKemKeyMessage({ sender: address });

// ---------------------------------------------------------------- groups
const epochKey = { epoch: 1n, key: det("epoch-1", 32) };
const epochEntropy = det("entropy-epoch", testing.sealEntropyLength("hybrid", 2));
const epochEnvelope = testing.sealWithEntropy(
  {
    chainId: CHAIN_ID,
    purpose: "epoch-key:my-rollup",
    recipients: [qs.recipientOf(keys[0]), qs.recipientOf(keys[1])],
    plaintext: qs.encodeEpochKey(epochKey),
  },
  epochEntropy,
);
const batchData = enc('{"txs":["transfer 5 to member-2","transfer 3 to member-1"]}');
const batchEntropy = det("entropy-batch", 44);
const batch = testing.sealBatchWithEntropy(
  { epochKey, context: "my-rollup", batchIndex: 7n, data: batchData },
  batchEntropy,
);

const sizes = [];
for (const mode of ["hybrid", "mlkem"]) {
  for (const [n, len] of [[1, 0], [1, 1024], [3, 1024], [10, 1024], [100, 1024]]) {
    sizes.push({ mode, recipients: n, plaintextLength: len, size: qs.envelopeSize({ mode, recipients: n, plaintextLength: len }) });
  }
}

const out = {
  format: "qoreseal-vectors-v1",
  description:
    "QoreSeal v1 test vectors (spec/qoreseal-v1.md). Generated by scripts/gen-vectors.mjs from the TypeScript package; every implementation must reproduce them byte for byte. Test keys only.",
  chainId: CHAIN_ID,
  purpose: PURPOSE,
  keys: keyVectors,
  mnemonicSeeds: mnemonicVectors,
  encapsulation: {
    recipient: 0,
    m: hex(m),
    ciphertext: hex(encaps.cipherText),
    sharedSecret: hex(encaps.sharedSecret),
  },
  x25519: {
    recipient: 0,
    ephemeralSecretKey: hex(eSk),
    ephemeralPublicKey: hex(ctX),
    sharedSecret: hex(ssX),
  },
  hybrid: {
    label: qs.HYBRID_LABEL,
    mlkemSharedSecret: hex(encaps.sharedSecret),
    x25519SharedSecret: hex(ssX),
    x25519Ciphertext: hex(ctX),
    x25519PublicKey: hex(keys[0].x25519PublicKey),
    shared: hex(combined),
  },
  kdf,
  hint: { salt: hex(salt), recipient: 0, hint: hex(qs.recipientHint(salt, keys[0].mlkemPublicKey)) },
  envelopes,
  negative,
  textNegative,
  card: {
    mnemonic: MNEMONIC,
    address,
    pqPublicKey: hex(pq.publicKey),
    sealKeysIndex: 0,
    text: qs.recipientCardText(card),
    card,
    negative: [
      { name: "other chain", chainId: "qorechain-vladi", error: "CARD_INVALID" },
      { name: "other ML-KEM key", mlkemKey: 1, error: "CARD_INVALID" },
      { name: "tampered X25519 key", x25519PublicKey: hex(keys[1].x25519PublicKey), error: "CARD_INVALID" },
      { name: "other address", address: qsign.addressFromPublicKey(qsign.deriveClassicalKey({ mnemonic: MNEMONIC, index: 1 }).publicKey, "secp256k1").bech32, error: "CARD_INVALID" },
    ],
  },
  registry: {
    sender: address,
    register: { typeUrl: register.typeUrl, value: hex(register.value) },
    remove: { typeUrl: remove.typeUrl, value: hex(remove.value) },
  },
  epoch: {
    purpose: "epoch-key:my-rollup",
    epoch: 1,
    key: hex(epochKey.key),
    payload: hex(qs.encodeEpochKey(epochKey)),
    recipients: [0, 1],
    entropy: hex(epochEntropy),
    envelope: hex(epochEnvelope),
  },
  batch: {
    epoch: 1,
    key: hex(epochKey.key),
    context: "my-rollup",
    batchIndex: 7,
    data: hex(batchData),
    entropy: hex(batchEntropy),
    blob: hex(batch.blob),
    ciphertextCommitment: hex(batch.ciphertextCommitment),
    plaintextCommitment: hex(batch.plaintextCommitment),
  },
  sizes,
};

// Card negatives are checked here too.
for (const n of out.card.negative) {
  let code = "none";
  try {
    const c = { ...card };
    if (n.x25519PublicKey) c.x25519PublicKey = n.x25519PublicKey;
    qs.verifyRecipientCard({
      card: c,
      chainId: n.chainId ?? CHAIN_ID,
      address: n.address,
      pqPublicKey: pq.publicKey,
      mlkemPublicKey: n.mlkemKey !== undefined ? keys[n.mlkemKey].mlkemPublicKey : cardKeys.mlkemPublicKey,
    });
  } catch (err) {
    code = err.code;
  }
  if (code !== n.error) throw new Error(`card case "${n.name}": expected ${n.error}, got ${code}`);
}

writeFileSync(join(root, "vectors/qoreseal-v1.json"), JSON.stringify(out, null, 2) + "\n");
console.log("wrote vectors/qoreseal-v1.json");
