// SPDX-License-Identifier: Apache-2.0
//
// Offline: a private rollup with three members. The operator encrypts every
// batch under the current epoch key; membership changes start a new epoch.
// The last step shows the fields an RDK settlement batch would carry.

import { createHash } from "node:crypto";
import {
  EpochKeyManager,
  PrivateBatchCodec,
  generateSealKeys,
  isQoreSealError,
  openBatch,
  openEpochKey,
  recipientOf,
  toHex,
} from "@qorechain/qoreseal";

const chainId = "qorechain-diana";
const rollupId = "demo-private-rollup";
const purpose = `epoch-key:${rollupId}`;
const enc = new TextEncoder();
const dec = new TextDecoder();

const members = { alice: generateSealKeys(), bob: generateSealKeys(), carol: generateSealKeys() };
const known = {}; // epoch keys each member has received
const receive = (name, rotation) => {
  if (!rotation.envelope || !rotation.members.includes(name)) return;
  (known[name] ??= []).push(openEpochKey({ chainId, purpose, envelope: rotation.envelope, keys: members[name] }));
};

// The operator starts the group with alice and bob (epoch 1).
const mgr = new EpochKeyManager({
  chainId,
  purpose,
  members: { alice: recipientOf(members.alice), bob: recipientOf(members.bob) },
});
const first = { epoch: mgr.epoch, envelope: mgr.distribution(), members: mgr.members() };
receive("alice", first);
receive("bob", first);
const codec = new PrivateBatchCodec(rollupId, mgr);

const batches = [];
batches.push(codec.seal(1, enc.encode('{"txs":["alice pays bob 5"]}')));

// carol joins: epoch 2, sealed to all three.
const join = mgr.addMember("carol", recipientOf(members.carol));
for (const name of join.members) receive(name, join);
batches.push(codec.seal(2, enc.encode('{"txs":["carol pays alice 3"]}')));

// bob leaves: epoch 3, sealed to alice and carol only.
const leave = mgr.removeMember("bob");
for (const name of leave.members) receive(name, leave);
batches.push(codec.seal(3, enc.encode('{"txs":["alice pays carol 1"]}')));

for (const b of batches) {
  const row = [`batch ${b.batchIndex} (epoch ${b.epoch})`];
  for (const name of Object.keys(members)) {
    try {
      const opened = openBatch({ blob: b.blob, keys: known[name] ?? [] });
      row.push(`${name}: ${dec.decode(opened.data)}`);
    } catch (err) {
      if (!isQoreSealError(err)) throw err;
      row.push(`${name}: ${err.code}`);
    }
  }
  console.log(row.join("\n  "));
}

// What goes on QoreChain for the last batch. With the RDK, the encrypted blob
// is the native DA blob, and its SHA-256 is the batch data_hash:
//
//   import { buildDaBlob, submitBatchMsg } from "@qorechain/rdk";
//   const blob = buildDaBlob({ data: sealed.blob, maxBlobSize: params.maxDaBlobSize });
//   const msg = submitBatchMsg({ sequencer, rollupId, batchIndex, stateRoot, txCount, dataHash: blob.dataHash });
//
// The ciphertext and plaintext commitments can go in your state transition or
// manifest: members recompute the plaintext one after decrypting; outsiders
// learn nothing from it because it is salted.
const sealed = batches.at(-1);
console.log("\nanchor fields for the last batch:");
console.log(`  data_hash (SHA-256 of the blob, as the RDK computes it): 0x${createHash("sha256").update(sealed.blob).digest("hex")}`);
console.log(`  ciphertext commitment (SHA3-256): ${toHex(sealed.ciphertextCommitment)}`);
console.log(`  plaintext commitment (salted SHA3-256): ${toHex(sealed.plaintextCommitment)}`);
console.log(`  blob size: ${sealed.blob.length} bytes`);
