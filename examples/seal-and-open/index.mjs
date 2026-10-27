// SPDX-License-Identifier: Apache-2.0
//
// Offline: seal one payload to two recipients and an auditor, open it, and
// see what fails when the context or the data changes.

import {
  envelopeSize,
  envelopeToText,
  generateSealKeys,
  isQoreSealError,
  open,
  parseEnvelope,
  recipientOf,
  seal,
} from "@qorechain/qoreseal";

const chainId = "qorechain-diana";
const purpose = "invoice";
const enc = new TextEncoder();
const dec = new TextDecoder();

const alice = generateSealKeys();
const bob = generateSealKeys();
const auditor = generateSealKeys();
const mallory = generateSealKeys();

const plaintext = enc.encode("Invoice 42: 120 QOR due on 2026-11-30");
const aad = enc.encode("invoice-42"); // authenticated, readable by anyone

const envelope = seal({
  chainId,
  purpose,
  recipients: [recipientOf(alice), recipientOf(bob), recipientOf(auditor)],
  plaintext,
  aad,
});
const parsed = parseEnvelope(envelope);
console.log(`envelope: ${envelope.length} bytes (${parsed.mode}, ${parsed.entries.length} recipients)`);
console.log(`expected: ${envelopeSize({ recipients: 3, plaintextLength: plaintext.length })} bytes`);
console.log(`text form: ${envelopeToText(envelope).slice(0, 48)}...`);

for (const [name, keys] of [["alice", alice], ["bob", bob], ["auditor", auditor]]) {
  console.log(`${name} reads: ${dec.decode(open({ chainId, purpose, envelope, keys, aad }))}`);
}

function attempt(label, fn) {
  try {
    fn();
    console.log(`${label}: opened (unexpected)`);
  } catch (err) {
    if (!isQoreSealError(err)) throw err;
    console.log(`${label}: ${err.code}`);
  }
}
attempt("mallory", () => open({ chainId, purpose, envelope, keys: mallory, aad }));
attempt("other purpose", () => open({ chainId, purpose: "chat", envelope, keys: alice, aad }));
attempt("other chain", () => open({ chainId: "qorechain-vladi", purpose, envelope, keys: alice, aad }));
attempt("other aad", () => open({ chainId, purpose, envelope, keys: alice, aad: enc.encode("invoice-43") }));
const tampered = Uint8Array.from(envelope);
tampered[tampered.length - 1] ^= 1;
attempt("tampered", () => open({ chainId, purpose, envelope: tampered, keys: alice, aad }));
