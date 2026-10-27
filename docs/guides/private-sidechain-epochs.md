# Private sidechain epochs with the RDK

A private sidechain (or app-chain rollup) keeps its batch data readable only by
its members while still anchoring to QoreChain. QoreSeal gives the operator two
pieces:

- `EpochKeyManager`: one shared 32-byte key per epoch, sealed to the current
  members, replaced on every membership change.
- `PrivateBatchCodec` (`sealBatch` / `openBatch`): batch data encrypted under
  the epoch key, with a ciphertext commitment and a salted plaintext commitment.

The RDK (`@qorechain/rdk` and its other languages) stays unchanged: QoreSeal
produces the bytes, the RDK submits and anchors them.

## What stays public

The chain sees the encrypted blob, its size, the batch index, the epoch number,
the context (for example the rollup id), the commitments and everything the RDK
normally publishes (state roots, sequencer, timing). Members see the batch
contents. This is payload confidentiality for the group, not a zero-knowledge
system: verifiers outside the group cannot check what happens inside a batch.

## Epochs

```ts
import { EpochKeyManager, PrivateBatchCodec, openEpochKey, openBatch, recipientOf } from "@qorechain/qoreseal";

const purpose = "epoch-key:my-rollup";
const mgr = new EpochKeyManager({
  chainId: "qorechain-diana",
  purpose,
  members: { alice: aliceRecipient, bob: bobRecipient }, // SealRecipient, e.g. from resolveRecipient()
});

// Send each member the current epoch key (store or relay the envelope).
const envelope = mgr.distribution();

// Membership changes start a new epoch and return its envelope.
const joined = mgr.addMember("carol", carolRecipient); // epoch 2: alice, bob, carol
const left = mgr.removeMember("bob");                  // epoch 3: alice, carol

// Member side:
const epochKey = openEpochKey({ chainId: "qorechain-diana", purpose, envelope: left.envelope!, keys: myKeys });
```

Rules that follow from this design:

- A member added at epoch N reads epochs N and later, not earlier ones. To give
  a newcomer history, seal the older epoch keys to it explicitly
  (`sealEpochKey`).
- A removed member keeps the keys of the epochs it belonged to, so it can still
  read those batches. It cannot read later ones.
- `rotate()` starts a new epoch without a membership change; do it on a
  schedule as well. A key is safe for far more than 2^32 batches, so rotation
  is about limiting exposure, not about the cipher.
- `exportKeys()` returns every epoch key. Store it encrypted (for example as an
  envelope sealed to the operator's own key and an offline recovery key);
  `new EpochKeyManager({ ..., history })` restores it.

## Batches and anchoring

```ts
import { buildDaBlob, submitBatchMsg } from "@qorechain/rdk";

const codec = new PrivateBatchCodec("my-rollup", mgr);
const sealed = codec.seal(batchIndex, batchBytes);

// The encrypted blob is the native DA blob; its SHA-256 is the batch data_hash.
const blob = buildDaBlob({ data: sealed.blob, maxBlobSize: params.maxDaBlobSize });
const msg = submitBatchMsg({
  sequencer,
  rollupId: "my-rollup",
  batchIndex,
  stateRoot,
  txCount,
  dataHash: blob.dataHash,
});
```

- `sealed.ciphertextCommitment` is SHA3-256 of the blob: anyone can check that
  the published blob is the committed one.
- `sealed.plaintextCommitment` is SHA3-256 of a random salt and the batch data.
  Members recompute it after `openBatch` and compare; outsiders learn nothing
  from it, because the salt stops guessing attacks on low-entropy data. Put it
  in your state transition or batch manifest if your rollup logic needs to bind
  the plaintext.
- Blob size is `83 + context length + data length` bytes; check it against the
  chain's `max_da_blob_size`.

The `private-rollup` example in [examples](../../examples) runs this flow
offline with three members, a join and a removal.

## Other languages

Go: `qoreseal.NewEpochKeyManager`, `qoreseal.NewPrivateBatchCodec`,
`qoreseal.SealBatch`, `qoreseal.OpenBatch`. Rust: `EpochKeyManager::new`,
`PrivateBatchCodec::new`, `seal_batch`, `open_batch`. Swift, Kotlin and Python:
the `EpochKeyManager` object (with `sealBatch`/`openBatch` methods) and the
`sealBatch`/`openBatch` functions.
