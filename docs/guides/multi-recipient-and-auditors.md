# Multi-recipient and auditor keys

One envelope can have up to 1024 recipients. The payload is encrypted once
under a random data key; each recipient gets its own wrap of that key (one
ML-KEM-1024 encapsulation, plus X25519 in hybrid mode). Every recipient reads
the same plaintext, and adding a recipient costs 1664 bytes (hybrid) or 1632
bytes (mlkem), whatever the payload size.

```ts
const envelope = seal({
  chainId: "qorechain-diana",
  purpose: "rwa-transfer",
  recipients: [recipientOf(buyer), recipientOf(seller), auditor],
  plaintext,
  aad: new TextEncoder().encode(`asset:${assetId}`),
});
```

## Auditor (view) keys

An auditor key is an ordinary QoreSeal key pair whose public half you add to
every envelope that must stay readable for an audit. It does not need to belong
to a funded account or be registered on chain: pass its public keys directly as
a recipient. Some patterns:

- **A fixed auditor.** Keep the auditor's `SealRecipient` (ML-KEM-1024 key and
  X25519 key) in your configuration and append it to every recipient list.
- **One auditor key per period.** Derive keys from one mnemonic with
  `deriveSealKeys({ mnemonic, index })` and use a new index each quarter. Hand
  the auditor only the seeds of the periods under review: each seed opens
  exactly the envelopes of its period.
- **Escrowed recovery.** Add a recovery key held offline. It works like an
  auditor key and protects users who lose their own key (see
  [key backup](key-backup.md)).

## What recipients can and cannot do

- Every recipient can decrypt the whole payload. There is no per-recipient
  redaction: seal separate envelopes when readers must see different data.
- Any recipient could build a different envelope for the others, because
  envelopes are not signed. When the content must be attributable, sign it
  (QoreSign `signMessage`) and seal the signed message, or sign the envelope.
- The recipient list is visible as a count, and as hints. A hint lets a
  recipient find its entry quickly; anyone who knows a candidate's public key
  can check whether that key is a recipient. Set `anonymous: true` to zero the
  hints; recipients then try every entry, which costs one decapsulation per
  entry.
- Removing a recipient from future envelopes does not remove it from envelopes
  already sent.

## Sealed bids and commit-reveal

Seal bids to the auction's key with `purpose: "bid:<auction id>"` and the bidder
address as AAD, store the envelopes (for example in a contract), and open them
after the deadline. The auction key holder can read bids early, so pick a
holder the bidders trust, or split the role with several recipients.
