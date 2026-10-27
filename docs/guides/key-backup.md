# Key backup

Whoever holds a QoreSeal key reads everything ever sealed to it. Whoever loses
it loses that data: there is no recovery on chain, and the chain never sees a
secret key.

## What to back up

A QoreSeal key pair (ML-KEM-1024 and X25519) derives from one 32-byte seed.
Back up one of:

- **The account mnemonic.** `deriveSealKeys({ mnemonic, index })` derives the
  seed from a BIP-39 mnemonic (with an optional passphrase) and an index. If you
  already keep the account mnemonic safe, the QoreSeal keys come with it. This
  is the default in the quickstart.
- **A separate mnemonic.** Use a dedicated mnemonic when the encryption key must
  be held by someone other than the account's signer (for example a compliance
  team), or when you want to rotate it independently.
- **The raw seed.** `keys.seed` (32 bytes); `sealKeysFromSeed(seed)` restores
  both key pairs. Store it as you would a private key, encrypted at rest.

The derivations are fixed in [the specification](../../spec/qoreseal-v1.md)
(section 4) and covered by the test vectors, so every implementation restores
the same keys.

## Rotation

Move to the next index (`index: 1`, `2`, ...) and register the new ML-KEM key;
registering replaces the old one on chain. Sign a new recipient card: old cards
stop verifying once the key on chain changes.

Keep the old seeds or indexes: envelopes already sealed to an old key still need
it. Rotating does not re-encrypt anything.

`MsgRemoveKEMKey` withdraws the key from the registry so no new envelopes are
made for it. It does not delete or protect data already sealed.

## Recovery keys

For data that must survive the loss of a user's key, add a recovery recipient
to every envelope: a key held offline by the user (a second mnemonic on paper)
or by an organisation the user trusts. A recovery recipient reads everything it
is added to, so treat it like an auditor key (see
[multi-recipient and auditor keys](multi-recipient-and-auditors.md)).

For groups, the operator's `exportKeys()` holds every epoch key. Seal that
export to the operator's own key and to an offline recovery key, and keep it
outside the machine that runs the sequencer.

## Wallets

A wallet that integrates QoreSeal should derive the keys from the account
mnemonic (index 0), show the recipient card for signing as plain text (it is a
QoreSign message signature), and never export the ML-KEM secret key on its own:
export the seed or the mnemonic.
