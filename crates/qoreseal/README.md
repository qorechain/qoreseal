# qorechain-qoreseal

ML-KEM-1024 (FIPS 203) encryption of data to QoreChain accounts, for Rust. This
is the Rust implementation of QoreSeal; it is offline (no network code) and
byte-compatible with the other implementations through the shared test vectors
in `vectors/qoreseal-v1.json`.

It covers:

- key pairs (ML-KEM-1024 plus X25519) from a seed or a BIP-39 mnemonic;
- envelopes to one or many recipients, in `hybrid` mode (default: ML-KEM-1024
  and X25519) or `mlkem` mode (ML-KEM-1024 only);
- recipient cards: the X25519 key of the hybrid mode, signed by the account
  with QoreSign and bound to the ML-KEM key on chain;
- `MsgRegisterKEMKey` / `MsgRemoveKEMKey` for the chain's KEM key registry
  (available on testnet; on mainnet from the v3.2.5 upgrade);
- epoch keys and a batch codec for private groups and sidechains.

## Install

```sh
cargo add qorechain-qoreseal
```

The library is imported as `qoreseal`.

## Example

```rust
use qoreseal::{generate_seal_keys, open, seal, SealArgs, SealMode};

let alice = generate_seal_keys();
let bob = generate_seal_keys();
let recipients = [alice.recipient(), bob.recipient()];

let mut args = SealArgs::new("qorechain-diana", "invoice", &recipients, b"amount due: 120 QOR");
args.aad = b"invoice-42"; // authenticated, not encrypted
let envelope = seal(&args)?;

let plaintext = open("qorechain-diana", "invoice", &envelope, &bob, b"invoice-42")?;
assert_eq!(plaintext, b"amount due: 120 QOR");

// ML-KEM-1024 only: needs just the key on chain.
args.mode = SealMode::Mlkem;
```

Publish your key with `build_register_kem_key_message(address, &keys.mlkem_public_key)`
in a transaction signed hybrid with `qoresign::sign_hybrid`. Sign a recipient
card with `sign_recipient_card` so others can use the hybrid mode; verify one
with `verify_recipient_card` against the account's ML-DSA-87 and ML-KEM keys on
chain.

## Limits

- Only the payload is confidential. Addresses, amounts, timing and sizes stay public.
- No zero-knowledge proofs are involved.
- Envelopes are not signed; sign them with QoreSign when the sender matters.
- Losing the seed or mnemonic loses access to everything sealed to the key.

The construction composes standard primitives and has not yet had an external
review; it is planned before 1.0. Format: `spec/qoreseal-v1.md`.

## License

Apache-2.0.
