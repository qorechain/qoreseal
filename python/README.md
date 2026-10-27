# qorechain-qoreseal (Python)

ML-KEM-1024 (FIPS 203) encryption of data to QoreChain accounts, for Python 3.9+.
The package wraps the Rust implementation through UniFFI, so its output is
byte-identical to the TypeScript, Rust, Go, Swift and Kotlin packages; all of
them are checked against `vectors/qoreseal-v1.json`.

## Install

```sh
pip install qorechain-qoreseal
```

Wheels: macOS (arm64, x86_64), Linux (manylinux2014 x86_64, aarch64), Windows x86_64.

## Example

```python
import qoreseal as qs

alice = qs.generate_seal_keys()
bob = qs.generate_seal_keys()

envelope = qs.seal_envelope(
    "qorechain-diana", "invoice",
    [qs.recipient_of(alice), qs.recipient_of(bob)],
    b"amount due: 120 QOR",
    aad=b"invoice-42",
)
text = qs.envelope_to_text(envelope)  # "qoreseal:..."

plaintext = qs.open_envelope("qorechain-diana", "invoice", envelope, bob, aad=b"invoice-42")
assert plaintext == b"amount due: 120 QOR"
```

- `mode=qs.SealMode.MLKEM` uses the recipient's ML-KEM-1024 key alone; the default
  `HYBRID` adds X25519 and needs the recipient's card (`verify_recipient_card`).
- Keys from a mnemonic: `qs.derive_seal_keys(mnemonic)`; back up the mnemonic or
  `keys.seed`.
- Publish your key: `qs.build_register_kem_key_message(address, keys.mlkem_public_key)`,
  then sign the transaction hybrid (QoreSign). The KEM key registry is available
  on testnet; on mainnet from the v3.2.5 upgrade.
- Private groups: `qs.EpochKeyManager`, `qs.seal_batch`, `qs.open_batch`.

Errors raise `qs.QoreSealError.Failure` with a stable `code`.

## Limits

Only the payload is confidential: addresses, amounts, timing and sizes stay
public; no zero-knowledge proof is involved; envelopes are not signed; losing the
seed or mnemonic loses access to the data. The construction is pending external
review before 1.0.

## License

Apache-2.0.
