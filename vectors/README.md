# Test vectors

`qoreseal-v1.json` is generated from the TypeScript implementation (`pnpm build && pnpm vectors`) and checked by the TypeScript, Rust, Go, Swift, Kotlin and Python test suites. A change to the file is a change to the wire format: add a new file with a new version instead of editing this one.

All keys are test keys: seeds come from SHAKE256 of fixed labels, the card account from the public BIP-39 test mnemonic (`abandon ... about`). Never send funds to these accounts or encrypt real data to these keys.

| Field | Contents |
|---|---|
| `keys` | three key pairs from 32-byte seeds: ML-KEM-1024 public key, SHA3-256 of the secret key, X25519 keys |
| `mnemonicSeeds` | seeds derived from a mnemonic, passphrase (one in NFC form, to check NFKD normalization) and index |
| `encapsulation` | ML-KEM-1024 encapsulation with explicit randomness `m`: ciphertext and shared secret |
| `x25519`, `hybrid` | the X25519 agreement and the combined hybrid secret |
| `kdf` | HKDF info strings and derived keys, with and without salt |
| `hint` | a recipient hint |
| `envelopes` | single and multi-recipient envelopes in both modes (one anonymous) with the exact entropy consumed, binary and text forms |
| `negative`, `textNegative` | mutations of the envelopes (or wrong keys, chain ids, purposes, AAD) and the error code every implementation must report |
| `card` | recipient card fields, signed text and the signed card (QoreSign message signature, deterministic), the account's ML-DSA-87 public key, and cards that must be refused |
| `registry` | encoded `MsgRegisterKEMKey` and `MsgRemoveKEMKey` |
| `epoch` | an epoch key payload and its envelope to two members |
| `batch` | an encrypted batch blob with its commitments |
| `sizes` | envelope sizes for the spec's size table |

All byte strings are lowercase hex. The entropy order is in the specification, section 9.
