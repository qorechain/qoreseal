# QoreSeal, version 1

Status: draft, review in progress. The construction composes standard primitives only; it has not yet had an external review, which is planned before 1.0.

QoreSeal encrypts data to QoreChain accounts. The recipient's ML-KEM-1024 (FIPS 203) encapsulation key is read from the account's on-chain KEM key registry; the payload is encrypted once with a random data key, and that key is wrapped separately for every recipient.

All integers are big-endian. `||` is byte concatenation. `UTF8(s)` is the UTF-8 encoding of a string. Hex is lowercase.

## 1. Primitives

| Use | Primitive |
|---|---|
| Key encapsulation | ML-KEM-1024 (FIPS 203): encapsulation key 1568 bytes, decapsulation key 3168 bytes, ciphertext 1568 bytes, shared secret 32 bytes |
| Classical key agreement (hybrid mode) | X25519 (RFC 7748) |
| Combiner (hybrid mode) | SHA3-256 (FIPS 202) |
| Key derivation | HKDF-SHA-256 (RFC 5869) |
| Authenticated encryption | AES-256-GCM (NIST SP 800-38D), 96-bit nonce, 128-bit tag |
| Hints, commitments | SHA3-256 |

No primitive is implemented by QoreSeal itself.

## 2. Modes

| Mode | Byte | Per-recipient secret |
|---|---|---|
| `hybrid` (default) | `0x01` | ML-KEM-1024 encapsulation **and** X25519 ephemeral-static agreement, combined with SHA3-256 |
| `mlkem` | `0x02` | ML-KEM-1024 encapsulation only |

`hybrid` stays confidential as long as either ML-KEM-1024 or X25519 holds. It needs the recipient's X25519 public key, which the chain does not store; it comes from a signed recipient card (section 7). `mlkem` needs only the key on chain. An implementation must not fall back from `hybrid` to `mlkem` on its own: the caller chooses `mlkem` explicitly.

## 3. Context strings

| String | Use |
|---|---|
| `"qorechain-kem-v1\|" + chainId + "\|" + purpose` | HKDF info of every key-encryption key |
| `"qorechain-qoreseal-hybrid-v1"` | combiner label |
| `"qorechain-qoreseal-hint-v1"` | recipient hint |
| `"qorechain-qoreseal-keys-v1\|ml-kem-1024"`, `"qorechain-qoreseal-keys-v1\|x25519"` | key derivation from a seed |
| `"qorechain-qoreseal-mnemonic-v1\|" + index` | seed derivation from a mnemonic |
| `"qorechain-qoreseal-batch-v1"` | batch plaintext commitment |

- `chainId` matches `^[A-Za-z0-9._-]{1,64}$`, for example `qorechain-diana`.
- `purpose` matches `^[A-Za-z0-9._:/-]{1,128}$` and names what the data is for in the application (for example `chat`, `invoice`, `epoch-key:my-rollup`). Different purposes give unrelated keys, so data sealed for one purpose cannot be opened under another.

Both are inputs of `seal` and `open`; they are not written into the envelope. The recipient must know them, as the sender does.

## 4. Recipient keys

A QoreSeal key pair is an ML-KEM-1024 key pair and an X25519 key pair, both derived from one 32-byte seed. Backing up the seed (or the mnemonic it comes from) backs up both keys.

```
mlkemSeed = HKDF-SHA-256(ikm = seed, salt = "", info = "qorechain-qoreseal-keys-v1|ml-kem-1024", L = 64)
(ek, dk)  = ML-KEM-1024.KeyGen_internal(d = mlkemSeed[0..32], z = mlkemSeed[32..64])
x25519Sk  = HKDF-SHA-256(ikm = seed, salt = "", info = "qorechain-qoreseal-keys-v1|x25519", L = 32)
x25519Pk  = X25519(x25519Sk, 9)
```

From a BIP-39 mnemonic (the account's own, or a separate one):

```
bip39Seed = BIP-39 seed(mnemonic, passphrase)                       (64 bytes)
seed      = HKDF-SHA-256(ikm = bip39Seed, salt = "",
                         info = "qorechain-qoreseal-mnemonic-v1|" + decimal(index), L = 32)
```

`index` is 0 to 2^31-1 (default 0). Moving to the next index is how a key is rotated without a new mnemonic.

An ML-KEM-1024 encapsulation key is accepted only if it is 1568 bytes, every 12-bit coefficient of its first 1536 bytes is below 3329 (FIPS 203 modulus check) and those 1536 bytes do not decode to all zeros. These are the checks the chain applies at registration. An X25519 public key is 32 bytes.

## 5. Envelope

### 5.1 Layout

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `"QSEL"` (`51 53 45 4c`) |
| 4 | 1 | version, `0x01` |
| 5 | 1 | mode: `0x01` hybrid, `0x02` mlkem |
| 6 | 1 | KEM: `0x02` = ML-KEM-1024 (the chain's algorithm id) |
| 7 | 1 | KDF: `0x01` = HKDF-SHA-256 |
| 8 | 1 | AEAD: `0x01` = AES-256-GCM |
| 9 | 1 | flags: bit 0 = anonymous; other bits must be 0 |
| 10 | 16 | salt (random) |
| 26 | 2 | `n`, number of recipients, 1 to 1024 |
| 28 | n * W | recipient entries |
| 28 + n * W | 12 | payload nonce (random) |
| 40 + n * W | rest | payload ciphertext and tag (at least 16 bytes) |

The first 28 bytes are the **fixed header**. Everything before the payload ciphertext (fixed header, entries, nonce) is the **header**.

Recipient entry:

| Size | Field |
|---|---|
| 16 | hint |
| 1568 | ML-KEM-1024 ciphertext |
| 32 | X25519 ephemeral public key (hybrid only) |
| 48 | wrapped data key (32 bytes + 16-byte tag) |

`W` is 1664 bytes in hybrid mode and 1632 in mlkem mode.

### 5.2 Sealing

Inputs: `chainId`, `purpose`, recipients (each an encapsulation key `ek` and, in hybrid mode, an X25519 key `pkX`), plaintext, optional user AAD (default empty), mode (default hybrid), anonymous (default false).

1. Check the inputs. Every `ek` passes the checks of section 4; in hybrid mode every recipient has `pkX`, otherwise fail with `RECIPIENT_NEEDS_X25519`.
2. `salt` = 16 random bytes. `dek` = 32 random bytes (the data key).
3. Fixed header as in 5.1.
4. For each recipient, in the order given:
   - `hint` = 16 zero bytes if anonymous, else `SHA3-256(UTF8("qorechain-qoreseal-hint-v1") || salt || ek)[0..16]`.
   - `(ctK, ssK)` = ML-KEM-1024.Encaps(ek), with 32 random bytes `m`.
   - hybrid: `eSk` = 32 random bytes, `ctX = X25519(eSk, 9)`, `ssX = X25519(eSk, pkX)`; fail with `INVALID_KEY` if `ssX` is all zero.
     `shared = SHA3-256(UTF8("qorechain-qoreseal-hybrid-v1") || ssK || ssX || ctX || pkX)`.
   - mlkem: `shared = ssK`.
   - `kek = HKDF-SHA-256(ikm = shared, salt = salt, info = UTF8("qorechain-kem-v1|" + chainId + "|" + purpose), L = 32)`.
   - `wrapped = AES-256-GCM.Seal(kek, nonce = 12 zero bytes, plaintext = dek, aad = fixedHeader || hint || ctK || ctX)` (`ctX` absent in mlkem mode). The zero nonce is safe because every `kek` comes from a fresh encapsulation and is used once.
5. `nonce` = 12 random bytes. `ciphertext = AES-256-GCM.Seal(dek, nonce, plaintext, aad = header || userAad)`.

The header is self-delimiting, so `header || userAad` is unambiguous.

### 5.3 Opening

Inputs: envelope, `chainId`, `purpose`, the recipient's key pair, optional user AAD. Checks run in this order, so every implementation reports the same error:

1. Fewer than 10 bytes or wrong magic: `MALFORMED_ENVELOPE`. Version other than 1: `UNSUPPORTED_VERSION`. Unknown mode, KEM, KDF or AEAD byte: `UNSUPPORTED_ALGORITHM`. Unknown flag bits, fewer than 28 bytes, `n` of 0 or above 1024, or fewer than `40 + n * W + 16` bytes: `MALFORMED_ENVELOPE`.
2. Candidate entries: all of them when the anonymous flag is set, else those whose hint equals the recipient's own hint for this salt. None: `NOT_A_RECIPIENT`.
3. For each candidate in order: decapsulate, recompute `shared` and `kek` as in 5.2 (fail on an all-zero `ssX` for that entry only), and open `wrapped`. The first entry that opens gives `dek`. None: `DECRYPTION_FAILED`.
4. Open the payload with `dek`, the nonce and `header || userAad`. Failure: `DECRYPTION_FAILED`.

A wrong `chainId`, `purpose` or AAD, and any change to the header or ciphertext, end in `DECRYPTION_FAILED`.

### 5.4 Text form

`"qoreseal:" + base64url(envelope)`, without padding (RFC 4648 section 5). Decoders reject padding, characters outside the alphabet and non-zero trailing bits, with `MALFORMED_ENVELOPE`.

### 5.5 Sizes

`size = 56 + n * W + plaintextLength`; the text form is `9 + ceil(size * 4 / 3)` characters.

| Recipients | Plaintext | hybrid (bytes) | mlkem (bytes) |
|---|---|---|---|
| 1 | 0 | 1,720 | 1,688 |
| 1 | 1,024 | 2,744 | 2,712 |
| 3 | 1,024 | 6,072 | 5,976 |
| 10 | 1,024 | 17,720 | 17,400 |
| 100 | 1,024 | 167,480 | 164,280 |

### 5.6 Recipient hints

The hint lets a recipient find its entry without trying all of them. It is not anonymity: anyone who knows a candidate's encapsulation key (on chain, so public) can test whether that key is a recipient. Hints are salted, so they do not link envelopes to each other for someone who does not know the candidate keys. With the anonymous flag the hints are zero and recipients try every entry (one ML-KEM decapsulation each); ML-KEM ciphertexts do not identify the key they were made for.

## 6. Registry messages

The chain's KEM key registry is in `qorechain.pqc.v1` (proto: `tx.proto`, `query.proto`). Available on testnet; on mainnet from the v3.2.5 upgrade.

```
MsgRegisterKEMKey { string sender = 1; uint32 algorithm_id = 2; bytes public_key = 3; }   // algorithm_id 2 = ML-KEM-1024
MsgRemoveKEMKey   { string sender = 1; }
GET /qorechain/pqc/v1/kem/{address}   -> { found, key { address, algorithm_id, algorithm_name, public_key, registered_height } }
```

Type URLs: `/qorechain.pqc.v1.MsgRegisterKEMKey`, `/qorechain.pqc.v1.MsgRemoveKEMKey`. Fields with default values are omitted from the protobuf encoding, as usual. The registration is authenticated by the transaction's hybrid signature: the sender must already have a post-quantum signature key, and the transaction is signed hybrid (QoreSign `signHybrid`). Registering again replaces the key; there is one key per account. The query accepts a `qor1` or `0x` address.

Errors (codespace `pqc`):

| Code | Meaning |
|---|---|
| 250 | the KEM key registry is not enabled on this chain yet |
| 251 | invalid KEM public key |
| 252 | no KEM key published for this account |
| 253 | this KEM key is already published for this account |
| 254 | publishing a KEM key needs a registered post-quantum signature key |

## 7. Recipient card

The registry holds only the ML-KEM key. A recipient card carries the X25519 key for hybrid mode, signed by the account with QoreSign message signing (ADR-36 secp256k1 plus ML-DSA-87 over `"qorechain-msg-v1|" + chainId + "|" + data`, see QoreSign `spec/message-signing-v1.md`). Cards are self-authenticating, so they can travel over any channel (a profile page, an API, a QR code, a contract).

Signed data (`data`), lines joined with `"\n"`, no trailing newline:

```
QoreSeal recipient card v1
Chain ID: <chainId>
Address: <qor1 address>
ML-KEM-1024 key SHA3-256: <hex of SHA3-256(ek)>
X25519 key: <hex of pkX>
Issued at: <YYYY-MM-DDTHH:MM:SSZ>
```

JSON form:

```json
{
  "version": 1,
  "chainId": "qorechain-diana",
  "address": "qor1...",
  "mlkemKeySha3": "<64 hex>",
  "x25519PublicKey": "<64 hex>",
  "issuedAt": "2026-10-27T12:00:00Z",
  "signature": { "signatureType": "ml-dsa-87-hybrid", "classical": { ... }, "pq": { ... } }
}
```

Verification, given the expected chain id and address, the account's registered ML-DSA-87 key and its registered ML-KEM key `ek`:

1. `version` is 1; fields are well formed; `chainId` and `address` are the expected ones. Otherwise `CARD_INVALID`.
2. `SHA3-256(ek)` equals `mlkemKeySha3`, otherwise `CARD_INVALID`. A card is therefore valid only while the key it names is the registered one; replacing the KEM key retires every card issued for the old one.
3. QoreSign `verifyMessage` with the PQ part required. Any failure: `CARD_INVALID`.

The result is the hybrid recipient `(ek, pkX)`.

A forged or stale card can only weaken hybrid mode to the strength of ML-KEM-1024 alone: the ML-KEM part always uses the key on chain. QoreSeal derives both keys from one seed, so they rotate together.

## 8. Private groups and sidechains

### 8.1 Epoch keys

A group (for example the members of a private rollup) shares a 32-byte epoch key. On every membership change the operator draws a new random key, increments the epoch number and seals it to the current members. Removed members keep the keys of epochs they belonged to, and cannot read later epochs. New members get only the epochs from their joining on.

Epoch key payload (45 bytes), sealed in an ordinary envelope:

| Size | Field |
|---|---|
| 4 | magic `"QSEK"` |
| 1 | version `0x01` |
| 8 | epoch number (u64, starts at 1) |
| 32 | epoch key |

### 8.2 Batch blob

| Size | Field |
|---|---|
| 4 | magic `"QSBT"` |
| 1 | version `0x01` |
| 1 | AEAD `0x01` = AES-256-GCM |
| 8 | epoch (u64) |
| 8 | batch index (u64) |
| 1 | context length `c`, 1 to 128 |
| c | context, same characters as `purpose` (for example the rollup id) |
| 12 | nonce (random) |
| rest | `AES-256-GCM.Seal(epochKey, nonce, commitSalt || data, aad = all bytes before the ciphertext)` |

`commitSalt` is 32 random bytes. Size: `83 + c + dataLength`.

Commitments, ready to anchor:

```
ciphertextCommitment = SHA3-256(blob)
plaintextCommitment  = SHA3-256(UTF8("qorechain-qoreseal-batch-v1") || commitSalt || data)
```

The plaintext commitment is salted because a plain hash of low-entropy data (a balance, a yes/no vote) can be checked by guessing. Members, who can decrypt, recompute it; outsiders learn nothing from it. Opening a blob checks its header (`MALFORMED_BATCH`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_ALGORITHM`), needs the key of its epoch (`UNKNOWN_EPOCH`) and fails with `DECRYPTION_FAILED` on any change.

## 9. Deterministic test hooks

For the shared vectors only, implementations accept the randomness of `seal` as one byte string, consumed in this order: salt (16), data key (32), then for each recipient ML-KEM `m` (32) and, in hybrid mode, the X25519 ephemeral secret (32), then the payload nonce (12). Its length must be exact. Batch sealing takes the nonce (12) then `commitSalt` (32). These entry points are named for testing and must never be used with real data.

## 10. Limits

- QoreSeal protects the content of the payload only. Addresses, amounts of bank transfers, transaction timing, sizes and the number of recipients stay public.
- No zero-knowledge proofs are involved. Nothing here hides who transacts with whom.
- Envelopes are not signed. Anyone can encrypt to an address, and any recipient of a multi-recipient envelope can produce a different envelope for the others. Sign the envelope (for example with QoreSign `signMessage`) when the sender must be authenticated.
- Losing the seed or mnemonic loses access to everything sealed to the key. Removing a key from the registry does not delete data already sealed to it.
- A random 96-bit nonce per message keeps AES-256-GCM safe for well over 2^32 messages per key; rotate epoch keys long before that.

## 11. Test vectors

`vectors/qoreseal-v1.json`, generated from the TypeScript package (`scripts/gen-vectors.mjs`).
