# QoreSeal

ML-KEM-1024 (FIPS 203) encryption of data to QoreChain accounts, for dApps and
private sidechains. An account publishes its ML-KEM-1024 key on chain; anyone
can then encrypt a payload that only that account (and any other recipient you
add) can read.

QoreSeal is an open-source library of the QoreChain Association, in TypeScript,
Rust, Go, Swift, Kotlin/Java and Python, all byte-compatible through shared test
vectors.

> Status: 0.1.0, released. The construction composes standard
> primitives only and is pending an external review before 1.0. Read
> [spec/qoreseal-v1.md](spec/qoreseal-v1.md) before relying on it.

## What it does

- **Encrypts a payload to one or many recipients.** The payload is encrypted
  once with a random data key (AES-256-GCM); the data key is wrapped for each
  recipient with an ML-KEM-1024 encapsulation to that recipient's key.
- **Reads recipients from the chain.** Keys come from the chain's KEM key
  registry (`MsgRegisterKEMKey`, query `/qorechain/pqc/v1/kem/{address}`).
  The registry is available on testnet; on mainnet from the v3.2.5 upgrade.
- **Hybrid by default.** The default mode adds an X25519 agreement, so the data
  stays protected as long as either ML-KEM-1024 or X25519 holds. The X25519 key
  travels in a recipient card that the account signs with its ML-DSA-87 key
  (QoreSign).
- **Binds every envelope to a chain and a purpose.** Keys are derived with
  HKDF-SHA-256 and the info `"qorechain-kem-v1|" + chainId + "|" + purpose`,
  so data sealed for one chain or purpose cannot be opened under another.
- **Supports private groups and sidechains.** Epoch keys rotate on every
  membership change; batches are encrypted under the epoch key and come with
  commitments ready to anchor on QoreChain (for example with the RDK).

## What it does not do

Read this before you build on it:

- **Only the payload is confidential.** Sender and recipient addresses, amounts
  of bank transfers, transaction timing, envelope sizes and the number of
  recipients stay public on chain.
- **No zero-knowledge proofs.** Nothing here hides who transacts with whom or
  proves anything about the encrypted data.
- **Envelopes are not signed.** Anyone can encrypt to an address. Sign the
  envelope (for example with QoreSign `signMessage`) when the recipient must
  know who sent it.
- **Key loss loses data.** If the seed or mnemonic behind a key is lost,
  everything sealed to that key is lost with it. See
  [key backup](docs/guides/key-backup.md).
- **Removing a key does not erase data.** Data sealed to a key stays readable
  by whoever holds that key.

## Modes

| Mode | Per recipient | Needs | Use when |
|---|---|---|---|
| `hybrid` (default) | ML-KEM-1024 + X25519, combined with SHA3-256 | the key on chain and the recipient card | you can get the recipient's card |
| `mlkem` | ML-KEM-1024 | the key on chain only | you only have the address |

`mlkem` is never chosen silently: pass it explicitly.

## Packages

| Language | Package | Install |
|---|---|---|
| TypeScript | `@qorechain/qoreseal` | coming to npm with the next release; build from `packages/ts` meanwhile |
| Rust | `qorechain-qoreseal` (library `qoreseal`) | `cargo add qorechain-qoreseal` |
| Go | `github.com/qorechain/qoreseal/go` | `go get github.com/qorechain/qoreseal/go` |
| Swift | `QoreSeal` (iOS 16+, macOS 13+) | Swift Package Manager, this repository |
| Kotlin / Java | `io.github.qorechain:qoreseal`, `qoreseal-android` | Maven Central |
| Python | `qorechain-qoreseal` (import `qoreseal`) | `pip install qorechain-qoreseal` |

Swift, Kotlin and Python wrap the Rust implementation; TypeScript and Go are
native implementations. Network helpers (reading keys and cards from a REST
endpoint) are in TypeScript (`@qorechain/qoreseal/network`) and Go
(`github.com/qorechain/qoreseal/go/network`).

## Example

```ts
import { generateSealKeys, open, recipientOf, seal } from "@qorechain/qoreseal";

const alice = generateSealKeys();
const auditor = generateSealKeys();

const envelope = seal({
  chainId: "qorechain-diana",
  purpose: "invoice",
  recipients: [recipientOf(alice), recipientOf(auditor)],
  plaintext: new TextEncoder().encode("120 QOR due on 2026-11-30"),
});

const plaintext = open({ chainId: "qorechain-diana", purpose: "invoice", envelope, keys: auditor });
```

To encrypt to an address instead, see the [quickstart](docs/quickstart.md).

## Documentation

- [Quickstart](docs/quickstart.md): register a key, encrypt to an address, decrypt, in under ten minutes.
- Guides: [encrypt to an address](docs/guides/encrypt-to-an-address.md),
  [multi-recipient and auditor keys](docs/guides/multi-recipient-and-auditors.md),
  [private sidechain epochs with the RDK](docs/guides/private-sidechain-epochs.md),
  [key backup](docs/guides/key-backup.md).
- [Specification](spec/qoreseal-v1.md) and [test vectors](vectors/qoreseal-v1.json).
- [Examples](examples).
- Per language: [Rust](crates/qoreseal/README.md), [Go](go/README.md),
  [Swift](swift/README.md), [Kotlin](kotlin/README.md), [Python](python/README.md).

## Security

QoreSeal implements no cryptographic primitive itself; see
[SECURITY.md](SECURITY.md) for the libraries it relies on and how to report a
vulnerability.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
