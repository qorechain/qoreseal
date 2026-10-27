# QoreSeal for Swift

ML-KEM-1024 (FIPS 203) encryption of data to QoreChain accounts, for iOS 16+
and macOS 13+. The package wraps the Rust implementation (`crates/qoreseal`)
through UniFFI, so its output is byte-identical to the TypeScript, Rust, Go,
Kotlin and Python packages; all of them are checked against
`vectors/qoreseal-v1.json`.

It is offline: keys, envelopes, recipient cards, registry messages, epoch keys
and batches. Reading keys from the chain and broadcasting stay in your app.

## Install

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/qorechain/qoreseal", from: "0.1.0"),
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "QoreSeal", package: "qoreseal"),
    ]),
]
```

## Example

```swift
import QoreSeal

let alice = generateSealKeys()
let bob = generateSealKeys()

let envelope = try sealEnvelope(
    chainId: "qorechain-diana", purpose: "invoice",
    recipients: [recipientOf(keys: alice), recipientOf(keys: bob)],
    plaintext: Data("amount due: 120 QOR".utf8),
    aad: Data("invoice-42".utf8))
let text = envelopeToText(envelope: envelope) // "qoreseal:..."

let plaintext = try openEnvelope(
    chainId: "qorechain-diana", purpose: "invoice",
    envelope: envelope, keys: bob, aad: Data("invoice-42".utf8))
```

- `mode: .mlkem` uses the recipient's ML-KEM-1024 key alone; the default hybrid
  mode adds X25519 and needs the recipient's card (`verifyRecipientCard`).
- `deriveSealKeys(mnemonic:)` derives keys from a mnemonic; keep the mnemonic or
  `keys.seed` backed up.
- `buildRegisterKemKeyMessage(sender:mlkemPublicKey:)` builds the registry
  message; sign the transaction hybrid with QoreSign. The KEM key registry is
  available on testnet; on mainnet from the v3.2.5 upgrade.
- `EpochKeyManager`, `sealBatch`, `openBatch` for private groups.

Errors are `QoreSealError`; `code` is the stable code shared by every
implementation.

Only the payload is confidential: addresses, amounts, timing and sizes stay
public, and losing the seed loses access to the data.

## Build locally

Needs macOS with Xcode, Rust 1.95 and the Apple targets:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin
scripts/build-xcframework.sh          # swift/QoreSealFFI.xcframework + zip + checksum
QORESEAL_LOCAL_FFI=1 swift test
```

When `xcode-select` points to the Command Line Tools, prefix both commands
with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.

`Package.swift` uses `swift/QoreSealFFI.xcframework` when `QORESEAL_LOCAL_FFI`
is set or that directory exists (it is git-ignored). Otherwise it uses the
xcframework zip attached to the GitHub release.

The script also regenerates `swift/Sources/QoreSeal/QoreSeal.swift` (UniFFI
output, do not edit by hand); CI fails when the committed file is stale.

## Releasing

SwiftPM verifies the downloaded zip against the checksum in the tagged
`Package.swift`, so the checksum must be committed before the tag:

1. Set `releaseVersion` in `Package.swift`.
2. `scripts/build-xcframework.sh --write-checksum` builds the zip and writes
   its checksum into `releaseChecksum` (a zero placeholder until then).
3. Commit, tag `v<version>`, push the tag.
4. `gh release upload v<version> swift/QoreSealFFI.xcframework.zip` with that
   same zip. The release workflow checks the uploaded zip against
   `Package.swift`; when no zip is uploaded it attaches its own build only if
   the checksum matches.

## License

Apache-2.0
