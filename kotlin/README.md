# QoreSeal for Kotlin and Java

ML-KEM-1024 (FIPS 203) encryption of data to QoreChain accounts, for the JVM
(Java 17+) and Android (API 24+). The library wraps the Rust implementation
(`crates/qoreseal`) through UniFFI and JNA, so its output is byte-identical to
the TypeScript, Rust, Go, Swift and Python packages; all of them are checked
against `vectors/qoreseal-v1.json`.

## Install

```kotlin
// JVM
implementation("io.github.qorechain:qoreseal:0.1.0")
// Android
implementation("io.github.qorechain:qoreseal-android:0.1.0")
```

The Android AAR ships R8 keep rules for JNA and the bindings.

## Example

```kotlin
import io.github.qorechain.qoreseal.*

val alice = generateSealKeys()
val bob = generateSealKeys()

val envelope = sealEnvelope(
    "qorechain-diana", "invoice",
    listOf(recipientOf(alice), recipientOf(bob)),
    "amount due: 120 QOR".toByteArray(),
    aad = "invoice-42".toByteArray(),
)
val text = envelopeToText(envelope) // "qoreseal:..."

val plaintext = openEnvelope("qorechain-diana", "invoice", envelope, bob, aad = "invoice-42".toByteArray())
```

- `mode = SealMode.MLKEM` uses the recipient's ML-KEM-1024 key alone; the default
  hybrid mode adds X25519 and needs the recipient's card (`verifyRecipientCard`).
- `deriveSealKeys(mnemonic)` derives keys from a mnemonic; keep the mnemonic or
  `keys.seed` backed up.
- `buildRegisterKemKeyMessage(sender, mlkemPublicKey)` builds the registry
  message; sign the transaction hybrid with QoreSign. The KEM key registry is
  available on testnet; on mainnet from the v3.2.5 upgrade.
- `EpochKeyManager` (close it, or use `use { }`), `sealBatch`, `openBatch` for
  private groups.

Errors are `QoreSealException`; `code` is the stable code shared by every
implementation.

Only the payload is confidential: addresses, amounts, timing and sizes stay
public, and losing the seed loses access to the data.

## Build locally

Needs Rust 1.95 and JDK 17 or 21 (run Gradle with `JAVA_HOME` pointing to it).

```sh
scripts/build-kotlin-natives.sh             # this machine's library -> kotlin/natives/
cd kotlin && ./gradlew test
```

`scripts/build-kotlin-natives.sh` takes a list of targets: `darwin-aarch64`,
`darwin-x86-64`, `linux-x86-64`, `linux-aarch64`, `win32-x86-64`, `android`
(or one ABI: `android-arm64-v8a`, `android-armeabi-v7a`, `android-x86_64`),
`host`, and `bindings` (regenerates
`src/main/kotlin/io/github/qorechain/qoreseal/qoreseal_ffi.kt`, UniFFI output,
do not edit by hand). The release workflow builds every target.

The Android module is included with `-PqoresealAndroid=true` and needs an
Android SDK (`ANDROID_HOME`) and, for the native libraries, NDK 27
(`ANDROID_NDK_HOME`):

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
ANDROID_NDK_HOME=... scripts/build-kotlin-natives.sh android
cd kotlin && ./gradlew -PqoresealAndroid=true :android:assembleRelease
```

Publishing is configured (Central Portal, signed) but runs only from the
release workflow; `./gradlew publishToMavenLocal` checks the packaging.

## License

Apache-2.0
