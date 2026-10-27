# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org); before 1.0, a minor version may contain breaking changes, which are always called out.

## [0.1.0] - Unreleased

First release, in TypeScript, Rust, Go, Swift, Kotlin and Python. The construction is pending an external review before 1.0.

### Added

- QoreSeal v1 specification (`spec/qoreseal-v1.md`) and shared test vectors (`vectors/qoreseal-v1.json`), checked byte for byte in every language.
- Key pairs (ML-KEM-1024 and X25519) from a 32-byte seed or a BIP-39 mnemonic and index.
- Envelopes to 1 to 1024 recipients: `hybrid` mode (default, ML-KEM-1024 plus X25519 combined with SHA3-256) and `mlkem` mode (ML-KEM-1024 only, chosen explicitly); HKDF-SHA-256 bound to the chain id and purpose; AES-256-GCM; optional AAD; salted recipient hints or anonymous entries; binary and `qoreseal:` text forms.
- Recipient cards: the X25519 key of the hybrid mode, signed with QoreSign message signing and bound to the account's ML-KEM key on chain.
- `MsgRegisterKEMKey` and `MsgRemoveKEMKey` builders and the registry's error codes (KEM key registry available on testnet; on mainnet from the v3.2.5 upgrade).
- Private groups and sidechains: `EpochKeyManager` (a new epoch key on every membership change, sealed to the current members) and the batch codec with ciphertext and salted plaintext commitments.
- Network helpers (TypeScript and Go): read a KEM key, resolve a recipient with its card, seal to addresses.
- Examples: offline sealing, testnet registration and encryption, a private rollup with three members.
