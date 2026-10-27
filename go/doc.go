// SPDX-License-Identifier: Apache-2.0

// Package qoreseal encrypts data to QoreChain accounts with ML-KEM-1024
// (FIPS 203), for dApps and private sidechains. It implements QoreSeal v1
// (spec/qoreseal-v1.md in the repository) and produces bytes identical to
// the TypeScript, Rust, Swift, Kotlin and Python packages; the shared vectors
// in vectors/qoreseal-v1.json are the contract.
//
// A payload is encrypted once with a random data key under AES-256-GCM, and
// the data key is wrapped for each recipient. The default mode, hybrid,
// combines an ML-KEM-1024 encapsulation to the recipient's key registered on
// chain with an X25519 agreement to the X25519 key of the recipient's signed
// card; the mlkem mode uses the registered key alone and must be chosen
// explicitly.
//
// The package also builds the registry messages (MsgRegisterKEMKey,
// MsgRemoveKEMKey; sign the transaction hybrid with QoreSign), signs and
// verifies recipient cards, and provides epoch keys (EpochKeyManager) and a
// batch codec (SealBatch, OpenBatch) for private groups and sidechains. The
// network subpackage reads recipients from a REST endpoint.
//
// Limits: only the content of the payload is protected. Addresses, amounts,
// timing, sizes and the number of recipients stay public; no zero-knowledge
// proofs are involved; envelopes are not signed; losing the seed or mnemonic
// loses access to the data sealed to the key.
package qoreseal
