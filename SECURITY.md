# Security Policy

QoreSeal encrypts data to QoreChain accounts, so we treat security reports for it with priority.

## Reporting a vulnerability

Please **do not** report vulnerabilities through public issues, discussions or pull requests. Email:

**security@qore.network**

Include, as far as you can: a description and the impact, steps to reproduce or a proof of concept, the affected package (TypeScript, Rust, Go, Swift, Kotlin or Python) and version, and a suggested fix.

Qualifying reports are eligible for the QoreChain bug bounty; scope and rules are published at <https://www.qorechain.io/security>.

## What to expect

- We acknowledge your report and keep you informed while we investigate.
- We coordinate disclosure with you once a fix is released.

## Supported versions

QoreSeal is pre-1.0 and its construction is still under review (see `spec/qoreseal-v1.md`). Security fixes go into the latest minor version of each package.

## Cryptography

QoreSeal implements no cryptographic primitive itself; it composes standard ones (spec section 1). ML-KEM-1024 comes from the `qorechain-pqc` bindings (over `@noble/post-quantum`, `fips203` and Cloudflare CIRCL); X25519, HKDF, SHA3 and AES-256-GCM come from `@noble/curves`, `@noble/hashes`, `@noble/ciphers`, RustCrypto crates and the Go standard library. Account signatures come from QoreSign. Issues in those libraries should also be reported upstream.

## Scope reminders

QoreSeal protects payload content only. Metadata on chain (addresses, amounts, timing, sizes) is public by design; reports about it are welcome as documentation issues, not as vulnerabilities.
