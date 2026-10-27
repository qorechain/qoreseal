# Contributing to QoreSeal

Thanks for your interest. Issues, pull requests and discussion are welcome.

## Layout

| Path | Contents |
|---|---|
| `packages/ts` | TypeScript package `@qorechain/qoreseal` (the reference implementation) |
| `crates/qoreseal` | Rust crate `qorechain-qoreseal` (library `qoreseal`) |
| `crates/qoreseal-ffi` | bindings layer used by the Swift, Kotlin and Python packages (not published) |
| `go` | Go module `github.com/qorechain/qoreseal/go` |
| `swift`, `Package.swift` | Swift package `QoreSeal` |
| `kotlin` | Kotlin/JVM library `io.github.qorechain:qoreseal` |
| `python` | Python package `qorechain-qoreseal` (import `qoreseal`) |
| `spec` | wire formats |
| `vectors` | test vectors shared by every implementation |
| `docs`, `examples` | guides and runnable examples |

## Build and test

```bash
pnpm install && pnpm build && pnpm lint && pnpm typecheck && pnpm test   # TypeScript
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test   # Rust
(cd go && gofmt -l . && go vet ./... && go test ./...)                      # Go
pip install -r python/requirements-dev.txt && scripts/build-python-wheels.sh \
  && pip install --no-index --find-links python/dist qorechain-qoreseal \
  && pytest python/tests                                                     # Python (in a venv)
```

Swift, Kotlin and Python: see `swift/README.md`, `kotlin/README.md` and `python/README.md`.

Integration tests against a testnet run only with `QORE_LIVE_TEST=1` and `QORE_TEST_MNEMONIC` set to a funded testnet account that has a registered ML-DSA-87 key. They register a KEM key, encrypt to the address, decrypt, and remove the key. They refuse mainnet (`qorechain-vladi`) until it has applied v3.2.5.

## Changing a wire format

The TypeScript package is the reference. If a change affects bytes on the wire, update `spec/qoreseal-v1.md` (or add a new versioned spec), regenerate the vectors into a **new** versioned file (`pnpm build && pnpm vectors`), and make every implementation pass it in the same pull request.

Changes to the construction itself (modes, combiner, key derivation, envelope layout) need a written rationale in the pull request and a review by a maintainer with cryptography background.

## Pull requests

- Keep changes focused; add tests for behaviour changes.
- Add a changeset (`pnpm changeset`) when a published package changes.
- Match the existing code style; formatting and linting run in CI.

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Do not open public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).
