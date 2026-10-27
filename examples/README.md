# Examples

| Example | Network | What it shows |
|---|---|---|
| [seal-and-open](seal-and-open) | none | seal to two recipients and an auditor, open, and what fails with the wrong key, chain, purpose, AAD or a tampered envelope |
| [register-and-encrypt](register-and-encrypt) | `qorechain-diana` | publish the account's ML-KEM-1024 key with a hybrid-signed `MsgRegisterKEMKey`, sign a recipient card, encrypt to the address from the chain's keys, decrypt |
| [private-rollup](private-rollup) | none | three members, epoch rotation on a join and a removal, encrypted batches, and the fields an RDK settlement batch carries |

Run from the repository root after `pnpm install && pnpm build`:

```bash
pnpm -C examples/seal-and-open start
QORE_MNEMONIC="<your testnet mnemonic>" pnpm -C examples/register-and-encrypt start
pnpm -C examples/private-rollup start
```

`register-and-encrypt` needs an account with testnet QOR and a registered
ML-DSA-87 key. It refuses `qorechain-vladi` (mainnet) until that network has
applied v3.2.5. Never put a mainnet mnemonic in a script or shell history.
