# @qorechain/qoreseal

ML-KEM-1024 (FIPS 203) encryption of data to QoreChain accounts: a hybrid
ML-KEM-1024 + X25519 mode (default) and an ML-KEM-1024-only mode,
multi-recipient envelopes, recipient cards signed with QoreSign, the KEM key
registry messages, and epoch keys and a batch codec for private groups and
sidechains.

```sh
npm install @qorechain/qoreseal
```

```ts
import { generateSealKeys, open, recipientOf, seal } from "@qorechain/qoreseal";
import { sealToAddresses } from "@qorechain/qoreseal/network";

const keys = generateSealKeys();
const envelope = seal({
  chainId: "qorechain-diana",
  purpose: "chat",
  recipients: [recipientOf(keys)],
  plaintext: new TextEncoder().encode("hello"),
});
open({ chainId: "qorechain-diana", purpose: "chat", envelope, keys });

// To an address: the ML-KEM key comes from the chain, the X25519 key from the
// account's recipient card (verified against its keys on chain).
await sealToAddresses({
  rest: "https://api-testnet.qore.host",
  chainId: "qorechain-diana",
  purpose: "chat",
  recipients: [{ address: "qor1...", card }],
  plaintext,
});
```

Entry points:

- `@qorechain/qoreseal`: offline (keys, `seal`/`open`, cards, registry messages, epochs, batches).
- `@qorechain/qoreseal/network`: `fetchKemKey`, `resolveRecipient`, `sealToAddresses`.
- `@qorechain/qoreseal/testing`: deterministic entry points for the shared test vectors only.

The KEM key registry is available on testnet; on mainnet from the v3.2.5
upgrade.

Only the payload is confidential: addresses, amounts, timing and sizes stay
public, no zero-knowledge proof is involved, envelopes are not signed, and
losing the seed or mnemonic loses access to the data. The construction is
pending external review before 1.0.

Documentation, specification and the other languages: <https://github.com/qorechain/qoreseal>.

Apache-2.0.
