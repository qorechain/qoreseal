# Encrypt to an address

A QoreChain account can receive encrypted data once it has published an
ML-KEM-1024 key in the chain's KEM key registry (available on testnet; on
mainnet from the v3.2.5 upgrade). This guide covers the sender's side: getting
the recipient's keys, choosing a mode, and binding the envelope to its context.

## What the sender needs

| Mode | From the chain | From the recipient |
|---|---|---|
| `hybrid` (default) | the ML-KEM-1024 key (`/qorechain/pqc/v1/kem/{address}`) and the ML-DSA-87 key (`/qorechain/pqc/v1/account/{address}`) | the recipient card |
| `mlkem` | the ML-KEM-1024 key | nothing |

The recipient card is a small signed JSON document (about 6.7 KB, mostly the
ML-DSA-87 signature) with the account's X25519 key. It is checked against both
keys on chain, so it can come from any channel: a profile page, your API, a QR
code, a contract. A card stops verifying as soon as the account registers a
different ML-KEM key.

If a card is forged or stale, the worst case is that the envelope is as strong
as ML-KEM-1024 alone: the ML-KEM part always uses the key on chain.

## Chain id, purpose and AAD

- `chainId` (for example `qorechain-diana`) and `purpose` (for example
  `invoice`, `chat`, `bid:auction-17`) go into the key derivation
  (`"qorechain-kem-v1|" + chainId + "|" + purpose`). The recipient must pass
  the same values to open the envelope, and an envelope made for one purpose
  never opens under another. Purposes use letters, digits and `. _ : / -`.
- `aad` is data you want authenticated but not encrypted, such as an invoice
  number or a contract address. The recipient must pass the same bytes.

## TypeScript

```ts
import { open } from "@qorechain/qoreseal";
import { resolveRecipient, sealToAddresses } from "@qorechain/qoreseal/network";

const rest = "https://api-testnet.qore.host";
const envelope = await sealToAddresses({
  rest,
  chainId: "qorechain-diana",
  purpose: "invoice",
  recipients: [{ address: "qor1...", card }],   // card: the recipient's RecipientCard JSON
  plaintext: new TextEncoder().encode("120 QOR due on 2026-11-30"),
  aad: new TextEncoder().encode("invoice-42"),
});

// Without a card:
const recipient = await resolveRecipient({ rest, chainId: "qorechain-diana", address: "qor1...", mode: "mlkem" });

// Recipient side:
open({ chainId: "qorechain-diana", purpose: "invoice", envelope, keys, aad: new TextEncoder().encode("invoice-42") });
```

## Go

```go
import (
    qoreseal "github.com/qorechain/qoreseal/go"
    "github.com/qorechain/qoreseal/go/network"
)

client := network.NewClient("https://api-testnet.qore.host")
envelope, err := client.SealToAddresses(ctx, network.SealToArgs{
    ChainID:    "qorechain-diana",
    Purpose:    "invoice",
    Recipients: []network.AddressRecipient{{Address: "qor1...", Card: &card}},
    Plaintext:  []byte("120 QOR due on 2026-11-30"),
    AAD:        []byte("invoice-42"),
})

plaintext, err := qoreseal.Open(qoreseal.OpenArgs{
    ChainID: "qorechain-diana", Purpose: "invoice", Envelope: envelope, Keys: keys, AAD: []byte("invoice-42"),
})
```

## Rust, Swift, Kotlin, Python

These packages are offline. Read the keys yourself (`GET
/qorechain/pqc/v1/kem/{address}` and `/qorechain/pqc/v1/account/{address}`,
base64 `public_key`), verify the card, then seal:

```rust
let recipient = qoreseal::verify_recipient_card(&qoreseal::VerifyCardArgs {
    card: &card, chain_id: "qorechain-diana", address: Some(address),
    pq_public_key: &ml_dsa_key, mlkem_public_key: &ml_kem_key,
})?;
let recipients = [recipient];
let mut args = qoreseal::SealArgs::new("qorechain-diana", "invoice", &recipients, plaintext);
args.aad = b"invoice-42";
let envelope = qoreseal::seal(&args)?;
```

```python
r = qs.verify_recipient_card(card_json, "qorechain-diana", ml_dsa_key, ml_kem_key, address=address)
envelope = qs.seal_envelope("qorechain-diana", "invoice", [r], plaintext, aad=b"invoice-42")
```

Swift (`verifyRecipientCard`, `sealEnvelope`) and Kotlin (`verifyRecipientCard`,
`sealEnvelope`) follow the Python names in their own casing.

## Transport

`envelopeToText` gives `"qoreseal:" + base64url`, safe in JSON, URLs and
transaction memos (mind the memo size limit of your network). The binary form
is smaller; use it for contract storage and files. Sizes:
`56 + 1664 * recipients + plaintext` bytes in hybrid mode,
`56 + 1632 * recipients + plaintext` in mlkem mode.

## Publishing your own key

Recipients publish once per key: `buildRegisterKemKeyMessage({ sender,
mlkemPublicKey })`, signed hybrid with QoreSign, from an account that already
has an ML-DSA-87 key. Registering again replaces the key;
`buildRemoveKemKeyMessage` withdraws it. Refusals come back with codespace
`pqc` and codes 250 to 254; `describeKemRegistryError` explains them. See the
[quickstart](../quickstart.md).
