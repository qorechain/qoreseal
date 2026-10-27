# Quickstart

In about ten minutes: publish an ML-KEM-1024 key for a testnet account, let
someone encrypt to that address, and decrypt. TypeScript; the other languages
follow the same steps (see [encrypt to an address](guides/encrypt-to-an-address.md)).

The KEM key registry is available on testnet; on mainnet from the v3.2.5
upgrade. Use a testnet account you control. Never put a mainnet mnemonic in a
script or shell history.

## 1. Prerequisites

- Node.js 20 or later.
- A `qorechain-diana` account with a little testnet QOR and a registered
  ML-DSA-87 key. QoreSign's `register-and-send` example registers one.

```sh
npm install @qorechain/qoreseal @qorechain/qoresign @cosmjs/amino @cosmjs/proto-signing cosmjs-types
```

## 2. Derive the keys

QoreSeal keys (ML-KEM-1024 and X25519) derive from the account's mnemonic, so
the mnemonic is also their backup.

```ts
import { addressFromPublicKey, deriveCanonicalPqKey, deriveClassicalKey } from "@qorechain/qoresign";
import { deriveSealKeys } from "@qorechain/qoreseal";

const mnemonic = process.env.QORE_MNEMONIC!;
const classical = deriveClassicalKey({ mnemonic });
const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
const pq = deriveCanonicalPqKey({ mnemonic, address });
const sealKeys = deriveSealKeys({ mnemonic }); // index 0
```

## 3. Publish the ML-KEM-1024 key

`MsgRegisterKEMKey` is authenticated by the transaction's hybrid signature, so
sign it with QoreSign `signHybrid`. Registering again replaces the key.

```ts
import { signHybrid } from "@qorechain/qoresign";
import { simulateTx, submitWithSignBytesFallback } from "@qorechain/qoresign/network";
import { buildRegisterKemKeyMessage, describeKemRegistryError } from "@qorechain/qoreseal";
import { TxBody } from "cosmjs-types/cosmos/tx/v1beta1/tx";

const msg = buildRegisterKemKeyMessage({ sender: address, mlkemPublicKey: sealKeys.mlkemPublicKey });
const bodyBytes = TxBody.encode(TxBody.fromPartial({ messages: [msg] })).finish();
// authInfoBytes(gas) and accountNumber as in any Cosmos SDK transaction; see
// examples/register-and-encrypt/index.mjs for the complete code.
const sign = (gas: bigint) =>
  signHybrid({ chainId: "qorechain-diana", accountNumber, bodyBytes, authInfoBytes: authInfoBytes(gas), classicalKey: classical, pqKey: pq }).txBytes;
const sim = await simulateTx({ rest, txBytes: sign(600_000n) });
const res = await submitWithSignBytesFallback({ rest, chainId: "qorechain-diana", sign: () => sign(sim.suggestedGasLimit) });
if (res.code !== 0) throw new Error(describeKemRegistryError(res.codespace, res.code) ?? res.log);
```

Check it: `GET https://api-testnet.qore.host/qorechain/pqc/v1/kem/<address>`.

## 4. Sign a recipient card

The chain stores only the ML-KEM-1024 key. The card carries the X25519 key for
the default hybrid mode, signed by the account and bound to the key on chain.
Publish it wherever senders can fetch it (your profile, an API, a QR code).

```ts
import { signRecipientCard } from "@qorechain/qoreseal";

const card = signRecipientCard({ chainId: "qorechain-diana", address, keys: sealKeys, classicalKey: classical, pqKey: pq });
```

## 5. Encrypt to the address (sender side)

The sender needs only the address and the card. `sealToAddresses` reads both
keys from the chain and verifies the card against them.

```ts
import { sealToAddresses } from "@qorechain/qoreseal/network";
import { envelopeToText } from "@qorechain/qoreseal";

const envelope = await sealToAddresses({
  rest: "https://api-testnet.qore.host",
  chainId: "qorechain-diana",
  purpose: "note",
  recipients: [{ address, card }],
  plaintext: new TextEncoder().encode("hello from QoreSeal"),
});
const text = envelopeToText(envelope); // "qoreseal:...", safe for JSON, URLs and memos
```

Without a card, pass `mode: "mlkem"` to use the key on chain alone.

## 6. Decrypt (recipient side)

```ts
import { open } from "@qorechain/qoreseal";

const plaintext = open({ chainId: "qorechain-diana", purpose: "note", envelope, keys: sealKeys });
```

The whole flow runs as `QORE_MNEMONIC="<testnet mnemonic>" pnpm -C examples/register-and-encrypt start`.

## Next

- Read [what QoreSeal does not do](../README.md#what-it-does-not-do).
- Add an auditor: [multi-recipient and auditor keys](guides/multi-recipient-and-auditors.md).
- Back up and rotate keys: [key backup](guides/key-backup.md).
