# QoreSeal for Go

`github.com/qorechain/qoreseal/go` encrypts data to QoreChain accounts with ML-KEM-1024 (FIPS 203) encryption of the payload, for dApps and private sidechains. It implements [QoreSeal v1](../spec/qoreseal-v1.md) and produces bytes identical to the TypeScript, Rust, Swift, Kotlin and Python packages (checked against `vectors/qoreseal-v1.json`).

Status: 0.x, construction under review before 1.0.

## Install

```bash
go get github.com/qorechain/qoreseal/go
```

Go 1.25 or later.

## Example

```go
import (
	"context"

	qoreseal "github.com/qorechain/qoreseal/go"
	"github.com/qorechain/qoreseal/go/network"
)

// Recipient side, once: derive the keys, register the ML-KEM-1024 key on chain
// (qoreseal.BuildRegisterKemKeyMessage, signed hybrid with QoreSign) and sign a
// recipient card for the hybrid mode (qoreseal.SignRecipientCard).
keys, _ := qoreseal.DeriveSealKeys(mnemonic, qoreseal.MnemonicOptions{})

// Sender side: resolve the address on chain and seal.
client := network.NewClient("https://api-testnet.qore.host")
envelope, err := client.SealToAddresses(context.Background(), network.SealToArgs{
	ChainID:    "qorechain-diana",
	Purpose:    "invoice",
	Recipients: []network.AddressRecipient{{Address: "qor1...", Card: &card}},
	Plaintext:  []byte("payload"),
})

// Recipient side: open.
plaintext, err := qoreseal.Open(qoreseal.OpenArgs{
	ChainID: "qorechain-diana", Purpose: "invoice", Envelope: envelope, Keys: keys,
})
```

Modes: `ModeHybrid` (default) combines ML-KEM-1024 with X25519 and needs the recipient's signed card; `ModeMlkem` uses the key registered on chain alone and must be chosen explicitly.

Private groups and sidechains: `EpochKeyManager` keeps one key per epoch and seals it to the current members on every membership change; `SealBatch` / `OpenBatch` (or `PrivateBatchCodec`) encrypt batch data under the epoch key and return a ciphertext commitment and a salted plaintext commitment ready to anchor.

The KEM key registry (`MsgRegisterKEMKey`, `MsgRemoveKEMKey`, `/qorechain/pqc/v1/kem/{address}`) is available on testnet; on mainnet from the v3.2.5 upgrade.

## Limits

- Only the content of the payload is protected. Addresses, amounts, transaction timing, sizes and the number of recipients stay public.
- No zero-knowledge proofs are involved.
- Envelopes are not signed; sign them (for example with QoreSign) when the sender must be authenticated.
- Losing the seed or mnemonic loses access to everything sealed to the key.

## Tests

```bash
go test ./...
```

`QORE_LIVE_TEST=1` with `QORE_TEST_MNEMONIC` (a funded testnet account with a registered ML-DSA-87 key) also runs the registry round trip against a testnet (`QORE_REST`, `QORE_CHAIN_ID`).
