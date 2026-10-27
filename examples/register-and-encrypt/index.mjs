// SPDX-License-Identifier: Apache-2.0
//
// Testnet: publish an account's ML-KEM-1024 key with a hybrid-signed
// MsgRegisterKEMKey, sign a recipient card, then encrypt to the address the
// way any sender would (reading the keys from the chain) and decrypt.
//
//   QORE_MNEMONIC="<testnet mnemonic>" pnpm -C examples/register-and-encrypt start
//
// The account must hold testnet QOR and a registered ML-DSA-87 key (see the
// QoreSign register-and-send example). Refuses mainnet until it has applied
// v3.2.5, the upgrade that brings the KEM key registry.

import { encodeSecp256k1Pubkey } from "@cosmjs/amino";
import { encodePubkey, makeAuthInfoBytes } from "@cosmjs/proto-signing";
import { SignMode } from "cosmjs-types/cosmos/tx/signing/v1beta1/signing";
import { TxBody } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { addressFromPublicKey, deriveCanonicalPqKey, deriveClassicalKey, signHybrid } from "@qorechain/qoresign";
import { fetchAppliedPlanHeight, fetchPqKeyStatus, simulateTx, submitWithSignBytesFallback } from "@qorechain/qoresign/network";
import {
  buildRegisterKemKeyMessage,
  deriveSealKeys,
  describeKemRegistryError,
  open,
  signRecipientCard,
  toHex,
} from "@qorechain/qoreseal";
import { fetchKemKey, sealToAddresses } from "@qorechain/qoreseal/network";

const REST = process.env.QORE_REST ?? "https://api-testnet.qore.host";
const CHAIN_ID = process.env.QORE_CHAIN_ID ?? "qorechain-diana";
const mnemonic = process.env.QORE_MNEMONIC;
if (!mnemonic) throw new Error("set QORE_MNEMONIC to a funded testnet mnemonic");
if (CHAIN_ID === "qorechain-vladi" && (await fetchAppliedPlanHeight({ rest: REST, name: "v3.2.5" })) === 0n) {
  throw new Error("mainnet has not applied v3.2.5 yet: the KEM key registry is not available there");
}

const classical = deriveClassicalKey({ mnemonic });
const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
const pq = deriveCanonicalPqKey({ mnemonic, address });
// QoreSeal keys from the same mnemonic (index 0): the mnemonic backs them up.
const sealKeys = deriveSealKeys({ mnemonic });
console.log(`account ${address}`);

const pqStatus = await fetchPqKeyStatus({ rest: REST, address });
if (!pqStatus.registered) throw new Error("register the account's ML-DSA-87 key first (QoreSign)");

async function sendHybrid(msg) {
  const info = await (await fetch(`${REST}/cosmos/auth/v1beta1/account_info/${address}`)).json();
  const accountNumber = BigInt(info.info.account_number);
  const sequence = BigInt(info.info.sequence ?? "0");
  const bodyBytes = TxBody.encode(TxBody.fromPartial({ messages: [msg] })).finish();
  const sign = (gas) =>
    signHybrid({
      chainId: CHAIN_ID,
      accountNumber,
      bodyBytes,
      authInfoBytes: makeAuthInfoBytes(
        [{ pubkey: encodePubkey(encodeSecp256k1Pubkey(classical.publicKey)), sequence }],
        [{ denom: "uqor", amount: ((gas + 9n) / 10n).toString() }], // 0.1 uqor per gas
        Number(gas),
        undefined,
        undefined,
        SignMode.SIGN_MODE_DIRECT,
      ),
      classicalKey: classical,
      pqKey: pq,
    }).txBytes;
  const sim = await simulateTx({ rest: REST, txBytes: sign(600_000n) });
  const res = await submitWithSignBytesFallback({ rest: REST, chainId: CHAIN_ID, sign: () => sign(sim.suggestedGasLimit) });
  if (res.code !== 0) throw new Error(`refused: ${describeKemRegistryError(res.codespace, res.code) ?? res.log}`);
  for (let i = 0; i < 40; i++) {
    const r = await fetch(`${REST}/cosmos/tx/v1beta1/txs/${res.txhash}`);
    if (r.ok) return res.txhash;
    await new Promise((ok) => setTimeout(ok, 1500));
  }
  throw new Error(`transaction ${res.txhash} was not committed`);
}

// 1. Publish the ML-KEM-1024 key, unless it is already the registered one.
const current = await fetchKemKey({ rest: REST, address });
if (current.registered && toHex(current.publicKey) === toHex(sealKeys.mlkemPublicKey)) {
  console.log(`KEM key already registered at height ${current.registeredHeight}`);
} else {
  const txhash = await sendHybrid(buildRegisterKemKeyMessage({ sender: address, mlkemPublicKey: sealKeys.mlkemPublicKey }));
  console.log(`registered the KEM key: ${txhash}`);
}

// 2. The recipient card carries the X25519 key for the hybrid mode. Publish
//    it wherever senders can find it (profile, API, QR code).
const card = signRecipientCard({ chainId: CHAIN_ID, address, keys: sealKeys, classicalKey: classical, pqKey: pq });
console.log(`card issued at ${card.issuedAt}, ${JSON.stringify(card).length} bytes of JSON`);

// 3. A sender encrypts to the address: keys come from the chain, the card is
//    verified against them.
const envelope = await sealToAddresses({
  rest: REST,
  chainId: CHAIN_ID,
  purpose: "example-note",
  recipients: [{ address, card }],
  plaintext: new TextEncoder().encode("hello from QoreSeal"),
});
console.log(`sealed ${envelope.length} bytes to ${address}`);

// 4. The recipient decrypts with its keys.
const plaintext = open({ chainId: CHAIN_ID, purpose: "example-note", envelope, keys: sealKeys });
console.log(`opened: ${new TextDecoder().decode(plaintext)}`);
