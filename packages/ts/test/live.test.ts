// SPDX-License-Identifier: Apache-2.0
//
// End-to-end checks against a QoreChain testnet. Skipped unless
// QORE_LIVE_TEST=1 and QORE_TEST_MNEMONIC (a funded testnet account with a
// registered ML-DSA-87 key) are set. Never point this at mainnet: it refuses
// qorechain-vladi until that network has applied v3.2.5.

import { encodeSecp256k1Pubkey } from "@cosmjs/amino";
import { encodePubkey, makeAuthInfoBytes } from "@cosmjs/proto-signing";
import { SignMode } from "cosmjs-types/cosmos/tx/signing/v1beta1/signing";
import { TxBody } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import {
  addressFromPublicKey,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  signHybrid,
  type ClassicalKey,
  type PqKeyPair,
} from "@qorechain/qoresign";
import { fetchAppliedPlanHeight, simulateTx, submitWithSignBytesFallback } from "@qorechain/qoresign/network";
import { beforeAll, describe, expect, it } from "vitest";
import * as qs from "../src/index.js";
import { fetchKemKey, resolveRecipient, sealToAddresses } from "../src/network.js";

const LIVE = process.env.QORE_LIVE_TEST === "1" && !!process.env.QORE_TEST_MNEMONIC;
const REST = process.env.QORE_REST ?? "https://api-testnet.qore.host";
const CHAIN_ID = process.env.QORE_CHAIN_ID ?? "qorechain-diana";
const GAS_PRICE_TENTHS = 1n; // 0.1 uqor per gas

interface Account {
  address: string;
  classical: ClassicalKey;
  pq: PqKeyPair;
}

function account(mnemonic: string): Account {
  const classical = deriveClassicalKey({ mnemonic });
  const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
  return { address, classical, pq: deriveCanonicalPqKey({ mnemonic, address }) };
}

async function accountInfo(address: string): Promise<{ accountNumber: bigint; sequence: bigint }> {
  const res = await fetch(`${REST}/cosmos/auth/v1beta1/account_info/${address}`);
  const body = (await res.json()) as { info?: { account_number?: string; sequence?: string } };
  if (!body.info) throw new Error(`account ${address} not found`);
  return { accountNumber: BigInt(body.info.account_number ?? "0"), sequence: BigInt(body.info.sequence ?? "0") };
}

async function waitForTx(txhash: string): Promise<{ code: number; rawLog: string }> {
  for (let i = 0; i < 40; i++) {
    const res = await fetch(`${REST}/cosmos/tx/v1beta1/txs/${txhash}`);
    if (res.ok) {
      const body = (await res.json()) as { tx_response: { code: number; raw_log: string } };
      return { code: body.tx_response.code, rawLog: body.tx_response.raw_log };
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error(`transaction ${txhash} was not committed`);
}

/** Sign hybrid with QoreSign, simulate for the gas limit, broadcast and wait. */
async function sendHybrid(acc: Account, msg: qs.EncodedMessage): Promise<string> {
  const bodyBytes = TxBody.encode(TxBody.fromPartial({ messages: [msg], memo: "qoreseal live test" })).finish();
  const { accountNumber, sequence } = await accountInfo(acc.address);
  const sign = (gas: bigint) =>
    signHybrid({
      chainId: CHAIN_ID,
      accountNumber,
      bodyBytes,
      authInfoBytes: makeAuthInfoBytes(
        [{ pubkey: encodePubkey(encodeSecp256k1Pubkey(acc.classical.publicKey)), sequence }],
        [{ denom: "uqor", amount: ((gas * GAS_PRICE_TENTHS + 9n) / 10n).toString() }],
        Number(gas),
        undefined,
        undefined,
        SignMode.SIGN_MODE_DIRECT,
      ),
      classicalKey: acc.classical,
      pqKey: acc.pq,
    }).txBytes;
  const sim = await simulateTx({ rest: REST, txBytes: sign(600_000n) });
  const res = await submitWithSignBytesFallback({ rest: REST, chainId: CHAIN_ID, sign: () => sign(sim.suggestedGasLimit) });
  expect(res.code, `${res.codespace} ${res.code}: ${qs.describeKemRegistryError(res.codespace, res.code) ?? res.log}`).toBe(0);
  const committed = await waitForTx(res.txhash);
  expect(committed.code, committed.rawLog).toBe(0);
  return res.txhash;
}

describe.skipIf(!LIVE)(`KEM registry on ${CHAIN_ID}`, () => {
  const acc = LIVE ? account(process.env.QORE_TEST_MNEMONIC!) : (undefined as unknown as Account);
  // A fresh key every run, so registering always changes the published key.
  const sealKeys = qs.generateSealKeys();

  beforeAll(async () => {
    if (CHAIN_ID === "qorechain-vladi") {
      const applied = await fetchAppliedPlanHeight({ rest: REST, name: "v3.2.5" });
      if (applied === 0n) throw new Error("qorechain-vladi has not applied v3.2.5: the KEM key registry is not available there yet");
    }
  });

  it("registers an ML-KEM-1024 key with a hybrid-signed MsgRegisterKEMKey and reads it back", async () => {
    const txhash = await sendHybrid(acc, qs.buildRegisterKemKeyMessage({ sender: acc.address, mlkemPublicKey: sealKeys.mlkemPublicKey }));
    const status = await fetchKemKey({ rest: REST, address: acc.address });
    expect(status.registered).toBe(true);
    expect(status.algorithmId).toBe(qs.ALGORITHM_ML_KEM_1024);
    expect(qs.toHex(status.publicKey!)).toBe(qs.toHex(sealKeys.mlkemPublicKey));
    console.log(`registered at height ${status.registeredHeight} (tx ${txhash})`);
  }, 180_000);

  it("encrypts to the address in both modes and decrypts", async () => {
    const card = qs.signRecipientCard({ chainId: CHAIN_ID, address: acc.address, keys: sealKeys, classicalKey: acc.classical, pqKey: acc.pq });
    const recipient = await resolveRecipient({ rest: REST, chainId: CHAIN_ID, address: acc.address, card });
    expect(qs.toHex(recipient.x25519PublicKey!)).toBe(qs.toHex(sealKeys.x25519PublicKey));
    const message = new TextEncoder().encode(`sealed on ${CHAIN_ID} at ${new Date().toISOString()}`);
    for (const mode of ["hybrid", "mlkem"] as const) {
      const env = await sealToAddresses({
        rest: REST,
        chainId: CHAIN_ID,
        purpose: "qoreseal-live-test",
        mode,
        recipients: [{ address: acc.address, card }],
        plaintext: message,
      });
      const out = qs.open({ chainId: CHAIN_ID, purpose: "qoreseal-live-test", envelope: env, keys: sealKeys });
      expect(new TextDecoder().decode(out)).toBe(new TextDecoder().decode(message));
    }
  }, 60_000);

  it("removes the key", async () => {
    await sendHybrid(acc, qs.buildRemoveKemKeyMessage({ sender: acc.address }));
    const status = await fetchKemKey({ rest: REST, address: acc.address });
    expect(status.registered).toBe(false);
  }, 180_000);
});
