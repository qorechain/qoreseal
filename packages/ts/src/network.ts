// SPDX-License-Identifier: Apache-2.0
//
// `@qorechain/qoreseal/network`: reading recipients from a QoreChain REST
// endpoint. Everything else in QoreSeal works offline.

import { parseAddress } from "@qorechain/qoresign";
import { fetchPqKeyStatus, type FetchLike } from "@qorechain/qoresign/network";
import { fromBase64Url } from "./bytes.js";
import { ALGORITHM_ML_KEM_1024, type SealMode } from "./constants.js";
import { seal, type SealArgs } from "./envelope.js";
import { QoreSealError } from "./errors.js";
import { validateMlkemPublicKey, type SealRecipient } from "./keys.js";
import { verifyRecipientCard, type RecipientCard } from "./card.js";

export type { FetchLike };

export interface RestOptions {
  /** REST endpoint, for example `https://api-testnet.qore.host`. */
  rest: string;
  fetch?: FetchLike;
}

/** The KEM key an account has published, as `/qorechain/pqc/v1/kem/{address}` reports it. */
export interface KemKeyStatus {
  registered: boolean;
  address?: string;
  algorithmId?: number;
  algorithmName?: string;
  publicKey?: Uint8Array;
  registeredHeight?: bigint;
}

function decodeBase64(s: string): Uint8Array {
  return fromBase64Url(s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
}

/** Read an account's published KEM key. Accepts a `qor1` or `0x` address. */
export async function fetchKemKey(opts: RestOptions & { address: string }): Promise<KemKeyStatus> {
  if (!opts.rest) throw new QoreSealError("INVALID_ARGUMENT", "a REST endpoint is required");
  const f: FetchLike = opts.fetch ?? ((url, init) => globalThis.fetch(url, init));
  const path = `/qorechain/pqc/v1/kem/${encodeURIComponent(opts.address)}`;
  let res;
  try {
    res = await f(`${opts.rest.replace(/\/+$/, "")}${path}`);
  } catch (err) {
    throw new QoreSealError("NETWORK_UNAVAILABLE", `request to ${path} failed`, { cause: String(err) });
  }
  let body: Record<string, unknown> = {};
  try {
    body = (await res.json()) as Record<string, unknown>;
  } catch {
    if (res.ok) throw new QoreSealError("NETWORK_UNAVAILABLE", `${path} returned a non-JSON body`);
  }
  if (res.status === 501 || (res.status === 404 && body.found === undefined)) {
    throw new QoreSealError("KEM_REGISTRY_UNAVAILABLE", "this network does not serve the KEM key registry (it arrives with v3.2.5)");
  }
  if (body.found === false) return { registered: false };
  const key = body.key as Record<string, unknown> | undefined;
  if (!res.ok || body.found !== true || !key || typeof key.public_key !== "string") {
    throw new QoreSealError("NETWORK_UNAVAILABLE", `could not read the KEM key of ${opts.address} (HTTP ${res.status})`);
  }
  return {
    registered: true,
    address: typeof key.address === "string" ? key.address : undefined,
    algorithmId: Number(key.algorithm_id),
    algorithmName: typeof key.algorithm_name === "string" ? key.algorithm_name : undefined,
    publicKey: decodeBase64(key.public_key),
    registeredHeight: BigInt(typeof key.registered_height === "string" && key.registered_height !== "" ? key.registered_height : "0"),
  };
}

/** The account's ML-KEM-1024 key, checked. Throws `KEM_KEY_NOT_REGISTERED` when there is none. */
export async function fetchMlkemPublicKey(opts: RestOptions & { address: string }): Promise<Uint8Array> {
  const status = await fetchKemKey(opts);
  if (!status.registered || !status.publicKey) {
    throw new QoreSealError("KEM_KEY_NOT_REGISTERED", `${opts.address} has not published a KEM key`);
  }
  if (status.algorithmId !== ALGORITHM_ML_KEM_1024) {
    throw new QoreSealError("UNSUPPORTED_ALGORITHM", `${opts.address} published a key of algorithm ${status.algorithmId}`);
  }
  validateMlkemPublicKey(status.publicKey);
  return status.publicKey;
}

/**
 * Build the recipient for an address. Hybrid (default) needs the account's
 * recipient card, verified against both keys on chain; `mlkem` uses the
 * registered key alone.
 */
export async function resolveRecipient(
  opts: RestOptions & { chainId: string; address: string; card?: RecipientCard; mode?: SealMode },
): Promise<SealRecipient> {
  const address = parseAddress(opts.address).bech32;
  const mlkemPublicKey = await fetchMlkemPublicKey({ ...opts, address });
  const mode = opts.mode ?? "hybrid";
  if (mode === "mlkem") return { mlkemPublicKey };
  if (!opts.card) {
    throw new QoreSealError(
      "RECIPIENT_NEEDS_X25519",
      `hybrid mode needs the recipient card of ${address}; pass mode 'mlkem' to use the on-chain key alone`,
    );
  }
  const pq = await fetchPqKeyStatus({ rest: opts.rest, fetch: opts.fetch, address });
  if (!pq.registered || !pq.publicKey) throw new QoreSealError("CARD_INVALID", `${address} has no ML-DSA-87 key on chain`);
  return verifyRecipientCard({ card: opts.card, chainId: opts.chainId, address, pqPublicKey: pq.publicKey, mlkemPublicKey });
}

/** Seal to accounts by address: resolves each recipient on chain, then {@link seal}. */
export async function sealToAddresses(
  opts: RestOptions &
    Omit<SealArgs, "recipients"> & { recipients: { address: string; card?: RecipientCard }[] },
): Promise<Uint8Array> {
  const recipients: SealRecipient[] = [];
  for (const r of opts.recipients) {
    recipients.push(await resolveRecipient({ rest: opts.rest, fetch: opts.fetch, chainId: opts.chainId, mode: opts.mode, ...r }));
  }
  return seal({ ...opts, recipients });
}
