// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const vectors: any = JSON.parse(readFileSync(join(here, "../../../vectors/qoreseal-v1.json"), "utf8"));

export const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

export function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    return (err as { code?: string }).code ?? "no code";
  }
  return "none";
}

export async function asyncCodeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (err) {
    return (err as { code?: string }).code ?? "no code";
  }
  return "none";
}
