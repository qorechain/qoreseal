// SPDX-License-Identifier: Apache-2.0

/** Stable error codes, identical in every QoreSeal implementation. */
export type QoreSealErrorCode =
  | "INVALID_ARGUMENT"
  | "INVALID_KEY"
  | "MALFORMED_ENVELOPE"
  | "MALFORMED_BATCH"
  | "UNSUPPORTED_VERSION"
  | "UNSUPPORTED_ALGORITHM"
  | "NOT_A_RECIPIENT"
  | "DECRYPTION_FAILED"
  | "RECIPIENT_NEEDS_X25519"
  | "CARD_INVALID"
  | "UNKNOWN_EPOCH"
  | "KEM_KEY_NOT_REGISTERED"
  | "KEM_REGISTRY_UNAVAILABLE"
  | "NETWORK_UNAVAILABLE";

/** Every failure QoreSeal reports. `code` is stable; `message` is for people. */
export class QoreSealError extends Error {
  readonly code: QoreSealErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: QoreSealErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "QoreSealError";
    this.code = code;
    this.details = details;
  }
}

export function isQoreSealError(err: unknown, code?: QoreSealErrorCode): err is QoreSealError {
  return err instanceof QoreSealError && (code === undefined || err.code === code);
}
