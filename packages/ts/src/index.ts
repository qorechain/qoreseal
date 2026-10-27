// SPDX-License-Identifier: Apache-2.0
//
// @qorechain/qoreseal: ML-KEM-1024 (FIPS 203) encryption of data to QoreChain
// accounts. Offline; reading recipients from the chain lives in
// `@qorechain/qoreseal/network`. Format: spec/qoreseal-v1.md.

export { QoreSealError, isQoreSealError, type QoreSealErrorCode } from "./errors.js";
export { toHex, fromHex, toBase64Url, fromBase64Url } from "./bytes.js";
export {
  ALGORITHM_ML_KEM_1024,
  ENTRY_LENGTH,
  ENVELOPE_TEXT_PREFIX,
  ENVELOPE_VERSION,
  HYBRID_LABEL,
  KDF_INFO_PREFIX,
  MAX_RECIPIENTS,
  ML_KEM_1024_CIPHERTEXT_LENGTH,
  ML_KEM_1024_PUBLIC_KEY_LENGTH,
  ML_KEM_1024_SECRET_KEY_LENGTH,
  SEED_LENGTH,
  X25519_KEY_LENGTH,
  type SealMode,
} from "./constants.js";
export {
  deriveSealKeys,
  generateSealKeys,
  recipientOf,
  sealKeysFromSeed,
  sealSeedFromMnemonic,
  validateMlkemPublicKey,
  validateX25519PublicKey,
  type SealKeyPair,
  type SealRecipient,
} from "./keys.js";
export {
  deriveKey,
  hybridSharedSecret,
  kdfInfo,
  mlkemDecapsulate,
  mlkemEncapsulate,
  recipientHint,
  x25519Agree,
  x25519PublicKey,
} from "./kem.js";
export {
  envelopeFromText,
  envelopeSize,
  envelopeToText,
  open,
  parseEnvelope,
  seal,
  type EnvelopeEntry,
  type OpenArgs,
  type ParsedEnvelope,
  type SealArgs,
} from "./envelope.js";
export {
  RECIPIENT_CARD_TITLE,
  RECIPIENT_CARD_VERSION,
  assembleRecipientCard,
  recipientCardFields,
  recipientCardSignBytes,
  recipientCardText,
  signRecipientCard,
  verifyRecipientCard,
  type RecipientCard,
  type RecipientCardFields,
} from "./card.js";
export {
  KEM_REGISTRY_ERRORS,
  MSG_REGISTER_KEM_KEY_TYPE_URL,
  MSG_REMOVE_KEM_KEY_TYPE_URL,
  buildRegisterKemKeyMessage,
  buildRemoveKemKeyMessage,
  describeKemRegistryError,
  type EncodedMessage,
} from "./registry.js";
export {
  EpochKeyManager,
  decodeEpochKey,
  encodeEpochKey,
  openEpochKey,
  sealEpochKey,
  type EpochKey,
  type EpochKeyManagerOptions,
  type EpochRotation,
} from "./group.js";
export {
  PrivateBatchCodec,
  batchPlaintextCommitment,
  batchSize,
  openBatch,
  parseBatchHeader,
  sealBatch,
  type BatchHeader,
  type EpochKeySource,
  type OpenedBatch,
  type SealedBatch,
} from "./batch.js";
