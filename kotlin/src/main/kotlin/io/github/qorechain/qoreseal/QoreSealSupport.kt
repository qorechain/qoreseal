// SPDX-License-Identifier: Apache-2.0
//
// Small additions over the generated bindings in qoreseal_ffi.kt.

package io.github.qorechain.qoreseal

/** Stable code shared by every QoreSeal implementation, e.g. `NOT_A_RECIPIENT`. */
val QoreSealException.code: String
    get() = when (this) {
        is QoreSealException.Failure -> code
    }

/** Human-readable message without the code. */
val QoreSealException.detail: String
    get() = when (this) {
        is QoreSealException.Failure -> detail
    }

/** Constants of the QoreSeal format, identical across implementations. */
object QoreSealConstants {
    /** Algorithm id of ML-KEM-1024 in the chain's KEM key registry and in envelopes. */
    const val ALGORITHM_ML_KEM_1024: UInt = 2u

    /** ML-KEM-1024 sizes (FIPS 203). */
    const val ML_KEM_1024_PUBLIC_KEY_LENGTH = 1568
    const val ML_KEM_1024_SECRET_KEY_LENGTH = 3168
    const val ML_KEM_1024_CIPHERTEXT_LENGTH = 1568

    /** Prefix of the text form of an envelope. */
    const val ENVELOPE_TEXT_PREFIX = "qoreseal:"

    /** Prefix of the HKDF info of every key-encryption key. */
    const val KDF_INFO_PREFIX = "qorechain-kem-v1|"

    /** Type URLs of the KEM key registry messages. */
    const val MSG_REGISTER_KEM_KEY_TYPE_URL = "/qorechain.pqc.v1.MsgRegisterKEMKey"
    const val MSG_REMOVE_KEM_KEY_TYPE_URL = "/qorechain.pqc.v1.MsgRemoveKEMKey"
}
