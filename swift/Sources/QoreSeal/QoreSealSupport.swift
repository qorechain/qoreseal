// SPDX-License-Identifier: Apache-2.0
//
// Small additions over the generated bindings in QoreSeal.swift.

import Foundation

extension QoreSealError {
    /// Stable code shared by every QoreSeal implementation, e.g. `NOT_A_RECIPIENT`.
    public var code: String {
        switch self {
        case let .Failure(code, _): return code
        }
    }

    /// Human-readable message.
    public var message: String {
        switch self {
        case let .Failure(_, detail): return detail
        }
    }
}

/// Constants of the QoreSeal format, identical across implementations.
public enum QoreSealConstants {
    /// Algorithm id of ML-KEM-1024 in the chain's KEM key registry and in envelopes.
    public static let algorithmMlKem1024: UInt32 = 2
    /// ML-KEM-1024 sizes (FIPS 203).
    public static let mlKem1024PublicKeyLength = 1568
    public static let mlKem1024SecretKeyLength = 3168
    public static let mlKem1024CiphertextLength = 1568
    /// Prefix of the text form of an envelope.
    public static let envelopeTextPrefix = "qoreseal:"
    /// Prefix of the HKDF info of every key-encryption key.
    public static let kdfInfoPrefix = "qorechain-kem-v1|"
    /// Type URLs of the KEM key registry messages.
    public static let msgRegisterKemKeyTypeUrl = "/qorechain.pqc.v1.MsgRegisterKEMKey"
    public static let msgRemoveKemKeyTypeUrl = "/qorechain.pqc.v1.MsgRemoveKEMKey"
}
