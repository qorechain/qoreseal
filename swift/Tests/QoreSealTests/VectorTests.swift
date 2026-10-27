// SPDX-License-Identifier: Apache-2.0
//
// Checks the Swift package against vectors/qoreseal-v1.json.

import Foundation
import XCTest

@testable import QoreSeal

private func loadVectors() throws -> [String: Any] {
    let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // QoreSealTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // swift
        .deletingLastPathComponent() // repository root
    let data = try Data(contentsOf: root.appendingPathComponent("vectors/qoreseal-v1.json"))
    return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
}

private func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func unhex(_ s: String) -> Data {
    var out = Data(capacity: s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return out
}

private func errorCode(_ body: () throws -> Void) -> String? {
    do {
        try body()
        return nil
    } catch let e as QoreSealError {
        return e.code
    } catch {
        return "unexpected \(error)"
    }
}

private func json(_ s: String) throws -> NSDictionary {
    try XCTUnwrap(JSONSerialization.jsonObject(with: Data(s.utf8)) as? NSDictionary)
}

private func jsonString(_ o: Any) throws -> String {
    String(decoding: try JSONSerialization.data(withJSONObject: o), as: UTF8.self)
}

final class VectorTests: XCTestCase {
    var v: [String: Any] = [:]
    var chainId = ""
    var purpose = ""
    var keys: [SealKeyPair] = []

    override func setUpWithError() throws {
        v = try loadVectors()
        XCTAssertEqual(v["format"] as? String, "qoreseal-vectors-v1")
        chainId = v["chainId"] as! String
        purpose = v["purpose"] as! String
        keys = try (v["keys"] as! [[String: Any]]).map { try sealKeysFromSeed(seed: unhex($0["seed"] as! String)) }
    }

    private func mode(_ s: Any?) -> SealMode { (s as? String) == "hybrid" ? .hybrid : .mlkem }

    func testKeysAndSeeds() throws {
        for (i, k) in (v["keys"] as! [[String: Any]]).enumerated() {
            XCTAssertEqual(hex(keys[i].mlkemPublicKey), k["mlkemPublicKey"] as? String)
            XCTAssertEqual(hex(keys[i].x25519PublicKey), k["x25519PublicKey"] as? String)
            XCTAssertEqual(hex(keys[i].x25519SecretKey), k["x25519SecretKey"] as? String)
        }
        for m in v["mnemonicSeeds"] as! [[String: Any]] {
            let seed = try sealSeedFromMnemonic(
                mnemonic: m["mnemonic"] as! String, passphrase: m["passphrase"] as! String,
                index: UInt32(m["index"] as! Int))
            XCTAssertEqual(hex(seed), m["seed"] as? String)
        }
    }

    func testPrimitives() throws {
        let e = v["encapsulation"] as! [String: Any]
        let k = keys[e["recipient"] as! Int]
        let enc = try testingMlkemEncapsulateWithRandomness(publicKey: k.mlkemPublicKey, m: unhex(e["m"] as! String))
        XCTAssertEqual(hex(enc.ciphertext), e["ciphertext"] as? String)
        XCTAssertEqual(hex(enc.sharedSecret), e["sharedSecret"] as? String)
        XCTAssertEqual(hex(try mlkemDecapsulate(secretKey: k.mlkemSecretKey, ciphertext: enc.ciphertext)), e["sharedSecret"] as? String)

        let x = v["x25519"] as! [String: Any]
        let esk = unhex(x["ephemeralSecretKey"] as! String)
        XCTAssertEqual(hex(try x25519PublicKey(secretKey: esk)), x["ephemeralPublicKey"] as? String)
        XCTAssertEqual(hex(try x25519Agree(secretKey: esk, publicKey: keys[0].x25519PublicKey)), x["sharedSecret"] as? String)

        let h = v["hybrid"] as! [String: Any]
        let shared = try hybridSharedSecret(
            mlkemSharedSecret: unhex(h["mlkemSharedSecret"] as! String),
            x25519SharedSecret: unhex(h["x25519SharedSecret"] as! String),
            x25519Ciphertext: unhex(h["x25519Ciphertext"] as! String),
            x25519PublicKey: unhex(h["x25519PublicKey"] as! String))
        XCTAssertEqual(hex(shared), h["shared"] as? String)

        for d in v["kdf"] as! [[String: Any]] {
            XCTAssertEqual(try kdfInfo(chainId: d["chainId"] as! String, purpose: d["purpose"] as! String), d["info"] as? String)
            let key = try deriveKey(
                shared: unhex(d["shared"] as! String), chainId: d["chainId"] as! String,
                purpose: d["purpose"] as! String, salt: unhex(d["salt"] as! String))
            XCTAssertEqual(hex(key), d["key"] as? String)
        }
        let hint = v["hint"] as! [String: Any]
        XCTAssertEqual(hex(recipientHint(salt: unhex(hint["salt"] as! String), mlkemPublicKey: keys[0].mlkemPublicKey)), hint["hint"] as? String)
    }

    func testEnvelopes() throws {
        for e in v["envelopes"] as! [[String: Any]] {
            let idx = e["recipients"] as! [Int]
            let aad = unhex(e["aad"] as! String)
            let env = try testingSealWithEntropy(
                chainId: chainId, purpose: purpose, recipients: idx.map { recipientOf(keys: keys[$0]) },
                plaintext: unhex(e["plaintext"] as! String), entropy: unhex(e["entropy"] as! String),
                aad: aad, mode: mode(e["mode"]), anonymous: e["anonymous"] as! Bool)
            XCTAssertEqual(hex(env), e["envelope"] as? String, e["name"] as! String)
            XCTAssertEqual(envelopeToText(envelope: env), e["text"] as? String)
            XCTAssertEqual(try envelopeFromText(text: e["text"] as! String), env)
            for i in idx {
                let out = try openEnvelope(chainId: chainId, purpose: purpose, envelope: env, keys: keys[i], aad: aad)
                XCTAssertEqual(hex(out), e["plaintext"] as? String)
            }
            XCTAssertEqual(try parseEnvelope(envelope: env).entries.count, idx.count)
        }
        let byName = Dictionary(uniqueKeysWithValues: (v["envelopes"] as! [[String: Any]]).map { ($0["name"] as! String, $0) })
        for n in v["negative"] as! [[String: Any]] {
            let base = byName[n["base"] as! String]!
            var env = [UInt8](unhex(base["envelope"] as! String))
            if let f = n["flip"] as? Int { env[f] ^= 1 }
            if let s = n["set"] as? [Int] { env[s[0]] = UInt8(s[1]) }
            if let t = n["truncate"] as? Int { env = Array(env[0..<t]) }
            let aad = unhex((n["aad"] as? String) ?? (base["aad"] as! String))
            let code = errorCode {
                _ = try openEnvelope(
                    chainId: (n["chainId"] as? String) ?? chainId, purpose: (n["purpose"] as? String) ?? purpose,
                    envelope: Data(env), keys: keys[n["key"] as! Int], aad: aad)
            }
            XCTAssertEqual(code, n["error"] as? String, n["name"] as! String)
        }
        for t in v["textNegative"] as! [[String: Any]] {
            XCTAssertEqual(errorCode { _ = try envelopeFromText(text: t["text"] as! String) }, t["error"] as? String)
        }
        for s in v["sizes"] as! [[String: Any]] {
            XCTAssertEqual(
                envelopeSize(mode: mode(s["mode"]), recipients: UInt32(s["recipients"] as! Int), plaintextLength: UInt64(s["plaintextLength"] as! Int)),
                UInt64(s["size"] as! Int))
        }
    }

    func testRecipientCard() throws {
        let c = v["card"] as! [String: Any]
        let card = c["card"] as! [String: Any]
        let acct = try accountKeysFromMnemonic(mnemonic: c["mnemonic"] as! String)
        XCTAssertEqual(acct.address, c["address"] as? String)
        XCTAssertEqual(hex(acct.pqPublicKey), c["pqPublicKey"] as? String)
        let sk = try deriveSealKeys(mnemonic: c["mnemonic"] as! String)
        let fields = try recipientCardFields(
            chainId: chainId, address: acct.address, mlkemPublicKey: sk.mlkemPublicKey,
            x25519PublicKey: sk.x25519PublicKey, issuedAt: card["issuedAt"] as? String)
        XCTAssertEqual(try recipientCardText(fields: fields), c["text"] as? String)
        let signed = try signRecipientCard(fields: fields, classicalPrivateKey: acct.classicalPrivateKey, pqSecretKey: acct.pqSecretKey)
        XCTAssertEqual(try json(signed), card as NSDictionary)
        let cardJson = try jsonString(card)
        let r = try verifyRecipientCard(
            cardJson: cardJson, chainId: chainId, pqPublicKey: unhex(c["pqPublicKey"] as! String),
            mlkemPublicKey: sk.mlkemPublicKey, address: acct.address)
        XCTAssertEqual(r.x25519PublicKey, sk.x25519PublicKey)
        for n in c["negative"] as! [[String: Any]] {
            var cc = card
            if let x = n["x25519PublicKey"] as? String { cc["x25519PublicKey"] = x }
            let mlkem = (n["mlkemKey"] as? Int).map { keys[$0].mlkemPublicKey } ?? sk.mlkemPublicKey
            let code = errorCode {
                _ = try verifyRecipientCard(
                    cardJson: try jsonString(cc), chainId: (n["chainId"] as? String) ?? chainId,
                    pqPublicKey: unhex(c["pqPublicKey"] as! String), mlkemPublicKey: mlkem,
                    address: n["address"] as? String)
            }
            XCTAssertEqual(code, n["error"] as? String, n["name"] as! String)
        }
    }

    func testRegistryEpochAndBatch() throws {
        let r = v["registry"] as! [String: Any]
        let sk = try deriveSealKeys(mnemonic: (v["card"] as! [String: Any])["mnemonic"] as! String)
        let reg = try buildRegisterKemKeyMessage(sender: r["sender"] as! String, mlkemPublicKey: sk.mlkemPublicKey)
        XCTAssertEqual(hex(reg.value), (r["register"] as! [String: Any])["value"] as? String)
        XCTAssertEqual(reg.typeUrl, QoreSealConstants.msgRegisterKemKeyTypeUrl)
        let rem = try buildRemoveKemKeyMessage(sender: r["sender"] as! String)
        XCTAssertEqual(hex(rem.value), (r["remove"] as! [String: Any])["value"] as? String)

        let e = v["epoch"] as! [String: Any]
        let ek = EpochKey(epoch: 1, key: unhex(e["key"] as! String))
        let payload = try encodeEpochKey(epochKey: ek)
        XCTAssertEqual(hex(payload), e["payload"] as? String)
        let idx = e["recipients"] as! [Int]
        let env = try testingSealWithEntropy(
            chainId: chainId, purpose: e["purpose"] as! String, recipients: idx.map { recipientOf(keys: keys[$0]) },
            plaintext: payload, entropy: unhex(e["entropy"] as! String))
        XCTAssertEqual(hex(env), e["envelope"] as? String)
        for i in idx {
            XCTAssertEqual(try openEpochKey(chainId: chainId, purpose: e["purpose"] as! String, envelope: env, keys: keys[i]), ek)
        }

        let b = v["batch"] as! [String: Any]
        let sealed = try testingSealBatchWithEntropy(
            epochKey: ek, context: b["context"] as! String, batchIndex: 7,
            data: unhex(b["data"] as! String), entropy: unhex(b["entropy"] as! String))
        XCTAssertEqual(hex(sealed.blob), b["blob"] as? String)
        XCTAssertEqual(hex(sealed.ciphertextCommitment), b["ciphertextCommitment"] as? String)
        XCTAssertEqual(hex(sealed.plaintextCommitment), b["plaintextCommitment"] as? String)
        XCTAssertEqual(try openBatch(blob: sealed.blob, keys: [ek]).data, unhex(b["data"] as! String))
    }

    func testGroupsAndRoundTrip() throws {
        let a = generateSealKeys(), b = generateSealKeys()
        let env = try sealEnvelope(chainId: chainId, purpose: "chat", recipients: [recipientOf(keys: a)], plaintext: Data("hi".utf8))
        XCTAssertEqual(try openEnvelope(chainId: chainId, purpose: "chat", envelope: env, keys: a), Data("hi".utf8))
        XCTAssertEqual(errorCode { _ = try openEnvelope(chainId: chainId, purpose: "chat", envelope: env, keys: b) }, "NOT_A_RECIPIENT")
        XCTAssertEqual(
            errorCode { _ = try sealEnvelope(chainId: chainId, purpose: "chat", recipients: [SealRecipient(mlkemPublicKey: a.mlkemPublicKey)], plaintext: Data()) },
            "RECIPIENT_NEEDS_X25519")

        let mgr = try EpochKeyManager(chainId: chainId, purpose: "epoch-key:demo", members: [GroupMember(id: "a", recipient: recipientOf(keys: a))])
        let rot = try mgr.addMember(id: "b", recipient: recipientOf(keys: b))
        XCTAssertEqual(rot.epoch, 2)
        let key = try openEpochKey(chainId: chainId, purpose: "epoch-key:demo", envelope: rot.envelope!, keys: b)
        let batch = try mgr.sealBatch(context: "demo", batchIndex: 1, data: Data("x".utf8))
        XCTAssertEqual(try openBatch(blob: batch.blob, keys: [key]).data, Data("x".utf8))
        let gone = try mgr.removeMember(id: "b")
        XCTAssertEqual(errorCode { _ = try openEpochKey(chainId: chainId, purpose: "epoch-key:demo", envelope: gone.envelope!, keys: b) }, "NOT_A_RECIPIENT")
    }
}
