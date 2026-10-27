// SPDX-License-Identifier: Apache-2.0
//
// Checks the Kotlin package against vectors/qoreseal-v1.json.

package io.github.qorechain.qoreseal

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

private val vectors: JsonObject = Json.parseToJsonElement(
    File(System.getProperty("qoreseal.vectors") ?: "../vectors/qoreseal-v1.json").readText(),
).jsonObject

private fun JsonElement.str(key: String): String = jsonObject.getValue(key).jsonPrimitive.content

private fun JsonElement.opt(key: String): String? = (jsonObject[key] as? JsonPrimitive)?.content

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

private fun String.unhex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun mode(s: String): SealMode = if (s == "hybrid") SealMode.HYBRID else SealMode.MLKEM

private fun errorCode(block: () -> Unit): String? =
    try {
        block()
        null
    } catch (e: QoreSealException) {
        e.code
    }

class VectorTest {
    private val chainId = vectors.str("chainId")
    private val purpose = vectors.str("purpose")
    private val keys = vectors.getValue("keys").jsonArray.map { sealKeysFromSeed(it.str("seed").unhex()) }

    @Test
    fun keysAndSeeds() {
        assertEquals("qoreseal-vectors-v1", vectors.str("format"))
        vectors.getValue("keys").jsonArray.forEachIndexed { i, k ->
            assertEquals(k.str("mlkemPublicKey"), keys[i].mlkemPublicKey.hex())
            assertEquals(k.str("x25519PublicKey"), keys[i].x25519PublicKey.hex())
            assertEquals(k.str("x25519SecretKey"), keys[i].x25519SecretKey.hex())
        }
        for (m in vectors.getValue("mnemonicSeeds").jsonArray) {
            val seed = sealSeedFromMnemonic(m.str("mnemonic"), m.str("passphrase"), m.str("index").toUInt())
            assertEquals(m.str("seed"), seed.hex())
        }
    }

    @Test
    fun primitives() {
        val e = vectors.getValue("encapsulation")
        val k = keys[e.str("recipient").toInt()]
        val enc = testingMlkemEncapsulateWithRandomness(k.mlkemPublicKey, e.str("m").unhex())
        assertEquals(e.str("ciphertext"), enc.ciphertext.hex())
        assertEquals(e.str("sharedSecret"), enc.sharedSecret.hex())
        assertEquals(e.str("sharedSecret"), mlkemDecapsulate(k.mlkemSecretKey, enc.ciphertext).hex())

        val x = vectors.getValue("x25519")
        val esk = x.str("ephemeralSecretKey").unhex()
        assertEquals(x.str("ephemeralPublicKey"), x25519PublicKey(esk).hex())
        assertEquals(x.str("sharedSecret"), x25519Agree(esk, keys[0].x25519PublicKey).hex())

        val h = vectors.getValue("hybrid")
        val shared = hybridSharedSecret(
            h.str("mlkemSharedSecret").unhex(),
            h.str("x25519SharedSecret").unhex(),
            h.str("x25519Ciphertext").unhex(),
            h.str("x25519PublicKey").unhex(),
        )
        assertEquals(h.str("shared"), shared.hex())

        for (d in vectors.getValue("kdf").jsonArray) {
            assertEquals(d.str("info"), kdfInfo(d.str("chainId"), d.str("purpose")))
            val key = deriveKey(d.str("shared").unhex(), d.str("chainId"), d.str("purpose"), d.str("salt").unhex())
            assertEquals(d.str("key"), key.hex())
        }
        val hint = vectors.getValue("hint")
        assertEquals(hint.str("hint"), recipientHint(hint.str("salt").unhex(), keys[0].mlkemPublicKey).hex())
    }

    @Test
    fun envelopes() {
        val byName = mutableMapOf<String, JsonElement>()
        for (e in vectors.getValue("envelopes").jsonArray) {
            byName[e.str("name")] = e
            val idx = e.jsonObject.getValue("recipients").jsonArray.map { it.jsonPrimitive.int }
            val aad = e.str("aad").unhex()
            val env = testingSealWithEntropy(
                chainId, purpose, idx.map { recipientOf(keys[it]) },
                e.str("plaintext").unhex(), e.str("entropy").unhex(),
                aad, mode(e.str("mode")), e.jsonObject.getValue("anonymous").jsonPrimitive.boolean,
            )
            assertEquals(e.str("envelope"), env.hex(), e.str("name"))
            assertEquals(e.str("text"), envelopeToText(env))
            assertArrayEquals(env, envelopeFromText(e.str("text")))
            for (i in idx) {
                assertEquals(e.str("plaintext"), openEnvelope(chainId, purpose, env, keys[i], aad).hex())
            }
            assertEquals(idx.size, parseEnvelope(env).entries.size)
        }
        for (n in vectors.getValue("negative").jsonArray) {
            val base = byName.getValue(n.str("base"))
            var env = base.str("envelope").unhex()
            n.opt("flip")?.toInt()?.let { env[it] = (env[it].toInt() xor 1).toByte() }
            n.jsonObject["set"]?.jsonArray?.let { env[it[0].jsonPrimitive.int] = it[1].jsonPrimitive.int.toByte() }
            n.opt("truncate")?.toInt()?.let { env = env.copyOf(it) }
            val aad = (n.opt("aad") ?: base.str("aad")).unhex()
            val code = errorCode {
                openEnvelope(n.opt("chainId") ?: chainId, n.opt("purpose") ?: purpose, env, keys[n.str("key").toInt()], aad)
            }
            assertEquals(n.str("error"), code, n.str("name"))
        }
        for (t in vectors.getValue("textNegative").jsonArray) {
            assertEquals(t.str("error"), errorCode { envelopeFromText(t.str("text")) }, t.str("name"))
        }
        for (s in vectors.getValue("sizes").jsonArray) {
            val size = envelopeSize(mode(s.str("mode")), s.str("recipients").toUInt(), s.str("plaintextLength").toULong())
            assertEquals(s.str("size").toULong(), size)
        }
    }

    @Test
    fun recipientCard() {
        val c = vectors.getValue("card")
        val card = c.jsonObject.getValue("card").jsonObject
        val acct = accountKeysFromMnemonic(c.str("mnemonic"))
        assertEquals(c.str("address"), acct.address)
        assertEquals(c.str("pqPublicKey"), acct.pqPublicKey.hex())
        val sk = deriveSealKeys(c.str("mnemonic"))
        val fields = recipientCardFields(chainId, acct.address, sk.mlkemPublicKey, sk.x25519PublicKey, card.str("issuedAt"))
        assertEquals(c.str("text"), recipientCardText(fields))
        val signed = signRecipientCard(fields, acct.classicalPrivateKey, acct.pqSecretKey)
        assertEquals(card, Json.parseToJsonElement(signed))
        val r = verifyRecipientCard(card.toString(), chainId, c.str("pqPublicKey").unhex(), sk.mlkemPublicKey, acct.address)
        assertArrayEquals(sk.x25519PublicKey, r.x25519PublicKey)
        for (n in c.jsonObject.getValue("negative").jsonArray) {
            val cc = n.opt("x25519PublicKey")?.let { JsonObject(card + ("x25519PublicKey" to JsonPrimitive(it))) } ?: card
            val mlkem = n.opt("mlkemKey")?.let { keys[it.toInt()].mlkemPublicKey } ?: sk.mlkemPublicKey
            val code = errorCode {
                verifyRecipientCard(cc.toString(), n.opt("chainId") ?: chainId, c.str("pqPublicKey").unhex(), mlkem, n.opt("address"))
            }
            assertEquals(n.str("error"), code, n.str("name"))
        }
    }

    @Test
    fun registryEpochAndBatch() {
        val r = vectors.getValue("registry")
        val sk = deriveSealKeys(vectors.getValue("card").str("mnemonic"))
        val reg = buildRegisterKemKeyMessage(r.str("sender"), sk.mlkemPublicKey)
        assertEquals(QoreSealConstants.MSG_REGISTER_KEM_KEY_TYPE_URL, reg.typeUrl)
        assertEquals(r.jsonObject.getValue("register").str("value"), reg.value.hex())
        assertEquals(r.jsonObject.getValue("remove").str("value"), buildRemoveKemKeyMessage(r.str("sender")).value.hex())

        val e = vectors.getValue("epoch")
        val ek = EpochKey(1uL, e.str("key").unhex())
        val payload = encodeEpochKey(ek)
        assertEquals(e.str("payload"), payload.hex())
        val idx = e.jsonObject.getValue("recipients").jsonArray.map { it.jsonPrimitive.int }
        val env = testingSealWithEntropy(chainId, e.str("purpose"), idx.map { recipientOf(keys[it]) }, payload, e.str("entropy").unhex())
        assertEquals(e.str("envelope"), env.hex())
        for (i in idx) assertArrayEquals(ek.key, openEpochKey(chainId, e.str("purpose"), env, keys[i]).key)

        val b = vectors.getValue("batch")
        val sealed = testingSealBatchWithEntropy(ek, b.str("context"), 7uL, b.str("data").unhex(), b.str("entropy").unhex())
        assertEquals(b.str("blob"), sealed.blob.hex())
        assertEquals(b.str("ciphertextCommitment"), sealed.ciphertextCommitment.hex())
        assertEquals(b.str("plaintextCommitment"), sealed.plaintextCommitment.hex())
        assertEquals(b.str("data"), openBatch(sealed.blob, listOf(ek)).data.hex())
    }

    @Test
    fun groupsAndRoundTrip() {
        val a = generateSealKeys()
        val b = generateSealKeys()
        val env = sealEnvelope(chainId, "chat", listOf(recipientOf(a)), "hi".toByteArray())
        assertEquals("hi", String(openEnvelope(chainId, "chat", env, a)))
        assertEquals("NOT_A_RECIPIENT", errorCode { openEnvelope(chainId, "chat", env, b) })
        assertEquals("RECIPIENT_NEEDS_X25519", errorCode { sealEnvelope(chainId, "chat", listOf(SealRecipient(a.mlkemPublicKey)), ByteArray(0)) })

        EpochKeyManager(chainId, "epoch-key:demo", listOf(GroupMember("a", recipientOf(a)))).use { mgr ->
            val rot = mgr.addMember("b", recipientOf(b))
            assertEquals(2uL, rot.epoch)
            val key = openEpochKey(chainId, "epoch-key:demo", rot.envelope!!, b)
            val batch = mgr.sealBatch("demo", 1uL, "x".toByteArray())
            assertEquals("x", String(openBatch(batch.blob, listOf(key)).data))
            val gone = mgr.removeMember("b")
            assertEquals("NOT_A_RECIPIENT", errorCode { openEpochKey(chainId, "epoch-key:demo", gone.envelope!!, b) })
        }
    }
}
