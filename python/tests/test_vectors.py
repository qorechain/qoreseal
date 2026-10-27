# SPDX-License-Identifier: Apache-2.0
#
# Checks the Python package against vectors/qoreseal-v1.json.

import json
import re
from pathlib import Path

import pytest

import qoreseal as qs

PYTHON_DIR = Path(__file__).resolve().parents[1]
VECTORS = PYTHON_DIR.parent / "vectors" / "qoreseal-v1.json"


def code_of(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except qs.QoreSealError as e:
        return e.code
    return None


def mode(s):
    return qs.SealMode.HYBRID if s == "hybrid" else qs.SealMode.MLKEM


H = bytes.fromhex


@pytest.fixture(scope="module")
def v():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert data["format"] == "qoreseal-vectors-v1"
    return data


@pytest.fixture(scope="module")
def keys(v):
    return [qs.seal_keys_from_seed(H(k["seed"])) for k in v["keys"]]


def test_package():
    pyproject = (PYTHON_DIR / "pyproject.toml").read_text(encoding="utf-8")
    assert qs.__version__ == re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    for name in qs.__all__:
        assert hasattr(qs, name), name
    assert qs.ALGORITHM_ML_KEM_1024 == 2


def test_keys_and_seeds(v, keys):
    for k, e in zip(keys, v["keys"]):
        assert k.mlkem_public_key.hex() == e["mlkemPublicKey"]
        assert k.x25519_public_key.hex() == e["x25519PublicKey"]
        assert k.x25519_secret_key.hex() == e["x25519SecretKey"]
    for m in v["mnemonicSeeds"]:
        seed = qs.seal_seed_from_mnemonic(m["mnemonic"], m["passphrase"], m["index"])
        assert seed.hex() == m["seed"]


def test_primitives(v, keys):
    e = v["encapsulation"]
    k = keys[e["recipient"]]
    enc = qs.testing_mlkem_encapsulate_with_randomness(k.mlkem_public_key, H(e["m"]))
    assert enc.ciphertext.hex() == e["ciphertext"]
    assert enc.shared_secret.hex() == e["sharedSecret"]
    assert qs.mlkem_decapsulate(k.mlkem_secret_key, enc.ciphertext).hex() == e["sharedSecret"]
    x = v["x25519"]
    esk = H(x["ephemeralSecretKey"])
    assert qs.x25519_public_key(esk).hex() == x["ephemeralPublicKey"]
    assert qs.x25519_agree(esk, keys[0].x25519_public_key).hex() == x["sharedSecret"]
    h = v["hybrid"]
    shared = qs.hybrid_shared_secret(
        H(h["mlkemSharedSecret"]), H(h["x25519SharedSecret"]), H(h["x25519Ciphertext"]), H(h["x25519PublicKey"])
    )
    assert shared.hex() == h["shared"]
    for d in v["kdf"]:
        assert qs.kdf_info(d["chainId"], d["purpose"]) == d["info"]
        assert qs.derive_key(H(d["shared"]), d["chainId"], d["purpose"], H(d["salt"])).hex() == d["key"]
    assert qs.recipient_hint(H(v["hint"]["salt"]), keys[0].mlkem_public_key).hex() == v["hint"]["hint"]


def test_envelopes(v, keys):
    by_name = {}
    for e in v["envelopes"]:
        by_name[e["name"]] = e
        rs = [qs.recipient_of(keys[i]) for i in e["recipients"]]
        aad = H(e["aad"])
        env = qs.testing_seal_with_entropy(
            v["chainId"], v["purpose"], rs, H(e["plaintext"]), H(e["entropy"]),
            aad=aad, mode=mode(e["mode"]), anonymous=e["anonymous"],
        )
        assert env.hex() == e["envelope"], e["name"]
        assert qs.envelope_to_text(env) == e["text"]
        assert qs.envelope_from_text(e["text"]) == env
        for i in e["recipients"]:
            assert qs.open_envelope(v["chainId"], v["purpose"], env, keys[i], aad=aad).hex() == e["plaintext"]
        assert len(qs.parse_envelope(env).entries) == len(rs)
    for n in v["negative"]:
        base = by_name[n["base"]]
        env = bytearray(H(base["envelope"]))
        if "flip" in n:
            env[n["flip"]] ^= 1
        if "set" in n:
            env[n["set"][0]] = n["set"][1]
        if "truncate" in n:
            env = env[: n["truncate"]]
        code = code_of(
            qs.open_envelope,
            n.get("chainId", v["chainId"]),
            n.get("purpose", v["purpose"]),
            bytes(env),
            keys[n["key"]],
            aad=H(n.get("aad", base["aad"])),
        )
        assert code == n["error"], n["name"]
    for t in v["textNegative"]:
        assert code_of(qs.envelope_from_text, t["text"]) == t["error"], t["name"]
    for s in v["sizes"]:
        assert qs.envelope_size(mode(s["mode"]), s["recipients"], s["plaintextLength"]) == s["size"]


def test_recipient_card(v, keys):
    c = v["card"]
    card = c["card"]
    acct = qs.account_keys_from_mnemonic(c["mnemonic"])
    assert acct.address == c["address"]
    assert acct.pq_public_key.hex() == c["pqPublicKey"]
    sk = qs.derive_seal_keys(c["mnemonic"])
    fields = qs.recipient_card_fields(
        v["chainId"], acct.address, sk.mlkem_public_key, sk.x25519_public_key, issued_at=card["issuedAt"]
    )
    assert qs.recipient_card_text(fields) == c["text"]
    signed = qs.sign_recipient_card(fields, acct.classical_private_key, acct.pq_secret_key)
    assert json.loads(signed) == card
    r = qs.verify_recipient_card(json.dumps(card), v["chainId"], H(c["pqPublicKey"]), sk.mlkem_public_key, address=acct.address)
    assert r.x25519_public_key == sk.x25519_public_key
    for n in c["negative"]:
        cc = dict(card)
        if "x25519PublicKey" in n:
            cc["x25519PublicKey"] = n["x25519PublicKey"]
        mlkem = keys[n["mlkemKey"]].mlkem_public_key if "mlkemKey" in n else sk.mlkem_public_key
        code = code_of(
            qs.verify_recipient_card,
            json.dumps(cc),
            n.get("chainId", v["chainId"]),
            H(c["pqPublicKey"]),
            mlkem,
            address=n.get("address"),
        )
        assert code == n["error"], n["name"]


def test_registry_epoch_and_batch(v, keys):
    r = v["registry"]
    sk = qs.derive_seal_keys(v["card"]["mnemonic"])
    reg = qs.build_register_kem_key_message(r["sender"], sk.mlkem_public_key)
    assert reg.type_url == qs.MSG_REGISTER_KEM_KEY_TYPE_URL
    assert reg.value.hex() == r["register"]["value"]
    assert qs.build_remove_kem_key_message(r["sender"]).value.hex() == r["remove"]["value"]
    assert "signature key" in qs.describe_kem_registry_error("pqc", 254)
    assert qs.describe_kem_registry_error("sdk", 254) is None

    e = v["epoch"]
    ek = qs.EpochKey(epoch=e["epoch"], key=H(e["key"]))
    payload = qs.encode_epoch_key(ek)
    assert payload.hex() == e["payload"]
    rs = [qs.recipient_of(keys[i]) for i in e["recipients"]]
    env = qs.testing_seal_with_entropy(v["chainId"], e["purpose"], rs, payload, H(e["entropy"]))
    assert env.hex() == e["envelope"]
    for i in e["recipients"]:
        assert qs.open_epoch_key(v["chainId"], e["purpose"], env, keys[i]) == ek

    b = v["batch"]
    sealed = qs.testing_seal_batch_with_entropy(ek, b["context"], b["batchIndex"], H(b["data"]), H(b["entropy"]))
    assert sealed.blob.hex() == b["blob"]
    assert sealed.ciphertext_commitment.hex() == b["ciphertextCommitment"]
    assert sealed.plaintext_commitment.hex() == b["plaintextCommitment"]
    assert qs.open_batch(sealed.blob, [ek]).data.hex() == b["data"]


def test_groups_and_round_trip():
    a, b = qs.generate_seal_keys(), qs.generate_seal_keys()
    env = qs.seal_envelope("qorechain-diana", "chat", [qs.recipient_of(a)], b"hi")
    assert qs.open_envelope("qorechain-diana", "chat", env, a) == b"hi"
    assert code_of(qs.open_envelope, "qorechain-diana", "chat", env, b) == "NOT_A_RECIPIENT"
    only_kem = qs.SealRecipient(mlkem_public_key=a.mlkem_public_key)
    assert code_of(qs.seal_envelope, "qorechain-diana", "chat", [only_kem], b"") == "RECIPIENT_NEEDS_X25519"
    mlkem_env = qs.seal_envelope("qorechain-diana", "chat", [only_kem], b"k", mode=qs.SealMode.MLKEM)
    assert qs.open_envelope("qorechain-diana", "chat", mlkem_env, a) == b"k"

    mgr = qs.EpochKeyManager("qorechain-diana", "epoch-key:demo", [qs.GroupMember(id="a", recipient=qs.recipient_of(a))])
    rot = mgr.add_member("b", qs.recipient_of(b))
    assert rot.epoch == 2
    key = qs.open_epoch_key("qorechain-diana", "epoch-key:demo", rot.envelope, b)
    batch = mgr.seal_batch("demo", 1, b"x")
    assert qs.open_batch(batch.blob, [key]).data == b"x"
    gone = mgr.remove_member("b")
    assert code_of(qs.open_epoch_key, "qorechain-diana", "epoch-key:demo", gone.envelope, b) == "NOT_A_RECIPIENT"
