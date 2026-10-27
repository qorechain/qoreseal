// SPDX-License-Identifier: Apache-2.0
//
// The Rust crate against vectors/qoreseal-v1.json.

use qoreseal::qoresign::{
    address_from_public_key, derive_canonical_pq_key, derive_classical_key, ClassicalKeyType,
};
use qoreseal::testing::{
    mlkem_encapsulate_with_randomness, seal_batch_with_entropy, seal_with_entropy,
};
use qoreseal::*;
use serde_json::Value;
use sha3::{Digest, Sha3_256};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/qoreseal-v1.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors file")).expect("JSON")
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}

fn s(v: &Value) -> &str {
    v.as_str().expect("string")
}

fn sha3(b: &[u8]) -> String {
    hex::encode(Sha3_256::digest(b))
}

fn keys(v: &Value) -> Vec<SealKeyPair> {
    v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| seal_keys_from_seed(&h(&k["seed"])).unwrap())
        .collect()
}

fn mode(v: &Value) -> SealMode {
    match s(v) {
        "hybrid" => SealMode::Hybrid,
        _ => SealMode::Mlkem,
    }
}

fn idx(v: &Value) -> usize {
    v.as_u64().unwrap() as usize
}

#[test]
fn keys_and_seeds() {
    let v = vectors();
    let ks = keys(&v);
    for (k, e) in ks.iter().zip(v["keys"].as_array().unwrap()) {
        assert_eq!(hex::encode(&k.mlkem_public_key), s(&e["mlkemPublicKey"]));
        assert_eq!(sha3(&k.mlkem_secret_key), s(&e["mlkemSecretKeySha3"]));
        assert_eq!(hex::encode(&k.x25519_public_key), s(&e["x25519PublicKey"]));
        assert_eq!(hex::encode(&k.x25519_secret_key), s(&e["x25519SecretKey"]));
    }
    for m in v["mnemonicSeeds"].as_array().unwrap() {
        let seed = seal_seed_from_mnemonic(
            s(&m["mnemonic"]),
            s(&m["passphrase"]),
            m["index"].as_u64().unwrap() as u32,
        )
        .unwrap();
        assert_eq!(hex::encode(&seed), s(&m["seed"]));
        assert_eq!(
            sha3(&seal_keys_from_seed(&seed).unwrap().mlkem_public_key),
            s(&m["mlkemPublicKeySha3"])
        );
    }
}

#[test]
fn primitives() {
    let v = vectors();
    let ks = keys(&v);
    let e = &v["encapsulation"];
    let k = &ks[idx(&e["recipient"])];
    let enc = mlkem_encapsulate_with_randomness(&k.mlkem_public_key, &h(&e["m"])).unwrap();
    assert_eq!(hex::encode(&enc.ciphertext), s(&e["ciphertext"]));
    assert_eq!(hex::encode(&enc.shared_secret), s(&e["sharedSecret"]));
    assert_eq!(
        hex::encode(mlkem_decapsulate(&k.mlkem_secret_key, &h(&e["ciphertext"])).unwrap()),
        s(&e["sharedSecret"])
    );

    let x = &v["x25519"];
    let kx = &ks[idx(&x["recipient"])];
    assert_eq!(
        hex::encode(x25519_public_key(&h(&x["ephemeralSecretKey"])).unwrap()),
        s(&x["ephemeralPublicKey"])
    );
    assert_eq!(
        hex::encode(x25519_agree(&h(&x["ephemeralSecretKey"]), &kx.x25519_public_key).unwrap()),
        s(&x["sharedSecret"])
    );
    assert_eq!(
        hex::encode(x25519_agree(&kx.x25519_secret_key, &h(&x["ephemeralPublicKey"])).unwrap()),
        s(&x["sharedSecret"])
    );

    let hy = &v["hybrid"];
    assert_eq!(HYBRID_LABEL, s(&hy["label"]));
    let shared = hybrid_shared_secret(
        &h(&hy["mlkemSharedSecret"]),
        &h(&hy["x25519SharedSecret"]),
        &h(&hy["x25519Ciphertext"]),
        &h(&hy["x25519PublicKey"]),
    )
    .unwrap();
    assert_eq!(hex::encode(shared), s(&hy["shared"]));

    for k in v["kdf"].as_array().unwrap() {
        assert_eq!(
            kdf_info(s(&k["chainId"]), s(&k["purpose"])).unwrap(),
            s(&k["info"])
        );
        let key = derive_key(
            &h(&k["shared"]),
            s(&k["chainId"]),
            s(&k["purpose"]),
            &h(&k["salt"]),
        )
        .unwrap();
        assert_eq!(hex::encode(key), s(&k["key"]));
    }
    let hint = &v["hint"];
    assert_eq!(
        hex::encode(recipient_hint(
            &h(&hint["salt"]),
            &ks[idx(&hint["recipient"])].mlkem_public_key
        )),
        s(&hint["hint"])
    );
}

#[test]
fn envelopes() {
    let v = vectors();
    let ks = keys(&v);
    let chain = s(&v["chainId"]);
    let purpose = s(&v["purpose"]);
    for e in v["envelopes"].as_array().unwrap() {
        let rs: Vec<SealRecipient> = e["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| ks[idx(i)].recipient())
            .collect();
        let pt = h(&e["plaintext"]);
        let aad = h(&e["aad"]);
        let mut args = SealArgs::new(chain, purpose, &rs, &pt);
        args.aad = &aad;
        args.mode = mode(&e["mode"]);
        args.anonymous = e["anonymous"].as_bool().unwrap();
        let env = seal_with_entropy(&args, &h(&e["entropy"])).unwrap();
        assert_eq!(hex::encode(&env), s(&e["envelope"]), "{}", s(&e["name"]));
        assert_eq!(env.len() as u64, e["size"].as_u64().unwrap());
        assert_eq!(envelope_to_text(&env), s(&e["text"]));
        assert_eq!(envelope_from_text(s(&e["text"])).unwrap(), env);
        for i in e["recipients"].as_array().unwrap() {
            assert_eq!(open(chain, purpose, &env, &ks[idx(i)], &aad).unwrap(), pt);
        }
        let p = parse_envelope(&env).unwrap();
        assert_eq!(p.mode, args.mode);
        assert_eq!(p.anonymous, args.anonymous);
        assert_eq!(p.entries.len(), rs.len());
    }
}

#[test]
fn negative_cases() {
    let v = vectors();
    let ks = keys(&v);
    let envs = v["envelopes"].as_array().unwrap();
    for n in v["negative"].as_array().unwrap() {
        let base = envs.iter().find(|e| e["name"] == n["base"]).unwrap();
        let mut env = h(&base["envelope"]);
        if let Some(f) = n.get("flip") {
            env[idx(f)] ^= 1;
        }
        if let Some(set) = n.get("set") {
            env[idx(&set[0])] = set[1].as_u64().unwrap() as u8;
        }
        if let Some(t) = n.get("truncate") {
            env.truncate(idx(t));
        }
        let aad = n.get("aad").map(h).unwrap_or_else(|| h(&base["aad"]));
        let err = open(
            n.get("chainId").map(s).unwrap_or(s(&v["chainId"])),
            n.get("purpose").map(s).unwrap_or(s(&v["purpose"])),
            &env,
            &ks[idx(&n["key"])],
            &aad,
        )
        .unwrap_err();
        assert_eq!(err.code(), s(&n["error"]), "{}", s(&n["name"]));
    }
    for t in v["textNegative"].as_array().unwrap() {
        assert_eq!(
            envelope_from_text(s(&t["text"])).unwrap_err().code(),
            s(&t["error"]),
            "{}",
            s(&t["name"])
        );
    }
    for sz in v["sizes"].as_array().unwrap() {
        assert_eq!(
            envelope_size(
                mode(&sz["mode"]),
                idx(&sz["recipients"]),
                idx(&sz["plaintextLength"])
            ) as u64,
            sz["size"].as_u64().unwrap()
        );
    }
}

#[test]
fn recipient_card() {
    let v = vectors();
    let ks = keys(&v);
    let c = &v["card"];
    let mnemonic = s(&c["mnemonic"]);
    let classical = derive_classical_key(mnemonic, ClassicalKeyType::Secp256k1, 0).unwrap();
    let address = address_from_public_key(&classical.public_key, ClassicalKeyType::Secp256k1)
        .unwrap()
        .bech32;
    assert_eq!(address, s(&c["address"]));
    let pq = derive_canonical_pq_key(mnemonic, &address).unwrap();
    assert_eq!(hex::encode(&pq.public_key), s(&c["pqPublicKey"]));
    let seal_keys =
        derive_seal_keys(mnemonic, "", c["sealKeysIndex"].as_u64().unwrap() as u32).unwrap();
    let issued = s(&c["card"]["issuedAt"]);
    let fields = recipient_card_fields(
        s(&v["chainId"]),
        &address,
        &seal_keys.mlkem_public_key,
        &seal_keys.x25519_public_key,
        Some(issued),
    )
    .unwrap();
    assert_eq!(recipient_card_text(&fields).unwrap(), s(&c["text"]));
    let card = sign_recipient_card(&fields, &classical, &pq).unwrap();
    assert_eq!(serde_json::to_value(&card).unwrap(), c["card"]);

    let parsed = RecipientCard::from_json(&c["card"].to_string()).unwrap();
    let pq_pk = h(&c["pqPublicKey"]);
    let r = verify_recipient_card(&VerifyCardArgs {
        card: &parsed,
        chain_id: s(&v["chainId"]),
        address: Some(&address),
        pq_public_key: &pq_pk,
        mlkem_public_key: &seal_keys.mlkem_public_key,
    })
    .unwrap();
    assert_eq!(r.x25519_public_key.unwrap(), seal_keys.x25519_public_key);

    for n in c["negative"].as_array().unwrap() {
        let mut card = parsed.clone();
        if let Some(x) = n.get("x25519PublicKey") {
            card.x25519_public_key = s(x).to_owned();
        }
        let mlkem = n
            .get("mlkemKey")
            .map(|i| ks[idx(i)].mlkem_public_key.clone())
            .unwrap_or_else(|| seal_keys.mlkem_public_key.clone());
        let err = verify_recipient_card(&VerifyCardArgs {
            card: &card,
            chain_id: n.get("chainId").map(s).unwrap_or(s(&v["chainId"])),
            address: n.get("address").map(s),
            pq_public_key: &pq_pk,
            mlkem_public_key: &mlkem,
        })
        .unwrap_err();
        assert_eq!(err.code(), s(&n["error"]), "{}", s(&n["name"]));
    }
}

#[test]
fn registry_epochs_and_batches() {
    let v = vectors();
    let ks = keys(&v);
    let r = &v["registry"];
    let seal_keys = derive_seal_keys(s(&v["card"]["mnemonic"]), "", 0).unwrap();
    let reg = build_register_kem_key_message(s(&r["sender"]), &seal_keys.mlkem_public_key).unwrap();
    assert_eq!(reg.type_url, s(&r["register"]["typeUrl"]));
    assert_eq!(hex::encode(&reg.value), s(&r["register"]["value"]));
    let rem = build_remove_kem_key_message(s(&r["sender"])).unwrap();
    assert_eq!(rem.type_url, s(&r["remove"]["typeUrl"]));
    assert_eq!(hex::encode(&rem.value), s(&r["remove"]["value"]));

    let e = &v["epoch"];
    let ek = EpochKey {
        epoch: e["epoch"].as_u64().unwrap(),
        key: h(&e["key"]),
    };
    let payload = encode_epoch_key(&ek).unwrap();
    assert_eq!(hex::encode(&payload), s(&e["payload"]));
    let rs: Vec<SealRecipient> = e["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| ks[idx(i)].recipient())
        .collect();
    let env = seal_with_entropy(
        &SealArgs::new(s(&v["chainId"]), s(&e["purpose"]), &rs, &payload),
        &h(&e["entropy"]),
    )
    .unwrap();
    assert_eq!(hex::encode(&env), s(&e["envelope"]));
    for i in e["recipients"].as_array().unwrap() {
        assert_eq!(
            open_epoch_key(s(&v["chainId"]), s(&e["purpose"]), &env, &ks[idx(i)]).unwrap(),
            ek
        );
    }

    let b = &v["batch"];
    let bk = EpochKey {
        epoch: b["epoch"].as_u64().unwrap(),
        key: h(&b["key"]),
    };
    let data = h(&b["data"]);
    let sealed = seal_batch_with_entropy(
        &bk,
        s(&b["context"]),
        b["batchIndex"].as_u64().unwrap(),
        &data,
        &h(&b["entropy"]),
    )
    .unwrap();
    assert_eq!(hex::encode(&sealed.blob), s(&b["blob"]));
    assert_eq!(
        hex::encode(&sealed.ciphertext_commitment),
        s(&b["ciphertextCommitment"])
    );
    assert_eq!(
        hex::encode(&sealed.plaintext_commitment),
        s(&b["plaintextCommitment"])
    );
    assert_eq!(
        sealed.blob.len(),
        batch_size(s(&b["context"]).len(), data.len())
    );
    let list = [bk];
    let opened = open_batch(&sealed.blob, keys_from_list(&list)).unwrap();
    assert_eq!(opened.data, data);
    assert_eq!(opened.batch_index, 7);
    assert_eq!(opened.context, s(&b["context"]));
    assert_eq!(
        hex::encode(&opened.plaintext_commitment),
        s(&b["plaintextCommitment"])
    );
}
