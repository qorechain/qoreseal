// SPDX-License-Identifier: Apache-2.0
//
// The FFI surface against vectors/qoreseal-v1.json (the core crate has the
// full vector suite; this checks the conversions).

use qoreseal_ffi::*;
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/qoreseal-v1.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).expect("parse")
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("string")).expect("hex")
}

fn s(v: &Value) -> String {
    v.as_str().expect("string").to_owned()
}

fn code<T: std::fmt::Debug>(r: Result<T, QoreSealError>) -> String {
    match r.unwrap_err() {
        QoreSealError::Failure { code, .. } => code,
    }
}

fn mode(v: &Value) -> Option<SealMode> {
    Some(if v == "hybrid" {
        SealMode::Hybrid
    } else {
        SealMode::Mlkem
    })
}

#[test]
fn envelopes_cards_and_batches() {
    let v = vectors();
    let keys: Vec<SealKeyPair> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| seal_keys_from_seed(h(&k["seed"])).unwrap())
        .collect();
    for e in v["envelopes"].as_array().unwrap() {
        let idx: Vec<usize> = e["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap() as usize)
            .collect();
        let rs = idx.iter().map(|i| recipient_of(keys[*i].clone())).collect();
        let env = testing_seal_with_entropy(
            s(&v["chainId"]),
            s(&v["purpose"]),
            rs,
            h(&e["plaintext"]),
            h(&e["entropy"]),
            h(&e["aad"]),
            mode(&e["mode"]),
            e["anonymous"].as_bool().unwrap(),
        )
        .unwrap();
        assert_eq!(hex::encode(&env), s(&e["envelope"]));
        assert_eq!(envelope_to_text(env.clone()), s(&e["text"]));
        for i in idx {
            let out = open_envelope(
                s(&v["chainId"]),
                s(&v["purpose"]),
                env.clone(),
                keys[i].clone(),
                h(&e["aad"]),
            )
            .unwrap();
            assert_eq!(out, h(&e["plaintext"]));
        }
    }
    let single = &v["envelopes"][0];
    assert_eq!(
        code(open_envelope(
            s(&v["chainId"]),
            s(&v["purpose"]),
            h(&single["envelope"]),
            keys[1].clone(),
            h(&single["aad"])
        )),
        "NOT_A_RECIPIENT"
    );

    let c = &v["card"];
    let acct = account_keys_from_mnemonic(s(&c["mnemonic"]), 0).unwrap();
    assert_eq!(acct.address, s(&c["address"]));
    let sk = derive_seal_keys(s(&c["mnemonic"]), String::new(), 0).unwrap();
    let fields = recipient_card_fields(
        s(&v["chainId"]),
        acct.address.clone(),
        sk.mlkem_public_key.clone(),
        sk.x25519_public_key.clone(),
        Some(s(&c["card"]["issuedAt"])),
    )
    .unwrap();
    assert_eq!(recipient_card_text(fields.clone()).unwrap(), s(&c["text"]));
    let json = sign_recipient_card(
        fields,
        acct.classical_private_key.clone(),
        acct.pq_secret_key.clone(),
        "secp256k1".into(),
    )
    .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&json).unwrap(), c["card"]);
    let r = verify_recipient_card(
        c["card"].to_string(),
        s(&v["chainId"]),
        h(&c["pqPublicKey"]),
        sk.mlkem_public_key.clone(),
        Some(acct.address),
    )
    .unwrap();
    assert_eq!(r.x25519_public_key.unwrap(), sk.x25519_public_key);
    assert_eq!(
        code(verify_recipient_card(
            c["card"].to_string(),
            "qorechain-vladi".into(),
            h(&c["pqPublicKey"]),
            sk.mlkem_public_key.clone(),
            None
        )),
        "CARD_INVALID"
    );

    let b = &v["batch"];
    let ek = EpochKey {
        epoch: 1,
        key: h(&b["key"]),
    };
    let sealed = testing_seal_batch_with_entropy(
        ek.clone(),
        s(&b["context"]),
        7,
        h(&b["data"]),
        h(&b["entropy"]),
    )
    .unwrap();
    assert_eq!(hex::encode(&sealed.blob), s(&b["blob"]));
    assert_eq!(
        open_batch(sealed.blob, vec![ek]).unwrap().data,
        h(&b["data"])
    );
}

#[test]
fn group_manager_object() {
    let (a, b) = (generate_seal_keys(), generate_seal_keys());
    let mgr = EpochKeyManager::new(
        "qorechain-diana".into(),
        "epoch-key:demo".into(),
        vec![GroupMember {
            id: "a".into(),
            recipient: recipient_of(a.clone()),
        }],
        None,
        vec![],
    )
    .unwrap();
    let rot = mgr.add_member("b".into(), recipient_of(b.clone())).unwrap();
    assert_eq!(rot.epoch, 2);
    let key = open_epoch_key(
        "qorechain-diana".into(),
        "epoch-key:demo".into(),
        rot.envelope.unwrap(),
        b,
    )
    .unwrap();
    let batch = mgr.seal_batch("demo".into(), 1, b"x".to_vec()).unwrap();
    assert_eq!(
        open_batch(batch.blob.clone(), vec![key]).unwrap().data,
        b"x"
    );
    assert_eq!(mgr.open_batch(batch.blob).unwrap().epoch, 2);
    assert_eq!(code(mgr.remove_member("zzz".into())), "INVALID_ARGUMENT");
}
