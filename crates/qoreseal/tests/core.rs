// SPDX-License-Identifier: Apache-2.0
//
// Behaviour beyond the vectors: random round trips, input checks, groups and batches.

use qoreseal::testing::{seal_entropy_length, seal_with_entropy};
use qoreseal::*;

const CHAIN: &str = "qorechain-diana";

#[test]
fn round_trips_in_both_modes() {
    let (alice, bob, carol) = (
        generate_seal_keys(),
        generate_seal_keys(),
        generate_seal_keys(),
    );
    let rs = [alice.recipient(), bob.recipient()];
    for mode in [SealMode::Hybrid, SealMode::Mlkem] {
        for anonymous in [false, true] {
            let mut args = SealArgs::new(CHAIN, "chat", &rs, b"hello");
            args.mode = mode;
            args.anonymous = anonymous;
            let env = seal(&args).unwrap();
            assert_eq!(env.len(), envelope_size(mode, 2, 5));
            for k in [&alice, &bob] {
                assert_eq!(open(CHAIN, "chat", &env, k, &[]).unwrap(), b"hello");
            }
            let err = open(CHAIN, "chat", &env, &carol, &[]).unwrap_err();
            assert_eq!(
                err.code(),
                if anonymous {
                    "DECRYPTION_FAILED"
                } else {
                    "NOT_A_RECIPIENT"
                }
            );
        }
    }
    let args = SealArgs::new(CHAIN, "chat", &rs, b"x");
    assert_ne!(seal(&args).unwrap(), seal(&args).unwrap());
}

#[test]
fn hybrid_needs_the_x25519_key() {
    let alice = generate_seal_keys();
    let only_kem = [SealRecipient {
        mlkem_public_key: alice.mlkem_public_key.clone(),
        x25519_public_key: None,
    }];
    let err = seal(&SealArgs::new(CHAIN, "chat", &only_kem, b"x")).unwrap_err();
    assert_eq!(err.code(), "RECIPIENT_NEEDS_X25519");
    let mut args = SealArgs::new(CHAIN, "chat", &only_kem, b"x");
    args.mode = SealMode::Mlkem;
    assert_eq!(
        parse_envelope(&seal(&args).unwrap()).unwrap().mode,
        SealMode::Mlkem
    );
}

#[test]
fn input_checks() {
    let alice = generate_seal_keys();
    let mut bad = alice.mlkem_public_key.clone();
    bad[0] = 0xff;
    bad[1] = 0x0f;
    assert_eq!(
        validate_mlkem_public_key(&bad).unwrap_err().code(),
        "INVALID_KEY"
    );
    assert_eq!(
        validate_mlkem_public_key(&[0u8; 1568]).unwrap_err().code(),
        "INVALID_KEY"
    );
    assert_eq!(
        validate_mlkem_public_key(&[1u8; 1567]).unwrap_err().code(),
        "INVALID_KEY"
    );
    let r = alice.recipient();
    let code = |recipient: SealRecipient, chain: &str, purpose: &str| {
        let rs = [recipient];
        seal(&SealArgs::new(chain, purpose, &rs, b"x"))
            .unwrap_err()
            .code()
    };
    assert_eq!(
        code(
            SealRecipient {
                mlkem_public_key: bad.clone(),
                ..r.clone()
            },
            CHAIN,
            "chat"
        ),
        "INVALID_KEY"
    );
    let mut low = vec![0u8; 32];
    low[0] = 1;
    assert_eq!(
        code(
            SealRecipient {
                x25519_public_key: Some(low),
                ..r.clone()
            },
            CHAIN,
            "chat"
        ),
        "INVALID_KEY"
    );
    assert_eq!(
        code(
            SealRecipient {
                x25519_public_key: Some(vec![0u8; 32]),
                ..r.clone()
            },
            CHAIN,
            "chat"
        ),
        "INVALID_KEY"
    );
    assert_eq!(code(r.clone(), "bad|chain", "chat"), "INVALID_ARGUMENT");
    assert_eq!(code(r.clone(), CHAIN, ""), "INVALID_ARGUMENT");
    assert_eq!(code(r.clone(), CHAIN, "a b"), "INVALID_ARGUMENT");
    assert_eq!(
        seal(&SealArgs::new(CHAIN, "chat", &[], b"x"))
            .unwrap_err()
            .code(),
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        seal_keys_from_seed(&[0u8; 31]).unwrap_err().code(),
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        derive_seal_keys("not a mnemonic", "", 0)
            .unwrap_err()
            .code(),
        "INVALID_ARGUMENT"
    );
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert_eq!(
        derive_seal_keys(mnemonic, "", 1 << 31).unwrap_err().code(),
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        parse_envelope(&[0u8; 3]).unwrap_err().code(),
        "MALFORMED_ENVELOPE"
    );
    assert_eq!(
        parse_envelope(b"QSEL\x01\x01\x02\x01\x01\x00")
            .unwrap_err()
            .code(),
        "MALFORMED_ENVELOPE"
    );
    assert!(describe_kem_registry_error("pqc", 254)
        .unwrap()
        .contains("signature key"));
    assert!(describe_kem_registry_error("sdk", 254).is_none());
    assert_eq!(
        build_register_kem_key_message("nope", &alice.mlkem_public_key)
            .unwrap_err()
            .code(),
        "INVALID_ARGUMENT"
    );
    assert_eq!(format_issued_at(1_793_102_400), "2026-10-27T12:00:00Z");
    assert_eq!(format_issued_at(951_782_400), "2000-02-29T00:00:00Z");
}

#[test]
fn test_entropy_must_be_exact() {
    let alice = generate_seal_keys();
    let rs = [alice.recipient()];
    let args = SealArgs::new(CHAIN, "chat", &rs, b"x");
    let n = seal_entropy_length(SealMode::Hybrid, 1);
    assert_eq!(n, 124);
    assert_eq!(
        seal_with_entropy(&args, &vec![7u8; n - 1])
            .unwrap_err()
            .code(),
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        seal_with_entropy(&args, &vec![7u8; n + 1])
            .unwrap_err()
            .code(),
        "INVALID_ARGUMENT"
    );
}

#[test]
fn groups_rotate_and_shut_removed_members_out() {
    let (alice, bob, carol) = (
        generate_seal_keys(),
        generate_seal_keys(),
        generate_seal_keys(),
    );
    let purpose = "epoch-key:demo-rollup";
    let mut mgr = EpochKeyManager::new(
        CHAIN,
        purpose,
        SealMode::Hybrid,
        vec![
            ("alice".into(), alice.recipient()),
            ("bob".into(), bob.recipient()),
        ],
        vec![],
    )
    .unwrap();
    assert_eq!(mgr.epoch(), 1);
    let b1 = PrivateBatchCodec::new("demo-rollup", &mgr)
        .unwrap()
        .seal(1, b"batch one")
        .unwrap();

    let join = mgr.add_member("carol", carol.recipient()).unwrap();
    assert_eq!(join.epoch, 2);
    let carol_key =
        open_epoch_key(CHAIN, purpose, join.envelope.as_ref().unwrap(), &carol).unwrap();
    assert_eq!(carol_key.epoch, 2);
    let carol_keys = [carol_key];
    assert_eq!(
        open_batch(&b1.blob, keys_from_list(&carol_keys))
            .unwrap_err()
            .code(),
        "UNKNOWN_EPOCH"
    );

    let leave = mgr.remove_member("bob").unwrap();
    assert_eq!(leave.epoch, 3);
    assert_eq!(
        leave.members,
        vec!["alice".to_string(), "carol".to_string()]
    );
    let env = leave.envelope.unwrap();
    assert_eq!(
        open_epoch_key(CHAIN, purpose, &env, &bob)
            .unwrap_err()
            .code(),
        "NOT_A_RECIPIENT"
    );
    let codec = PrivateBatchCodec::new("demo-rollup", &mgr).unwrap();
    let b3 = codec.seal(3, b"batch three").unwrap();
    let alice_keys = [open_epoch_key(CHAIN, purpose, &env, &alice).unwrap()];
    let opened = open_batch(&b3.blob, keys_from_list(&alice_keys)).unwrap();
    assert_eq!(opened.data, b"batch three");
    assert_eq!(opened.plaintext_commitment, b3.plaintext_commitment);
    assert_eq!(codec.open(&b1.blob).unwrap().batch_index, 1);

    let restored =
        EpochKeyManager::new(CHAIN, purpose, SealMode::Hybrid, vec![], mgr.export_keys()).unwrap();
    assert_eq!(restored.epoch(), 3);
    assert_eq!(restored.key_for(1), mgr.key_for(1));
}

#[test]
fn batches_refuse_tampering() {
    let ek = EpochKey {
        epoch: 4,
        key: vec![9u8; 32],
    };
    let b = seal_batch(&ek, "demo-rollup", 2, b"data").unwrap();
    let list = [ek.clone()];
    let mut t = b.blob.clone();
    let last = t.len() - 1;
    t[last] ^= 1;
    assert_eq!(
        open_batch(&t, keys_from_list(&list)).unwrap_err().code(),
        "DECRYPTION_FAILED"
    );
    let mut hdr = b.blob.clone();
    hdr[21] ^= 1;
    assert_eq!(
        open_batch(&hdr, keys_from_list(&list)).unwrap_err().code(),
        "DECRYPTION_FAILED"
    );
    let mut ver = b.blob.clone();
    ver[4] = 9;
    assert_eq!(
        open_batch(&ver, keys_from_list(&list)).unwrap_err().code(),
        "UNSUPPORTED_VERSION"
    );
    assert_eq!(
        open_batch(b"nope", keys_from_list(&list))
            .unwrap_err()
            .code(),
        "MALFORMED_BATCH"
    );
    let wrong = [EpochKey {
        epoch: 4,
        key: vec![0u8; 32],
    }];
    assert_eq!(
        open_batch(&b.blob, keys_from_list(&wrong))
            .unwrap_err()
            .code(),
        "DECRYPTION_FAILED"
    );
    assert_eq!(
        seal_batch(&ek, "bad context", 1, b"x").unwrap_err().code(),
        "INVALID_ARGUMENT"
    );
}
