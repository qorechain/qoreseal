// SPDX-License-Identifier: Apache-2.0
//
// Messages of the chain's KEM key registry (`qorechain.pqc.v1`). Sign the
// transaction that carries them hybrid, with QoreSign `sign_hybrid`.

use qoresign::{parse_address, AnyMessage};

use crate::constants::ALGORITHM_ML_KEM_1024;
use crate::errors::{Error, Result};
use crate::keys::validate_mlkem_public_key;

pub const MSG_REGISTER_KEM_KEY_TYPE_URL: &str = "/qorechain.pqc.v1.MsgRegisterKEMKey";
pub const MSG_REMOVE_KEM_KEY_TYPE_URL: &str = "/qorechain.pqc.v1.MsgRemoveKEMKey";

fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn len_field(field: u64, payload: &[u8], out: &mut Vec<u8>) {
    varint((field << 3) | 2, out);
    varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn sender(address: &str) -> Result<String> {
    parse_address(address)
        .map(|a| a.bech32)
        .map_err(|_| Error::InvalidArgument(format!("invalid account address {address:?}")))
}

/// `MsgRegisterKEMKey { sender, algorithm_id: 2, public_key }`. Registering again replaces the key.
pub fn build_register_kem_key_message(
    sender_address: &str,
    mlkem_public_key: &[u8],
) -> Result<AnyMessage> {
    validate_mlkem_public_key(mlkem_public_key)?;
    let mut value = Vec::with_capacity(1700);
    len_field(1, sender(sender_address)?.as_bytes(), &mut value);
    value.extend_from_slice(&[0x10, ALGORITHM_ML_KEM_1024]);
    len_field(3, mlkem_public_key, &mut value);
    Ok(AnyMessage {
        type_url: MSG_REGISTER_KEM_KEY_TYPE_URL.into(),
        value,
    })
}

/// `MsgRemoveKEMKey { sender }`.
pub fn build_remove_kem_key_message(sender_address: &str) -> Result<AnyMessage> {
    let mut value = Vec::new();
    len_field(1, sender(sender_address)?.as_bytes(), &mut value);
    Ok(AnyMessage {
        type_url: MSG_REMOVE_KEM_KEY_TYPE_URL.into(),
        value,
    })
}

/// Errors of the KEM key registry (codespace `pqc`).
pub const KEM_REGISTRY_ERRORS: [(u32, &str); 5] = [
    (250, "the KEM key registry is not enabled on this chain yet"),
    (251, "invalid KEM public key"),
    (252, "no KEM key published for this account"),
    (253, "this KEM key is already published for this account"),
    (
        254,
        "publishing a KEM key needs a registered post-quantum signature key",
    ),
];

/// Explain a refusal of a registry transaction, or `None` when it is not one.
pub fn describe_kem_registry_error(codespace: &str, code: u32) -> Option<&'static str> {
    if codespace != "pqc" {
        return None;
    }
    KEM_REGISTRY_ERRORS
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, m)| *m)
}
