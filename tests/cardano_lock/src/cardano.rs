use blake2b_rs::Blake2bBuilder;
use cardano_message_signing::{
    cbor::{CBORArray, CBORValue},
    utils::{Deserialize, Int},
};
use cardano_serialization_lib::crypto::{PrivateKey, PublicKey};
use cbor_event::de::Deserializer;
use ckb_types::{bytes::Bytes, core::ScriptHashType};
use lazy_static::lazy_static;
use molecule::prelude::*;

lazy_static! {
    pub static ref AUTH_DL: Bytes = Bytes::from(&include_bytes!("../../../build/auth")[..]);
    pub static ref AUTH_DL_HASH_TYPE: ScriptHashType = ScriptHashType::Data1;
}

pub fn load_file(path: &str) -> Vec<u8> {
    let data = std::fs::read(path).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&data).unwrap();

    let mut raw_data = v.get("cborHex").unwrap().to_string();
    if raw_data.as_bytes()[0] == '\"' as u8 {
        raw_data = String::from(&raw_data[1..raw_data.len() - 1]);
    }

    hex::decode(&raw_data).unwrap()
}

pub fn load_private_key(path: &str) -> PrivateKey {
    let key = load_file(path);
    if key[0] != 0x58 || key[1] != 0x20 {
        panic!("Private key is invalid, data: {:02X?}, path: {}", key, path);
    }
    if key.len() != 32 + 2 {
        panic!("Load key failed, len is not 32, {:02X?}", key);
    }

    PrivateKey::from_normal_bytes(&key[2..]).unwrap()
}

pub fn load_public_key(path: &str) -> PublicKey {
    let key = load_file(path);
    if key[0] != 0x58 || key[1] != 0x20 {
        panic!("Private key is invalid, data: {:02X?}, path: {}", key, path);
    }
    if key.len() != 32 + 2 {
        panic!("Load key failed, len is not 32, {:02X?}", key);
    }

    PublicKey::from_bytes(&key[2..]).unwrap()
}

pub fn load_signature_file(path: &str) -> Vec<u8> {
    let data = std::fs::read(path).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&data).unwrap();

    let mut data = v.get("cborHex").unwrap().to_string();

    if data.as_bytes()[0] == '\"' as u8 {
        data = String::from(&data[1..data.len() - 1]);
    }

    hex::decode(data).unwrap()
}

pub fn load_signature(path: &str) -> Vec<u8> {
    let data = load_file(path);

    data
}

pub fn get_signature_struct(path: &str) -> (Vec<u8>, Vec<u8>) {
    let data = load_file(path);

    let mut des_data = Deserializer::from(std::io::Cursor::new(data));
    let root = CBORArray::deserialize(&mut des_data).unwrap();

    let sign_buf = root
        .get(1)
        .as_object()
        .unwrap()
        .get(&CBORValue::new_int(&Int::new_i32(0)))
        .unwrap()
        .as_array()
        .unwrap()
        .get(0)
        .as_array()
        .unwrap()
        .get(1)
        .as_bytes()
        .unwrap();

    let data = load_file(path);

    let mut des_data = Deserializer::from(std::io::Cursor::new(data));
    let root = CBORArray::deserialize(&mut des_data).unwrap();

    let pubkey_buf = root
        .get(1)
        .as_object()
        .unwrap()
        .get(&CBORValue::new_int(&Int::new_i32(0)))
        .unwrap()
        .as_array()
        .unwrap()
        .get(0)
        .as_array()
        .unwrap()
        .get(0)
        .as_bytes()
        .unwrap();

    (sign_buf, pubkey_buf)
}

pub fn cardano_blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut ctx = Blake2bBuilder::new(32).build();

    ctx.update(data);
    let mut r = [0u8; 32];
    ctx.finalize(&mut r);
    r
}
