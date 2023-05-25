use auth_spawn_rust::*;
use cardano_lock::cardano::*;
use cardano_lock::*;

use cardano_serialization_lib::{
    crypto::Ed25519Signature, utils::hash_transaction, TransactionBody,
};

const G_PRIVATE_KEY_PATH: &str = "test_data/cold.skey.json";
const G_PUBLIC_KEY_PATH: &str = "test_data/cold.vkey.json";
const G_TX_PATH: &str = "test_data/cardano_tx.json";
const G_TX_SIGNED_PATH: &str = "test_data/cardano_tx.signed.json";

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    check_cardano_sign()?;

    let mut tx = read_tx_template("templates/cardano-success.json")?;
    update_auth_code_hash(&mut tx);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);
    update_args(&mut tx, 0x0b, &ckb_hash::blake2b_256(public_key.as_bytes()));

    let private_key = load_private_key(G_PRIVATE_KEY_PATH);

    let message = generate_sighash_all(&tx, 0)?;
    let signature = cardano_sign(&private_key, &message);
    update_witness(&mut tx, vec![signature]);

    let json = serde_json::to_string_pretty(&tx).unwrap();
    println!("{}", json);
    Ok(())
}

fn check_cardano_sign() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = load_private_key(G_PRIVATE_KEY_PATH);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);

    assert_eq!(private_key.to_public().as_bytes(), public_key.as_bytes());

    let tx_data = load_signature(G_TX_PATH);

    let tx_body = TransactionBody::from_bytes(tx_data[1..tx_data.len() - 2].to_vec())
        .expect("new tx body from bytes");

    let tx_hash = hash_transaction(&tx_body);
    let tx_hash2 = cardano_blake2b_256(&tx_body.to_bytes());
    assert_eq!(tx_hash.to_bytes(), tx_hash2);

    let (sign_data, pubkey) = get_signature_struct(G_TX_SIGNED_PATH);
    assert_eq!(public_key.as_bytes(), pubkey);

    let ret = public_key.verify(&tx_hash2, &Ed25519Signature::from_bytes(sign_data).unwrap());
    assert!(ret);

    Ok(())
}
