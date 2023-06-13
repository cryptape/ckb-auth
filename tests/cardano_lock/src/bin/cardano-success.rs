use auth_spawn_rust::*;
use cardano_lock::cardano::*;
use cardano_lock::*;
use cardano_message_signing::{
    cbor::{CBORArray, CBORObject, CBORValue},
    utils::Deserialize,
    utils::{Int, ToBytes},
};
use cardano_serialization_lib::{
    crypto::{Ed25519Signature, PublicKey},
    utils::hash_transaction,
    TransactionBody,
};
use cbor_event::de::Deserializer;
use ckb_mock_tx_types::ReprMockTransaction;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    check_cardano_sign()?;

    let mut tx: ReprMockTransaction = read_tx_template("templates/cardano-success.json")?;
    update_auth_code_hash(&mut tx);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);
    update_args(&mut tx, 0x0b, &ckb_hash::blake2b_256(public_key.as_bytes()));
    update_witness_pubkey(&mut tx, &public_key);

    let witness = load_signature(G_TX_SIGNED_PATH);
    update_witness(&mut tx, vec![witness.clone()]);
    // println!("{:02x?}", tx.tx.witnesses.get(0).unwrap().as_bytes());

    let json = serde_json::to_string_pretty(&tx).unwrap();
    println!("{}", json);
    Ok(())
}

fn update_witness_pubkey(tx: &mut ReprMockTransaction, public_key: &PublicKey) {
    let witness = tx.tx.witnesses.get_mut(G_CKB_TX_INDEX).unwrap();

    let data = witness.as_bytes()[20..].to_vec();
    let mut des_data = Deserializer::from(std::io::Cursor::new(data));
    let root = CBORArray::deserialize(&mut des_data).unwrap();

    let mut root2 = CBORArray::new();
    root2.add(&root.get(0));

    let mut sign_data = CBORObject::new();
    sign_data.insert(
        &CBORValue::new_int(&Int::new_i32(0)),
        &CBORValue::new_bytes(public_key.as_bytes()),
    );
    root2.add(&CBORValue::new_object(&sign_data));
    root2.add(&root.get(1));

    update_witness(tx, vec![root2.to_bytes()]);
}

fn check_cardano_sign() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = load_private_key(G_PRIVATE_KEY_PATH);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);

    assert_eq!(private_key.to_public().as_bytes(), public_key.as_bytes());

    let tx_data = load_signature(G_TX_PATH);
    // println!("len({}) {:02x?}", tx_data.len(), tx_data);

    let tx_body =
        TransactionBody::from_bytes(tx_data[1..].to_vec()).expect("new tx body from bytes");

    // println!("{:02x?}", tx_body.to_bytes());
    let tx_hash = hash_transaction(&tx_body);
    let tx_hash2 = cardano_blake2b_256(&tx_body.to_bytes());
    assert_eq!(tx_hash.to_bytes(), tx_hash2);
    // println!("{:02x?}", tx_hash2);

    let (sign_data, pubkey) = get_signature_struct(G_TX_SIGNED_PATH);
    assert_eq!(public_key.as_bytes(), pubkey);

    // println!("{:02x?}", sign_data);
    // println!("{:02x?}", pubkey);

    let ret = public_key.verify(&tx_hash2, &Ed25519Signature::from_bytes(sign_data).unwrap());
    assert!(ret);

    Ok(())
}
