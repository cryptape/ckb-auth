use auth_spawn_rust::*;
use cardano_lock::cardano::*;
use cardano_lock::*;
use cardano_message_signing::{
    cbor::{CBORArray, CBORValue},
    utils::{Int, ToBytes},
};
use cardano_serialization_lib::{
    crypto::{Ed25519Signature, PrivateKey, PublicKey},
    utils::hash_transaction,
    TransactionBody,
};
use ckb_mock_tx_types::ReprMockTransaction;

const G_PRIVATE_KEY_PATH: &str = "test_data/cold.skey.json";
const G_PUBLIC_KEY_PATH: &str = "test_data/cold.vkey.json";
const G_TX_PATH: &str = "test_data/cardano_tx.json";
const G_TX_SIGNED_PATH: &str = "test_data/cardano_tx.signed.json";

const G_CKB_TX_INDEX: usize = 0;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    check_cardano_sign()?;

    let mut tx: ReprMockTransaction = read_tx_template("templates/cardano-success.json")?;
    update_auth_code_hash(&mut tx);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);
    update_args(&mut tx, 0x0b, &ckb_hash::blake2b_256(public_key.as_bytes()));

    let private_key = load_private_key(G_PRIVATE_KEY_PATH);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);
    let signature = generate_witness(&tx, &private_key, &public_key, false);
    update_witness(&mut tx, vec![signature]);
    // println!("{:02X?}", tx.tx.witnesses.get(0).unwrap().as_bytes());

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

fn generate_witness(
    tx: &ReprMockTransaction,
    private_key: &PrivateKey,
    public_key: &PublicKey,
    output_zero: bool,
) -> Vec<u8> {
    let message = if output_zero {
        [0u8; 32]
    } else {
        generate_sighash_all(tx, G_CKB_TX_INDEX).unwrap()
    };

    let mut root = CBORArray::new();

    let mut sign_data: CBORArray = CBORArray::new();
    sign_data.add(&CBORValue::new_bytes(message.to_vec()));
    sign_data.add(&CBORValue::new_bytes(public_key.as_bytes()));
    root.add(&CBORValue::new_array(&sign_data));

    // custom data
    let mut custom_node = CBORArray::new();
    custom_node.add(&CBORValue::new_int(&Int::new_i32(0x123123)));

    // lock code hash
    custom_node.add(&CBORValue::new_bytes({
        use ckb_types::{
            packed::{Byte, Byte32, ScriptBuilder},
            prelude::*,
        };

        let lock = &tx.mock_info.inputs.get(0).unwrap().output.lock;
        let sc = ScriptBuilder::default()
            .code_hash(Byte32::new(
                lock.code_hash.as_bytes().to_vec().try_into().unwrap(),
            ))
            .args(lock.args.as_bytes().pack())
            .hash_type(Byte::new(lock.hash_type.clone() as u8))
            .build();

        sc.calc_script_hash().as_bytes().to_vec()
    }));

    // input capacity
    custom_node.add(&CBORValue::new_bytes(
        tx.mock_info
            .inputs
            .get(0)
            .unwrap()
            .output
            .capacity
            .value()
            .to_le_bytes()
            .to_vec(),
    ));

    // output cap
    custom_node.add(&CBORValue::new_bytes(
        tx.tx
            .outputs
            .get(0)
            .unwrap()
            .capacity
            .value()
            .to_le_bytes()
            .to_vec(),
    ));
    root.add(&CBORValue::new_array(&custom_node));

    let mut root2 = root.clone();
    root.add(&CBORValue::new_bytes([0u8; 64].to_vec()));
    let sign = if output_zero {
        [0u8; 64].to_vec()
    } else {
        private_key.sign(&root.to_bytes()).to_bytes()
    };
    root2.add(&CBORValue::new_bytes(sign));

    root2.to_bytes()
}
