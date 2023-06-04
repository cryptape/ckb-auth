use auth_spawn_rust::*;
use cardano_lock::cardano::*;
use cardano_lock::*;
use ckb_mock_tx_types::ReprMockTransaction;
use ckb_types::packed::Byte32;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut tx: ReprMockTransaction = read_tx_template("templates/cardano-success.json")?;
    update_auth_code_hash(&mut tx);
    let public_key = load_public_key(G_PUBLIC_KEY_PATH);
    update_args(&mut tx, 0x0b, &ckb_hash::blake2b_256(public_key.as_bytes()));

    let hash = Byte32::new(generate_sighash_all(&tx, G_CKB_TX_INDEX).unwrap());

    let output_str = format!("{:#x}", hash);
    println!("{}", &output_str[2..]);

    Ok(())
}
