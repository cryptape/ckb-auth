pub mod cardano;

use ckb_jsonrpc_types::JsonBytes;
use ckb_mock_tx_types::ReprMockTransaction;

pub fn update_args(tx: &mut ReprMockTransaction, auth_id: u8, pub_key_hash: &[u8]) {
    let inputs = &mut tx.mock_info.inputs;

    let mut args = Vec::<u8>::with_capacity(21);
    args.resize(21, 0);
    args[0] = auth_id;
    args[1..].copy_from_slice(&pub_key_hash[0..20]);

    for i in inputs {
        let mut data = i.output.lock.args.as_bytes().to_vec();
        data[0..21].copy_from_slice(&args);
        i.output.lock.args = JsonBytes::from_vec(data);
    }
}
