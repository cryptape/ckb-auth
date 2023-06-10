use auth_lock_test::AlgorithmType;

pub fn cardano_verify(pubkey_hash: &[u8], message: &[u8], sign: &[u8]) {
    if pubkey_hash.len() != 20 {
        panic!("Cardano public key len is not 20 ({})", pubkey_hash.len());
    }

    if message.len() != 32 {
        panic!("Cardano message len is not 32 ({})", message.len());
    }

    super::auth_script::run_auth_exec(AlgorithmType::Cardano, pubkey_hash, message, sign);
}
