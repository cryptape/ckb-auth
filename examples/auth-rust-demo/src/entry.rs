extern crate alloc;
use log::info;
// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
// use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use crate::error::Error;

use rust_ckb_auth::ckb_auth::{
    ckb_auth, AuthAlgorithmIdType, CkbAuthType, CkbEntryType, EntryCategoryType,
};

use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, core::ScriptHashType, prelude::*},
    high_level::{load_script, load_witness_args},
};
use rust_ckb_auth::generate_sighash_all::generate_sighash_all;

// use ckb_std::debug;

pub fn main() -> Result<(), Error> {
    info!("auth-script-test entry");
    let mut pubkey_hash = [0u8; 20];
    let auth_id: u8;
    let entry_type: u8;
    let hash_type: ScriptHashType;
    let mut code_hash = [0u8; 32];

    // get message
    let message = generate_sighash_all().map_err(|_| Error::GeneratedMsgError)?;
    let signature = {
        info!("run as standalone script");

        let script = load_script()?;
        let args: Bytes = script.args().unpack();
        if args.len() != 55 {
            return Err(Error::ArgsError);
        }
        auth_id = args[0] as u8;
        pubkey_hash.copy_from_slice(&args[1..21]);
        code_hash.copy_from_slice(&args[21..53]);
        hash_type = match args[53] as u8 {
            0 => ScriptHashType::Data,
            1 => ScriptHashType::Type,
            2 => ScriptHashType::Data1,
            _ => {
                return Err(Error::ArgsError);
            }
        };
        entry_type = args[54] as u8;

        let witness_args =
            load_witness_args(0, Source::GroupInput).map_err(|_| Error::WitnessError)?;
        witness_args.as_slice()[20..].to_vec()
    };

    let id = CkbAuthType {
        algorithm_id: AuthAlgorithmIdType::try_from(auth_id)?,
        pubkey_hash: pubkey_hash,
    };

    let entry = CkbEntryType {
        code_hash,
        hash_type,
        entry_category: EntryCategoryType::try_from(entry_type).unwrap(),
    };

    ckb_auth(&entry, &id, &signature, &message)?;

    Ok(())
}
