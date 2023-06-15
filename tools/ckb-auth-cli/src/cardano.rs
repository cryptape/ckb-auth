use super::{BlockChain, BlockChainArgs};
use anyhow::{anyhow, Error};
use ckb_auth_rs::AlgorithmType;
use clap::{arg, ArgMatches, Command};
use hex::decode;

pub struct CardanoLockArgs {}

impl BlockChainArgs for CardanoLockArgs {
    fn block_chain_name(&self) -> &'static str {
        "cardano"
    }

    fn reg_parse_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-x --hex <HEX> "The public key hex"))
    }
    fn reg_generate_args(&self, cmd: Command) -> Command {
        cmd
    }
    fn reg_verify_args(&self, cmd: Command) -> Command {
        cmd.arg(arg!(-p --pubkeyhash <PUBKEYHASH> "The pubkey hash to verify against"))
            .arg(arg!(-s --signature <SIGNATURE> "The signature to verify"))
            .arg(arg!(-m --message <MESSAGE> "The signature message"))
    }

    fn get_block_chain(&self) -> Box<dyn BlockChain> {
        Box::new(CardanoLock {})
    }
}

pub struct CardanoLock {}

impl BlockChain for CardanoLock {
    fn parse(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let pubkey = decode(
            operate_mathches
                .get_one::<String>("hex")
                .expect("get cardano public key"),
        )
        .expect("decode");

        let pubkey_hash = ckb_hash::blake2b_256(&pubkey[2..]);
        println!("{}", hex::encode(&pubkey_hash[0..20]));

        Ok(())
    }

    fn generate(&self, _operate_mathches: &ArgMatches) -> Result<(), Error> {
        Err(anyhow!("cardano does not generate"))
    }

    fn verify(&self, operate_mathches: &ArgMatches) -> Result<(), Error> {
        let pubkey_hash = decode(
            operate_mathches
                .get_one::<String>("pubkeyhash")
                .expect("get cardano pubkey hash"),
        )
        .expect("decode pubkey hash");

        let signature = decode(
            operate_mathches
                .get_one::<String>("signature")
                .expect("get cardano signauthe"),
        )
        .expect("decode signature data");

        let message = decode(
            operate_mathches
                .get_one::<String>("message")
                .expect("get cardano signauthe message"),
        )
        .expect("decode signature message data");

        cardano_verify(&pubkey_hash, &message, &signature)?;

        println!("Signature verification succeeded!");
        Ok(())
    }
}

pub fn cardano_verify(pubkey_hash: &[u8], message: &[u8], sign: &[u8]) -> Result<(), Error> {
    if pubkey_hash.len() != 20 {
        panic!("Cardano public key len is not 20 ({})", pubkey_hash.len());
    }

    if message.len() != 32 {
        panic!("Cardano message len is not 32 ({})", message.len());
    }

    super::auth_script::run_auth_exec(AlgorithmType::Cardano, pubkey_hash, message, sign)
}
