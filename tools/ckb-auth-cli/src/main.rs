mod auth_script;
mod cardano;

use clap::{arg, Command};
use hex::decode;

fn cli() -> Command {
    Command::new("ckb-auth-cli")
        .about("ckb auth client")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("cardano")
                .about("Cardano Lock")
                .subcommand(
                    Command::new("get-pubkey-hash")
                        .arg(arg!([PUBKEY]))
                        .arg_required_else_help(true),
                )
                .subcommand(
                    Command::new("verify")
                        .arg(arg!([PUBKEY]))
                        .arg(arg!([MESSAGE]))
                        .arg(arg!([SIGN]))
                        .arg_required_else_help(true),
                )
                .arg_required_else_help(true),
        )
}

fn print_pubkey_hash(pubkey: &[u8]) {
    let pubkey_hash = ckb_hash::blake2b_256(pubkey);
    println!("pubkey hash: {}", hex::encode(&pubkey_hash[0..20]));
}

fn main() {
    let matches = cli().get_matches();

    let sub_cmd = matches.subcommand();

    match sub_cmd {
        Some(("cardano", sub_matches)) => {
            let sub_command = sub_matches.subcommand();
            match sub_command {
                Some(("get-pubkey-hash", sub_matches)) => {
                    let pubkey = decode(
                        sub_matches
                            .get_one::<String>("PUBKEY")
                            .expect("Get pubkey hash"),
                    )
                    .expect("decode pubkey hash");

                    print_pubkey_hash(&pubkey);
                }
                Some(("verify", sub_matches)) => {
                    let pubkey = decode(
                        sub_matches
                            .get_one::<String>("PUBKEY")
                            .expect("Get pubkey hash"),
                    )
                    .expect("decode pubkey hash");

                    let message = decode(
                        sub_matches
                            .get_one::<String>("MESSAGE")
                            .expect("Get Message"),
                    )
                    .expect("decode message");

                    let sign = decode(sub_matches.get_one::<String>("SIGN").expect("Get sign"))
                        .expect("decode sign");
                    cardano::cardano_verify(&pubkey, &message, &sign);
                }
                _ => {
                    panic!("unsupport cardano subcommand")
                }
            }
        }
        _ => {
            panic!("unsupport subcommand")
        }
    }
}
