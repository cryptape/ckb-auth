# ckb-auth-cli
ckb-auth-cli is a command line utillity to faciliate the creation and verification of transaction
with ckb-auth as lock script.

## Get the pub key hash with `generate` sub command.
Given the account we want to sign messages with, we obtain pub key hash like data that will be used later by ckb-auth to
verify the validity of a signature. ckb-auth will verify that the signature is valid and
it is signed by someone with pubkey hashed to this data.

## Get the message to sign with `generate` subcommand.
This step is used to generate the message for the native blockchain clients to sign.
The same message will be used by ckb-auth internally. ckb-auth will check the validity of the
signature in the transaction against this message.

## Sign the message with litecoin-cli
We can now sign the message with native blockchain clients. Depending on the specific blockchains,
each blockchain wallets accept different parameters and output different data. See below for each
blockchains.

## Verify the signature with `verify` subcommand
ckb-auth-cli generate the same transaction and set the signature to the one generated above,
and then it checks the validity of this transaction.

# integrations
##  litecoin
Below uses the sample key in [litecoin docs](./litecoin.md))

### Get the pub key hash with `generate` sub command.
```
cargo run --bin ckb-auth-cli -- -b litecoin parse -a msv9GiUuCGEaoWzu7YcPDJo8hu5ij3Nzjn
```
which outputs
```
88043d56e0079d30927ebf8bb99358d7ddad7ad8
```
### Get the message to sign with `generate` subcommand.
```
cargo run --bin ckb-auth-cli -- -b litecoin generate -a msv9GiUuCGEaoWzu7YcPDJo8hu5ij3Nzjn
```
which outputs
```
8fe9f62674d51f3103a3635433e73b4fcdadf6faa3b0c8392546ca6af161aa12
```
### Sign the message with litecoin-cli
```
litecoin-cli -rpcwallet=ckb-auth-test-wallet -testnet signmessage msv9GiUuCGEaoWzu7YcPDJo8hu5ij3Nzjn 8fe9f62674d51f3103a3635433e73b4fcdadf6faa3b0c8392546ca6af161aa12
```
which outputs
```
ICbd+cH5vWtimef3mJZf0nwbR30Em1zTDQW7WGOJZ1aia2wwUL9DFJdO88P6ChF15mQmirb/525+V9u8BWVZY2E=
```
### Verify the signature with `verify` subcommand
```
cargo run --bin ckb-auth-cli -- -b litecoin verify -s ICbd+cH5vWtimef3mJZf0nwbR30Em1zTDQW7WGOJZ1aia2wwUL9DFJdO88P6ChF15mQmirb/525+V9u8BWVZY2E= --encoding base64 -p 88043d56e0079d30927ebf8bb99358d7ddad7ad8
```
