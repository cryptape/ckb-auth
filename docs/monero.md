# ckb-auth monero interoperability

Ckb-auth library is able to verify a lot of blockchain signatures including the monero.
We can use `monero-wallet-cli` (or other compatible wallet) to generate valid signatures and validate them on-chain with ckb-auth.

A simple way to use monero signature algorithm to lock ckb cells
is to sign the transaction hash (or maybe `sighash_all`, i.e. hashing all fields 
including transaction hash and other witnesses in this input group)
with `monero-wallet-cli`, and then leverage ckb-auth to check the validity of this signature.
See [the docs](./auth.md) for more details.

# Signing a transaction with monero-wallet-cli
## Downloading the monero binaries
The commands below download the official `monero` binaries (e.g. `monerod` for monero daemon,
`monero-wallet-cli` for monero command line client) into the directory `/usr/local`.

```
tarball=monero-wallet-cli.tar.gz
wget -O "$tarball" https://downloads.getmonero.org/cli/monero-linux-x64-v0.18.2.2.tar.bz2
tar xvaf "$tarball"
sudo cp -r monero-*/* /usr/local/
```

## Setting up a monero wallet
### Creating a new wallet
You will need to create a new wallet to sign transactions with `monero-wallet-cli`.

One option is to generate a all-new wallet by running
```
monero-wallet-cli --offline --generate-new-wallet ckb-auth-test-wallet
```

Just follow the instructions to create a new wallet.

### Importing private keys into wallet file
To import an account with address `41eBLjYsK28CJD5z2b7FojMCDg6vERASShVZqAvnsC9LhS7saG8CmMo5Rm92wgnT8wa6nJVu57MHHjmnoyvTpCG7NQ7dErc` into a wallet named `ckb-auth-test-wallet` non-interactively, we can first create a file which is to be used as the stdin of a following `monero-wallet-cli`.
```
cat <<EOF >commands
41eBLjYsK28CJD5z2b7FojMCDg6vERASShVZqAvnsC9LhS7saG8CmMo5Rm92wgnT8wa6nJVu57MHHjmnoyvTpCG7NQ7dErc
8ef26aced8b5f8e1e8ce63b6c75ac6ee41424242424242424242424242424202
972874ae95f5c167285858141e940847398f9c246c7913c0d396b6d73b484105
pw
pw
0
N

EOF
```

Here `8ef26aced8b5f8e1e8ce63b6c75ac6ee41424242424242424242424242424202` and `972874ae95f5c167285858141e940847398f9c246c7913c0d396b6d73b484105` are respectively the spend private key and view private key of this account.

We can then run the following command to import this account.
```
monero-wallet-cli --offline --generate-from-keys ckb-auth-test-wallet < commands
```

## Obtaining address information

See also [Creating a wallet in non-interactive mode using monero-wallet-cli? - Monero Stack Exchange](https://monero.stackexchange.com/questions/10385/creating-a-wallet-in-non-interactive-mode-using-monero-wallet-cli).

Running `monero-wallet-cli --wallet-file ckb-auth-test-wallet --password pw --offline` to enter the interactive mode of
monero command line wallet.

```
[wallet 41eBLj (no daemon)]: viewkey
Wallet password:
secret: 972874ae95f5c167285858141e940847398f9c246c7913c0d396b6d73b484105
public: bbcb8c902571ae1a777f7f07a023ecc5e3d83ba624d4b0ffb7eff79e8b5d10bd
[wallet 41eBLj (no daemon)]: spendkey
Wallet password:
secret: 8ef26aced8b5f8e1e8ce63b6c75ac6ee41424242424242424242424242424202
public: 007caf7a553a894389dd562115b17e78ba84a5c7692677f216c54385dc5c6ff1
[wallet 41eBLj (no daemon)]: address
0  41eBLjYsK28CJD5z2b7FojMCDg6vERASShVZqAvnsC9LhS7saG8CmMo5Rm92wgnT8wa6nJVu57MHHjmnoyvTpCG7NQ7dErc  Primary address
```

## Getting the pubkey hash
There is a flag `mode` for `monero-wallet-cli` to toggle whether to use spend key or view key to sign a message.
The only valid values for `mode` are 0 and 1. 0 (default or set by passing parameter `--spend` to the rpc `sign`)
represents that we used spend key to sign the message,
while 1 (set by passing parameter `--view` to the rpc `sign`) represents that we used view key to sign the message.

Currently, ckb-auth uses mode, spend public key, view public key to compute pubkey hash of monero account.
To be more specific,

```
pubkey_hash = blake2b_256(mode || pub_spend_key || pub_view_key)
```

For example if the account we are using to sign messages is as above, i.e. it has
public spend key `007caf7a553a894389dd562115b17e78ba84a5c7692677f216c54385dc5c6ff1` and
public view key `bbcb8c902571ae1a777f7f07a023ecc5e3d83ba624d4b0ffb7eff79e8b5d10bd`.
Then the pubkey hash `a55ec8bb5b93aaffefd754996cb097228839aad6` is just the blake2b 256 hash of `00007caf7a553a894389dd562115b17e78ba84a5c7692677f216c54385dc5c6ff1bbcb8c902571ae1a777f7f07a023ecc5e3d83ba624d4b0ffb7eff79e8b5d10bd`.

## Signing message helloworld
### Creating message file
In order for `monero-wallet-cli` to sign a message, we need first create a message file.
Normally the message the binary representation of a hash, we can create such binary file easily with

```
printf '%b' $(printf 4242424242424242424242424242424242424242424242424242424242424242 | fold -b2 | sed 's#^#\\x#') > message
```
Here `message` is a binary file with 32 repeated bytes of `0x42`. Change the command to suit your needs.

### Signing the message
We can sign a message by running
```
monero-wallet-cli --wallet-file ckb-auth-test-wallet --password pw sign message
```

Below is a sample output of the above command.

```
This is the command line monero wallet. It needs to connect to a monero
daemon to work correctly.
WARNING: Do not reuse your Monero keys on another fork, UNLESS this fork has key reuse mitigations built in. Doing so will harm your privacy.

Monero 'Fluorine Fermi' (v0.18.1.2-unknown)
Logging to monero-wallet-cli.log
Opened wallet: 41eBLjYsK28CJD5z2b7FojMCDg6vERASShVZqAvnsC9LhS7saG8CmMo5Rm92wgnT8wa6nJVu57MHHjmnoyvTpCG7NQ7dErc
**********************************************************************
Use the "help" command to see a simplified list of available commands.
Use "help all" to see the list of all available commands.
Use "help <command>" to see a command's documentation.
**********************************************************************
SigV2DXdetxj9qiRe6PHsch9EwZVutb1FFR38ubNuM9ef8YPYcnjAisLWo4sLZMoT3g4Z48VRD3xAUsk1EcfthWcxnayW
```

Stripping the prefix `SigV2` of `SigV2DXdetxj9qiRe6PHsch9EwZVutb1FFR38ubNuM9ef8YPYcnjAisLWo4sLZMoT3g4Z48VRD3xAUsk1EcfthWcxnayW`,
we get the base58 representation of the signature. Note that monero's implementation of base58 is different from bitcoin's.
See [monero-rs/base58-monero](https://github.com/monero-rs/base58-monero) for how to manipulate monero base58 data programatically.
