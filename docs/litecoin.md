# ckb-auth litecoin interoperability

Ckb-auth library is able to verify a lot of blockchain signatures including the litecoin.
We can use `litecoin-cli` (or other compatible wallet) to generate valid signatures and validate them on-chain with ckb-auth.

A simple way to use litecoin signature algorithm to lock ckb cells
is to sign the transaction hash (or maybe `sighash_all`, i.e. hashing all fields 
including transaction hash and other witnesses in this input group)
with `litecoin-cli`, and then leverage ckb-auth to check the validity of this signature.
See [the docs](./auth.md) for more details.

# Signing a transaction with litecoin-cli

## Downloading the litecoin binaries
The commands below download the official `litecoin` binaries (e.g. `litecoind` for litecoin daemon,
`litecoin-cli` for litecoin command line client) into the directory `/usr/local`.

```bash
tarball=litecoin.tar.gz
wget -O "$tarball" https://download.litecoin.org/litecoin-0.21.2.2/linux/litecoin-0.21.2.2-x86_64-linux-gnu.tar.gz
tar xvzf "$tarball"
sudo cp -r litecoin-*/* /usr/local
```

## Starting the litecoin daemon
Litecoin daemon is required in order to for litecoin-cli to work. For example,
to work with Litecoin in a test environment, you need to start a Litecoin testnet node.
You can do this using the `litecoind` command with the `-testnet` option. Here's how:
```bash
litecoind -testnet -daemon
```

## Creating a new account or use the existing litecoin account
To sign a message, you will need to create a litecoin wallet
(for illustration, we use wallet `ckb-auth-test-wallet` below)
and a litecoin account (for illustration, we use account with
private key `cQoJiU5ECnVpRqfV5dWKDE2sLQq6516Tja1Hb1GABUV24n7WkqV4` below) to sign messages.

If you already have a wallet, load the wallet `ckb-auth-test-wallet` with
`litecoin-cli -testnet loadwallet ckb-auth-test-wallet` and skip this step.

To create a wallet named `ckb-auth-test-wallet`, import private key
`cQoJiU5ECnVpRqfV5dWKDE2sLQq6516Tja1Hb1GABUV24n7WkqV4` into this wallet and 
label this account with `ckb-auth-test-privkey`, we can run
```bash
litecoin-cli -testnet createwallet ckb-auth-test-wallet
litecoin-cli -rpcwallet=ckb-auth-test-wallet -testnet importprivkey cQoJiU5ECnVpRqfV5dWKDE2sLQq6516Tja1Hb1GABUV24n7WkqV4 ckb-auth-test-privkey false
```

## Obtaining the litecoin address to sign data
Due to the deprecation of [old address format (p2pkh address)](https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses) ([upstream bitcoin switched to Hierarchical Deterministic (HD) Wallet](https://river.com/learn/terms/h/hd-wallet)),
we need to obtain the legacy p2pkh address of the litecoin account to sign messages.

The easiest way to do such thing is to label the account (say with `ckb-auth-test-privkey`) 
and dump all its address, we can run 
```
litecoin-cli -rpcwallet=ckb-auth-test-wallet -testnet getaddressesbylabel ckb-auth-test-privkey
```
Here's the output when I run that script:
```json
{
  "mhknqLHQGWDXuLsPdzab8nA4jD3fMdVYS2": {
    "purpose": "receive"
  },
  "myGi4qfsqJ8kzgLEJLfdqr75PQQFyH2DSf": {
    "purpose": "receive"
  },
  "QjpdvL4h5jnfaj1uV5ifJNUAYZTTbjgFH5": {
    "purpose": "receive"
  },
  "tltc1qp4t37xntgjw43lsuc3xr40hg2akne6j6twy3xn": {
    "purpose": "receive"
  },
  "tltc1qrz8z67vtu38pq2yzqtq7unftmsaueq6a8da5n2": {
    "purpose": "receive"
  },
  "tltc1qyth2j9ar6gzkuhuu7qytl9x8q2ud5p7fjts2vy": {
    "purpose": "receive"
  },
  "tltc1qjadecaemcwpk8ytjclns56vq2kurd7f3j3dcx7": {
    "purpose": "receive"
  },
  "tmweb1qqd6usenz75lvym9px3q7gakhy4a3u4ne95rwg4h3w2shm7hva28wsqemjfm7c2v7gt5sl5snf9kr6tygl3t773l6spt4cmuel4d92m038gtejwnn": {
    "purpose": "receive"
  }
}
```

The legacy p2pkh addresses are normally with short length (see [How is a Litecoin address generated?](https://bitcoin.stackexchange.com/questions/65282/how-is-a-litecoin-address-generated) and [address format - litecoin constants and prefixes](https://bitcoin.stackexchange.com/questions/62781/litecoin-constants-and-prefixes) for details).
As an rule of thumb, we can use the addresses started with m or n in litecoin testnet and addresses started with L for litecoin mainnet.
For example, here both the short addresses `mhknqLHQGWDXuLsPdzab8nA4jD3fMdVYS2` and `myGi4qfsqJ8kzgLEJLfdqr75PQQFyH2DSf` may
be used to sign message, while another short address `QjpdvL4h5jnfaj1uV5ifJNUAYZTTbjgFH5` does not work.

If the account is not labelled, you may run `litecoin-cli -testnet listreceivedbyaddress 1 true`
to dump all addresses and find out the desired legacy address from there.

## Obtaining public key hash needed by ckb-auth
To obtain public key hash of address `mhknqLHQGWDXuLsPdzab8nA4jD3fMdVYS2`, we need to decode it with
base58 and then take the [1, 21) bytes of the resulting binary data (i.e. dropping the first byte, and
take the following 20 bytes of data). You may [decode it online](http://lenschulwitz.com/base58) or run
the command `base58 -d <<< mhknqLHQGWDXuLsPdzab8nA4jD3fMdVYS2 | xxd -s 1 -l 20 -p` 
([keis/base58](https://github.com/keis/base58) and [xxd(1)](https://linux.die.net/man/1/xxd)required).

## Signing a message with litecoin-cli
To sign the message `29553f9e37fa16e45f1d3e616ac5366f6afd9936477f2d6fc870f49bdf540157`, we can run
```bash
litecoin-cli -rpcwallet=ckb-auth-test-wallet -testnet signmessage mhknqLHQGWDXuLsPdzab8nA4jD3fMdVYS2 29553f9e37fa16e45f1d3e616ac5366f6afd9936477f2d6fc870f49bdf540157
```
whose output `H2gWHSzffPkvD2QYD9jdLTuM5x7cax4E7Ax0Nm79T90wLU0LcK/DEYENggsC5G4FK/69qJP9eXp9zHkZ40PH6ME=` is the base64-encoded form of the signature. The binary form can be fed to ckb-auth for authentication.

