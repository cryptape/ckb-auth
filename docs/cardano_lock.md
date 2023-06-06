# Cardano Lock

## About cardano lock
[Cardano](https://cardano.org/) is a blockchain platform for changemakers, innovators, and visionaries, with the tools and technologies required to create possibility for the many, as well as the few, and bring about positive global change.


## Signature
Signatures are structured using CBOR. In order to ensure compatibility with cadrano-cli and the security of transactions, some modifications have been made to the original structure here:
The transaction hash of the Input is passed into ```generate_sighash_all``` function in ckb-auth as a hash.


### Generate signature
1. Use cardano-cli to generate key.
```bash
./bin/cardano-cli node key-gen \
    --cold-verification-key-file test_data/cold.vkey.json \
    --cold-signing-key-file test_data/cold.skey.json \
    --operational-certificate-issue-counter-file test_data/cold.counter.json
```
2. Use get-sign-hash to generate hash. (tests/cardano_lock/src/bin/get-sign-hash.rs)
3. Generate a tx with cardano and sign
```bash
sign_hash=`./target/debug/get-sign-hash`
.bin/cardano-cli transaction build-raw \
    --shelley-era \
    --tx-in $sign_hash#0 \
    --tx-out addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v+1 \
    --invalid-hereafter 0 \
    --fee 7 \
    --out-file test_data/cardano_tx.json
./bin/cardano-cli transaction sign \
    --tx-body-file test_data/cardano_tx.json \
    --signing-key-file test_data/cold.skey.json \
    --mainnet \
    --out-file test_data/cardano_tx.signed.json
```
4. Pass the whole cborHex in the output json as the witnesses of ckb-auth.

You can refer to the Makefile of cardano-test (tests/cardano_lock/Makefile).

### Elements
* The generated key/tx is a readable JSON file, where cborHex represents the actual CBOR data.
* The Cardano pubkey is directly extracted after generation.
* The Cardano signature message only applies to the critical transaction parts, excluding the metadata. Therefore, here, only the input transaction hash can be used.

### Install cardano-cli
Download from the [official](https://github.com/input-output-hk/cardano-node/releases/tag/8.0.0).
You can use --help to view more related commands. The relevant commands we used can be independent of the cardano-node (Cardano network).
