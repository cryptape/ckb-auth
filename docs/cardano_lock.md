# Cardano Lock

## About cardano lock
[Cardano](https://cardano.org/) is a blockchain platform for changemakers, innovators, and visionaries, with the tools and technologies required to create possibility for the many, as well as the few, and bring about positive global change.


## Signature
When signing, refer to some designs of [CIP-8](https://cips.cardano.org/cips/cip8/).
The signature struct uses CBOR, This makes it easier for users to view signature information.

Struct:
```text
83      # Root array, size is 3
    82      # Store the necessary signature information
        58 20   # From generate_sighash_all 32 bytes
            xxxxxxx
        58 20   # Public key, 32 bytes
            xxxxxxx
    xx      # custom data
        xxxxxx
    58 40   # Signature data 64 bytes
        xxxxxxx
```



## Test
Test with official tools, but the tx hash is used as the signed data when constructing the witness of the transaction. Therefore, it is only used as an indirect comparison.

First generate the key, transaction data, and sign the transaction.
```bash
./bin/cardano-cli node key-gen \
    --cold-verification-key-file test_data/cold.vkey.json \
    --cold-signing-key-file test_data/cold.skey.json \
    --operational-certificate-issue-counter-file test_data/cold.counter.json
./bin/cardano-cli transaction build-raw \
    --shelley-era \
    --tx-in 1100000000000000000000000000000000000000000000000000000000000000#0 \
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
* ```cold.skey.json``` is private key
* ```cold.vkey.json``` is public key
* ```cardano_tx.json``` is transaction data
* ```cardano_tx.signed.json``` is signatured

Then, use the public key in cardano-success to verify the data.
Verify uses the same library(cardano_serialization_lib) as the signature data witness into the script, so that it can be indirectly verified to be compatible with the official.


