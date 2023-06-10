# Cardano Lock

## About cardano lock
[Cardano](https://cardano.org/) is a blockchain platform for changemakers, innovators, and visionaries, with the tools and technologies required to create possibility for the many, as well as the few, and bring about positive global change.

## Quick Start

The directory needs to jump to `tests/cardano_lock`

### Install cardano-cli
Download from the [official](https://github.com/input-output-hk/cardano-node/releases/tag/8.0.0).
You can use --help to view more related commands. The relevant commands we used can be independent of the cardano-node (Cardano network).
Also available [here](https://github.com/input-output-hk/cardano-wallet/releases/tag/v2023-04-14)


```bash
# Generate Key
mkdir -p test_data
./bin/cardano-cli node key-gen \
    --cold-verification-key-file test_data/cold.vkey.json \
    --cold-signing-key-file test_data/cold.skey.json \
    --operational-certificate-issue-counter-file test_data/cold.counter.json

# Get public key hash
ckb-auth-cli cardano get-pubkey-hash <Public key>
```
The `test_data/cold.skey.json` is public key
* Note: The first two bytes are CBOR encoded (`5820`), and the latter is the real data.
* Note: The json file is in a fixed format. The data is stored in "cborHex".

```bash
# Signature
message="0011223344556677889900112233445500112233445566778899001122334455"
./bin/cardano-cli transaction build-raw \
    --shelley-era \
    --tx-in $message#0 \
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
The `test_data/cardano_tx.signed.json` is signature.

```bash
# Verify
ckb-auth-cli cardano verify <Public key hash> $message <Sign>
```
* Note: Sign uses all data in *.signed.json 's `cborHex`


## Signature
Signatures are structured using CBOR. In order to ensure compatibility with cadrano-cli and the security of transactions, some modifications have been made to the original structure here:
The transaction hash of the Input is passed into ```generate_sighash_all``` function in ckb-auth as a hash.


Specific signature process:
### 1. Generate key
```bash
./bin/cardano-cli node key-gen \
    --cold-verification-key-file test_data/cold.vkey.json \
    --cold-signing-key-file test_data/cold.skey.json \
    --operational-certificate-issue-counter-file test_data/cold.counter.json
```
The cold.skey.json is for signature. And The cold.vkey.json is for verify.
```cborHex``` in key.json stores the generated key, the binary is stored in the form of [CBOR](https://tools.ietf.org/html/rfc7049), and the actual key data is 2 to 34 bytes. (The following tx/signed are all in a similar format)


### 2. Generate Tx
```bash
sign_hash=`./target/debug/get-sign-hash`
.bin/cardano-cli transaction build-raw \
    --shelley-era \
    --tx-in $sign_hash#0 \
    --tx-out addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v+1 \
    --invalid-hereafter 0 \
    --fee 7 \
    --out-file test_data/cardano_tx.json
```
Because Cardano's transaction information does not have a position similar to the sign-hash in CKB, and Cardano-cli verifies the transaction structure. Therefore, here we use the input's tx to store the sign-hash for signing. In CKB transactions, a unique hash is generated through sign-hash, and the data parameter is signed, so there shouldn't be significant security issues.

### 3. Sign
```bash
./bin/cardano-cli transaction sign \
    --tx-body-file test_data/cardano_tx.json \
    --signing-key-file test_data/cold.skey.json \
    --mainnet \
    --out-file test_data/cardano_tx.signed.json
```
We sign directly with cardano-cli. You can see from the command that the previously generated private key is used and finally output to test_data/cardano_tx.signed.json.
When signing in Cardano, the first part of the transaction is hashed using Blake2b 256, and the resulting output is used as the message for signing. (You can use the following command to get. )
```bash
bin/cardano-cli transaction  txid  --tx-body-file test_data/cardano_tx.json
```
Finally, it will be signed by ed25519.

### 4. Build the transaction of auth-demo
Get pubkey from cold.skey.json and witness from cardano_tx.signed.json. Same as ckb elsewhere.

### 5. ckb-auth verify
First, extract the sign, pubkey, and message from the witness. The witness directly utilizes the signing result from cardano-cli, with data stored in CBOR format.
Among these, the first map stores transaction information, the second map stores pubkey and sign, and the third one stores metadata (which is empty in this case). Here, we retrieve the message from the transaction information and obtain pubkey and sign from the second map.
```bash
# You can use these two commands to parse transaction information and cbor structure
bin/cardano-cli transaction view --tx-body-file test_data/cardano_tx.signed.json
bin/cardano-cli text-view decode-cbor  --in-file test_data/cardano_tx.signed.json
```
Afterwards, we will compare the message to see if it matches the one generated by the auth-demo script. And finally, we will perform ```ed25519_verify``` and compare the public key hash.


### Script and testcase
The above-mentioned matters have all been included in the test cases. If you wish to understand the specific situation, you can refer to this file: ```tests/cardano_lock/Makefile``` and ```tests/cardano_lock/src/bin/gen_cardano_signature.sh```.
