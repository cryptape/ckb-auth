cargo build

sign_hash=`./target/debug/get-sign-hash`

./bin/cardano-cli transaction build-raw \
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