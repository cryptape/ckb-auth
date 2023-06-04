CKB_DEBUGGER ?= ckb-debugger

MOLC := moleculec
MOLC_VERSION := 0.7.0

CARDANO_LOCK_TOOLS_URL=https://update-cardano-mainnet.iohk.io/cardano-node-releases/cardano-node-8.0.0-linux.tar.gz
#For Mac use the link below
#CARDANO_LOCK_TOOLS_URL=https://update-cardano-mainnet.iohk.io/cardano-node-releases/cardano-node-8.0.0-macos.tar.gz

all: \
	gen_cardano_key \
	cardano-success

gen_cardano_key:
	mkdir -p test_data
	./bin/cardano-cli node key-gen \
		--cold-verification-key-file test_data/cold.vkey.json \
		--cold-signing-key-file test_data/cold.skey.json \
		--operational-certificate-issue-counter-file test_data/cold.counter.json

gen_cardano_signature:
	./src/gen_cardano_signature.sh

cardano-success: gen_cardano_signature
	cargo run --bin cardano-success > tx.json
	${CKB_DEBUGGER} --tx-file=tx.json -s lock

install:
	cargo install --locked --branch ckb2023 --git https://github.com/nervosnetwork/ckb-standalone-debugger ckb-debugger

install_cardano_tools:
	mkdir -p bin
	cd bin && wget ${CARDANO_LOCK_TOOLS_URL} && tar -xf `basename -- $(CARDANO_LOCK_TOOLS_URL)`

clean:
	rm -rf test_data/*
	cargo clean
