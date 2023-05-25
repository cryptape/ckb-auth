CKB_DEBUGGER ?= ckb-debugger

MOLC := moleculec
MOLC_VERSION := 0.7.0

CARDANO_LOCK_TOOLS_URL=https://update-cardano-mainnet.iohk.io/cardano-node-releases/cardano-node-8.0.0-linux.tar.gz
#For Mac use the link below
#CARDANO_LOCK_TOOLS_URL=https://update-cardano-mainnet.iohk.io/cardano-node-releases/cardano-node-8.0.0-macos.tar.gz

all: \
	cardano-success

mol:
	rm -f src/blockchain.rs
	rm -f src/cardano_lock_mol.rs
	make src/blockchain.rs
	make src/cardano_lock_mol.rs

src/cardano_lock_mol.rs: ../../c/cardano_lock.mol
	${MOLC} --language rust --schema-file $< | rustfmt > $@

src/blockchain.rs: ../../c/blockchain.mol
	${MOLC} --language rust --schema-file $< | rustfmt > $@

gen_cardano_signature:
	mkdir -p test_data
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

cardano-success: gen_cardano_signature
	cargo run --bin cardano-success > tx.json
	${CKB_DEBUGGER} --tx-file=tx.json -s lock

install:
	cargo install --locked --branch ckb2023 --git https://github.com/nervosnetwork/ckb-standalone-debugger ckb-debugger

install_cardano_tools:
	mkdir -p bin
	cd bin && wget ${CARDANO_LOCK_TOOLS_URL} && tar -xf `basename -- $(CARDANO_LOCK_TOOLS_URL)`
