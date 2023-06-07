CKB_DEBUGGER ?= ckb-debugger

all: \
	auth-spawn-success \
	auth-spawn-rust-success

auth-spawn-success:
	cargo run --bin auth-spawn-success > tx.json
	${CKB_DEBUGGER} --tx-file=tx.json -s lock

auth-spawn-rust-success:
	cargo run --bin auth-spawn-rust-success > tx.json
	${CKB_DEBUGGER} --tx-file=tx.json -s lock

install:
	cargo install --locked --branch ckb2023 --git https://github.com/nervosnetwork/ckb-standalone-debugger ckb-debugger
