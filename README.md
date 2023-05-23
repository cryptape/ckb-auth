# ckb-auth
A consolidated library featuring numerous blockchains authentication techniques
on CKB-VM. More details in [auth.md](./docs/auth.md). We also write a [simple
script](./examples/auth-demo/auth_demo.c) to demonstrate how to use this
library.

## Build

``` bash
make all-via-docker
```
For more details, please check out [CI script](./.github/workflows/rust.yml).

## Test

```bash
cd tests/auth_rust && bash run.sh
```

## Test with Spawn
Before running test cases with spawn support, please install ckb-debugger for next hardfork:
```bash
cargo install --locked --branch ckb2023 --git https://github.com/nervosnetwork/ckb-standalone-debugger ckb-debugger
```
Then run:

```bash
cd tests/auth_spawn_rust && make all
```

## Integration
If you want to integrate `ckb-auth` into real world projects, we have some tutorials:
- [litecoin](./docs/litecoin.md)
