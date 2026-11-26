<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fuzz targets

Fuzz targets for the attacker-controlled parsing surfaces. Run with
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) on a nightly toolchain:

```sh
cargo +nightly fuzz run fuzz_decide_req
cargo +nightly fuzz run fuzz_entity_graph
```

| Target | What it exercises |
|---|---|
| `fuzz_decide_req` | The AuthZEN evaluation request shape: the JSON an attacker sends to `POST /access/v1/evaluation`. |
| `fuzz_entity_graph` | The authority graph parser (`Directory::parse`, `validate`, `ancestors_of`, `revoked`, `descendants_of`): attacker-controlled entity JSON. |

Every path must resolve to a result or a refusal, never a panic.
