<!-- SPDX-License-Identifier: Apache-2.0 -->
# decern — agent & contributor guide

decern is a deterministic authorization kernel: its safety properties are machine-checked
over the whole input space, and every decision lands in a tamper-evident ledger. The
guarantees are the product — a change that weakens one is a regression, even if it compiles.

## Layout
- 7 library crates, plus `decern-cli` (binary `decern`: `prove` / `decide` / `verify`) and
  `decern-server` (binary `decern-serve`: a thin, AuthZEN-shaped, fail-closed PDP).
  See [ARCHITECTURE.md](ARCHITECTURE.md) for the crate map and where each contribution area lives.
- `crates/decern-kernel/model/` — the Cedar policy, schema, and entities the kernel loads.
- `.agent/` — how agents and contributors work here (method only, no project history).

## Conventions
- Rust 2021, toolchain pinned in `rust-toolchain.toml`. Don't bump it casually.
- Pure Rust: the core libraries and the `decern`/`decern-serve` binaries have no
  compiled-C-FFI dependencies. The one documented exception is the optional
  `decern-store-postgres` crate (multi-host deployments need a TLS stack); the
  binaries don't depend on it, so the default build stays pure Rust. See that
  crate's README. New deps must be permissive-licensed and cheap to audit.
- Terse code, terse comments. Comment the non-obvious *why*, never the *what*.

## Verify before commit
Run the canonical script (the same gates CI runs) and keep it green:

```
./scripts/verify.sh
```

Needs the pinned toolchain, `cargo-deny`, and **cvc5** for the proofs. See [CONTRIBUTING.md](CONTRIBUTING.md).

`--skip-proofs` runs every gate except the proofs, for iterating on a change that cannot reach
authorization semantics. It exits non-zero regardless, so it can never stand in for a passing
run: finish with `./scripts/verify.sh` and no flags before you commit.

## Proof-first
Any change touching authorization semantics — the kernel decision function, the Cedar model,
the invariants, or their inputs — must keep the proofs green:

```
decern prove
```

This shells out to the **cvc5** SMT solver, which must be installed. A red proof blocks the
change; a proof statement must never claim more than the solver checks.

## Sign-off (DCO)
Sign off every commit (`git commit -s`) — see [CONTRIBUTING.md](CONTRIBUTING.md).
