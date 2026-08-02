<!-- SPDX-License-Identifier: Apache-2.0 -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/decern-mark-dark.svg">
    <img src="docs/img/decern-mark.svg" alt="decern" width="64" height="64">
  </picture>
</p>

# Architecture

A map of decern for contributors — human or agent. If you're here to pick something up, the
per-crate table below tells you *where* things live, and [CONTRIBUTING.md](CONTRIBUTING.md) tells
you *how* to land a change.

<p align="center"><img src="docs/img/architecture.png" alt="decern architecture: the decern and decern-serve binaries over the kernel, identity, proof, ledger, store, and crypto crates" width="860"></p>

## The shape

A decision is a **pure function of `(principal, authority graph, policy, now)`**. Everything else
is arranged around that function: a proof harness that machine-checks its safety properties, a
tamper-evident ledger that records what it decided, and thin binaries that expose it.

Two binaries over seven library crates. The stock build is pure Rust; the one exception —
`decern-store-postgres` — carries a TLS stack behind a build flag and is off by default.

| Crate | Kind | Responsibility |
|---|---|---|
| `decern-kernel` | lib | The deterministic decision function. Cedar authority graph, the `Directory`, `Kernel::check`. This is the security core. |
| `decern-proof` | lib | The SMT proof harness. Compiles the Cedar model symbolically and discharges the nine invariants with cvc5, with per-invariant negative controls. |
| `decern-ledger` | lib | The tamper-evident record. Append-only, Ed25519-signed, hash-chained ledger; Merkle, JCS canonicalization, anchors, single-file + sharded. |
| `decern-store` | lib | Persistence traits + reference impls. `LedgerHeadStore` (single-host `flock` head store) and the durable `MissionRegistry`. |
| `decern-store-postgres` | lib *(optional)* | Multi-host `LedgerHeadStore` over Postgres advisory locks. The one compiled-C (TLS) dependency; behind `--features postgres`. |
| `decern-identity` | lib | The Mission core: approval-backed, provably-attenuated authority (`approve`, `ApprovedMission`, `MissionRegistry`). |
| `decern-crypto` | lib | Ed25519 + SHA-256 primitives shared by the ledger and identity. |
| `decern-cli` | bin → `decern` | `prove` / `decide` / `verify`. |
| `decern-server` | bin → `decern-serve` | The fail-closed AuthZEN PDP: evaluate, record, serve. Also serves the Mission lifecycle over `decern-identity` (`POST /mission/v1/approve`, `GET`/`terminate`), recording each transition to the ledger. |

`crates/decern-kernel/model/` holds the Cedar policy, schema, and entities the kernel loads. `.agent/` holds the working
method and the standards registry. `scripts/verify.sh` is the one gate every change must pass.

## How a decision flows

1. A request reaches `decern-serve` (`POST /access/v1/evaluation`, AuthZEN-shaped).
2. `decern-kernel` evaluates the pure decision function over the loaded authority graph and policy.
   The server supplies `now` from its own clock (never the request body).
3. The decision, plus a server-derived **accountable-owner** (the root of the subject's delegation
   chain), is appended to the `decern-ledger` — Ed25519-signed and hash-chained.
4. The decision is returned **only if that record was written**. If it couldn't be, the server
   returns `503`, never a bare allow. This fail-closed contract is the whole point of the PDP.
5. Anyone can later run `decern verify` over the ledger: signatures prove each record authentic,
   the chain proves nothing was dropped — **without trusting the operator**.

The same binary also reaches `decern-identity` for the **Mission lifecycle**: `POST /mission/v1/approve`
grants an agent a scoped, fail-closed-attenuated authorization context (refused, and nothing recorded,
if it exceeds the approver's own authority or expiry); `GET /mission/v1/{s256}` reports its state; and
`POST /mission/v1/{s256}/terminate` ends it, with no revival. Each accepted transition is appended to
the ledger under the same fail-closed contract as a decision — a 503 rather than an unrecorded success —
so a Mission's whole history is as externally verifiable as the decisions it authorizes. The durable
Mission registry (`decern-store`) holds the authoritative state, so a termination outlives any single
process.

## How the guarantees are established

The safety properties are not tested on examples — they're **proven over the modeled input domain**.
`decern-proof` compiles the Cedar model with a symbolic compiler and asks cvc5 whether each of the
nine invariants can be violated; a green suite means it could find no counterexample anywhere in the
domain. Each invariant ships with a **negative control** — a test that removes the guarantee from the
policy and asserts cvc5 then *finds* a counterexample — so a passing suite is evidence the proofs are
load-bearing. Proof statements are calibrated to exactly what the solver certifies; where a property
depends on a derived attribute (e.g. the transitive delegation closure), the derivation is trusted
Rust covered by property tests and is documented as such. See `decern-proof` and `AGENTS.md`.

The solver runs in `decern prove` and CI only — `decern-serve` does not link it. The guarantee is
established where the proofs run, not on the request path.

## Where to start contributing

Match a contribution area to the crate that owns it:

- **A new client SDK** → mirror `sdks/python` / `sdks/typescript` against the AuthZEN surface in `decern-server`.
- **An enforcement adapter** (put decern behind an HTTP/gRPC gateway) → a thin client over `decern-server`.
- **Authority-graph tooling** (traversal, blast-radius, export) → `decern-kernel`'s `Directory`.
- **A new ledger backend** → implement `decern-store`'s `LedgerHeadStore` trait.
- **A new proven property** → `decern-proof` (add the invariant *and* its negative control).
- **Model / policy packs** → `crates/decern-kernel/model/`.

Read [`AGENTS.md`](AGENTS.md) (the method), [`.agent/standards/`](.agent/standards/) (the conventions,
including the comment standard), and [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change.
