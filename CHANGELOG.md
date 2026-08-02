<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

Initial release.

### Added

- Deterministic authorization kernel with **9 SMT invariants** (money-gate, isolation, decay,
  attenuation-edge, scope-gate, revocation-gate, residency-gate, role-gate, consent-gate)
  discharged over the entire input space by cvc5.
- Proven delegation attenuation.
- Append-only, Ed25519-signed, hash-chained tamper-evident decision ledger.
- Derived **accountable-owner** column on decisions recorded by the PDP: the root of the subject's
  delegation chain, resolved server-side from the directory (never a request input) — a recorded
  accountability column, not a decision gate.
- `decern` CLI: `prove`, `decide`, `verify`.
- `decern-serve` PDP: AuthZEN 1.0 Access Evaluation `POST /access/v1/evaluation` (with `/decide`
  as an alias) — request `{subject, action:{name}, resource, context}`, response `{decision}` with
  any reasons (allow) or errors (deny) under `context`; plus `GET /pubkey`, `GET /healthz`.
  Fail-closed (a decision whose audit record cannot be written returns 503, never the Allow).
- `decern-serve` Mission-lifecycle service over `decern-identity`: `POST /mission/v1/approve`,
  `GET /mission/v1/{s256}`, `POST /mission/v1/{s256}/terminate`. An approver grants an agent a scoped,
  fail-closed-attenuated Mission (an approved tool the approver does not hold, or an expiry beyond
  theirs, is refused and nothing is recorded); each accepted transition is recorded to the
  tamper-evident ledger and is not reported as succeeded unless that record was written; a terminated
  Mission never revives. Backed by the durable `MissionRegistry` (`--missions <PATH>`, default
  `decern-missions.json` alongside the ledger).
- `decern-serve --sharded <dir>` hosted mode: several server processes on one host share one
  tamper-evident ledger (one hash chain per tenant) via a `flock` file head store; each decision is
  recorded to its subject's tenant shard. Mutually exclusive with `--ledger`.
- Multi-host sharded mode: `--sharded` also accepts a `postgres://` URL (Postgres advisory-lock head
  store, `decern-store-postgres`) when `decern-serve` is built with `--features postgres`. Off by
  default, so the shipped binary stays pure Rust; the postgres URL is never echoed in logs.
- `examples/quickstart.sh`: prove -> serve -> decide -> verify -> tamper-fails.
- Pure Rust, zero compiled-C-FFI dependencies; toolchain pinned via `rust-toolchain.toml`.
