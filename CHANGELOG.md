<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-08

### Changed

- **Breaking: `Entry::parameter_digest` is now `Entry::digests`, a map keyed by name.** A decision
  binds more than its arguments, and a column per thing bound does not scale: consumers of
  `decern-ledger` now record what their own decisions depend on under names they choose, and a
  reader that does not recognise a name can still see that something was pinned and whether it
  matches. `DIGEST_PARAMETERS` holds what `parameter_digest` held. Ordered, since the map is inside
  the bytes the hash chain covers. `jcs::parameter_digest` is now `jcs::digest`, which is what it
  always computed.
- **Breaking: numbers canonicalize per RFC 8785 §3.2.2.3, so a digest is portable.** §3.2.2.3
  requires a JSON number to be serialized as ECMAScript prints it, which a shortest-round-trip float
  printer does not do: `3` is required where `3.0` was written, `100000000000000000000` where `1e20`
  was, and `0.000001` where `1e-6` was. A digest over a value carrying such a number now agrees with
  one computed by any other conformant implementation, and `3` and `3.0` — the same IEEE-754 double
  — now digest alike. Verified against V8 over 3.1M doubles. An integer outside §3.2.2.3's
  interoperable range of ±(2^53−1) keeps every digit rather than rounding to the nearest double, so
  two distinct ids can never share a digest. Digests recorded before this change are not comparable
  with digests computed after it. The hash chain is unaffected: it commits to each entry's exact
  stored bytes and never canonicalizes.

### Added

- **The authority a decision was taken against, on the record.** Every decision recorded by the PDP
  carries `DIGEST_AUTHORITY` — the policy, schema and entity graph as they stood. The chain shows a
  record was not altered; this shows what it was decided against, so a later reading can tell
  whether that authority is still in force. Computed once at load.
- **Anchoring.** `decern-serve` publishes a signed RFC 9162 tree head at `GET /anchor/v1/tree-head`;
  `decern verify --anchor <file>` proves the log still extends a commitment published earlier, so a
  record dropped after it was committed is detectable by someone who is not the operator.
- **`GET /audit/v1/subject?handle=<h>`** — the decisions recorded about one party, each with an
  inclusion proof against the returned head. Bounded, and says when it truncates.
- **A subject-side challenge surface.** The party a decision was about can register a signed
  challenge; it is removed from the context before the kernel runs, answered afterwards, and the
  answer and its reason are recorded. Standing tokens are verified against issuer keys configured
  with `--standing-issuer-key`. What a deployment supports is at
  `GET /.well-known/decern-subject-side-disclosure`.
- **`decern explain`** — a faithful reading of one recorded decision, chain verified first.
- **Revocation blast radius** — `Directory::descendants_of` and
  `GET /directory/v1/principals/{id}/descendants`.
- **[docs/CLI.md](docs/CLI.md)** — a command reference for both binaries.
- SDK clients cap the error-body read at 64 KiB and report truncation.

## [0.1.1] - 2026-08-02

### Fixed

- **Mission: a terminated grant could revive to Active after its own expiry.** The registry evicted the
  terminated tombstone at expiry and `approve()` had no future-expiry guard, so re-approving an
  identical lapsed grant returned Active. Fixed at both layers — `approve()` refuses an already-expired
  mission, and the store retains terminated tombstones past expiry and is self-monotone (refuses
  re-registering an expired entry). A registry-layer enforcement bug found by the pre-release audit;
  the proven kernel (`decay` et al.) and the tamper-evident ledger were unaffected and would have
  recorded the transition. (#7, #8)

### Changed

- Honesty corrections from the pre-release audit: the transitive-closure derivation is covered by
  re-derivation **unit** tests (not "property tests"); the default build is not zero-compiled-native
  (cedar → stacker → psm compiles an assembly routine via `cc`), corrected in the README and on the
  site; and `decern verify` now prints a prominent notice when run without `--pubkey`, since a
  chain-only pass is not a full verify. (#9, #10)

## [0.1.0] - 2026-08-02

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
