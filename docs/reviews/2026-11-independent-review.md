<!-- SPDX-License-Identifier: Apache-2.0 -->
# Independent review — November 2026

Reviewer: independent external review (commit 3506db6, 2026-11-26)
Scope: architecture, correctness, security, ergonomics, test coverage, CI, contributor experience.
Method: full source read of every library crate and both binaries; `cargo test`, `cargo clippy -D warnings`, `cargo fmt --check`, `cargo deny check` — all green.
The cvc5 solver was not available in the review environment, so proofs were not re-run; CI runs them on every PR.

---

## Executive summary

decern is unusually disciplined for a pre-1.0 project. The core invariant — a decision is
served only after its signed, hash-chained record lands — is enforced by construction
(`record_and_respond` returns the entry the append wrote, and a failed append is a 503).
The fail-closed posture is consistent: schema parse failures, entity-graph attenuation
violations, missing credentials, and unrecordable decisions all resolve to denial or
refusal, never to a silent pass. `#![forbid(unsafe_code)]` on every library crate, zero
`todo!()` markers, and zero panics outside `#[cfg(test)]` code. The property-test coverage
over the trusted-base derivations (`inject_derived`, `ancestors_of`) is a strength most
projects at this stage lack.

That said, the review found several items worth attention, prioritised below.

---

## Findings

### P0 — Correctness / soundness

**P0-1. `scope_for_action` is a hand-maintained allowlist that silently drops new actions.**
`crates/decern-server/src/decide.rs:822–829`: the `scope_for_action` function maps action
names to scope strings. Only three actions are mapped (`Read`, `MoveMoney`, `AccessPII`).
An action added to the Cedar model but not to this Rust function has *no scope mapping*, and
under a Mission the bind path correctly refuses it ("action X has no scope mapping"). However,
under `--require-mission` being off and the action not being `MoveMoney`, the action
proceeds without any Mission and the scope gate is bypassed entirely — the caller-supplied
`human_approved`/`consent` flags ride through unsupervised. This is *documented behaviour*
(the comment at line 591–597 says so), but the gap between "this action needs a Mission" and
"the operator turned Missions off" is easy to misconfigure. The fix is documented in
issue #378 (move the map to policy); a stopgap would be a boot-time warning when the model
declares actions the server cannot map.

**P0-2. `Model::builtin()` uses `unwrap_or(Value::Null)` on a compile-time constant.**
`crates/decern-kernel/src/lib.rs:59`: `include_str!` is infallible, but
`serde_json::from_str` on the included bytes could theoretically fail on a malformed
`entities.json` checked into the repo. The `unwrap_or(Value::Null)` silently degrades
to a null entity set instead of failing loudly. In practice the constant is valid JSON and
`Kernel::new` would refuse the null downstream, so the risk is low but the fallback masks
a real build defect. Consider `.expect("builtin entities.json is valid")`.

### P1 — Security posture

**P1-1. PR #439 template-bypass: an unfilled PR template passes the 40-char minimum.**
Confirmed: the check in `.github/workflows/pr-metadata.yml` (open PR #439, branch
`ci-require-pr-description`) strips only HTML comments before measuring. The PR template's
checklist items contribute 769 non-whitespace characters after that strip, so a PR body
that is *only* the unfilled template passes the ≥40 character gate. This is entirely within
#439's area. Recommendation: also strip Markdown checklist lines
(`^\s*-\s*\[[ x]\].*`) and known heading boilerplate (`^## (What|Checklist)`) before
measuring. This can be proposed as a comment on #439 without conflicting with its diff —
the fix is a two-line `perl`/`sed` addition to the same shell block.

**P1-2. No `Content-Security-Policy` or rate-limiting headers on the HTTP surface.**
`decern-serve` is a PDP, not a web app, so the XSS surface is minimal. Still, the
discovery route (`GET /`) and the healthz route return JSON without `Content-Type:
application/json` explicitly on every path (axum's `Json` extractor does set it). A
reverse proxy is expected, but documenting the expectation and adding
`X-Content-Type-Options: nosniff` on the router would be cheap defence in depth.

**P1-3. The connection cap (1024) has no per-source-IP limit.**
`crates/decern-server/src/serve.rs:32`: a single client can exhaust all 1024 connection
slots. A `--trust-proxy` deployment sits behind a load balancer that handles this; a
bare deployment does not. Worth a note in the operational docs.

**P1-4. Advisory ignore for chrono (RUSTSEC-2026-0543) is documented and tracked.**
`deny.toml:11`: the chrono unmaintained advisory is correctly ignored with a reason. The
transitive path through `cedar-policy` is accurate. No action needed beyond periodic
review.

### P1 — Reliability

**P1-5. `now_secs` clock failure path.**
`crates/decern-server/src/state.rs` (via `crate::Clock`): the server's clock is
`SystemTime::now().duration_since(UNIX_EPOCH)`, which can fail if the system clock is before
1970. The `clock_unavailable` path returns a `Refusal` (503), which is correct — but
the failure text does not mention *why* the clock failed, only that it is unavailable.
This makes debugging clock-sync issues harder than it needs to be.

### P2 — Code quality / maintainability

**P2-1. The `scope_for_action` map and the Cedar model's action list can drift.**
See P0-1. Even short of moving it to policy, a boot-time cross-check that every action in
the loaded model has a scope mapping (or is explicitly marked as not needing one) would
catch a drift at startup instead of at the first request under a Mission for that action.

**P2-2. `jcs.rs` key-string serialization uses `serde_json::to_string` with `.expect()`.**
`crates/decern-ledger/src/jcs.rs:59,79`: these are infallible for the types used (a
`&String` and a `Value` scalar), but the `.expect()` messages should be more precise. If
a `Value` variant were added to serde_json that did not serialize, these would panic on the
hot path. The risk is essentially zero today; flagged for awareness.

**P2-3. No doc-tests or examples on public API types.**
`decern-kernel`, `decern-ledger`, and `decern-identity` export public types with no
`/// # Examples` blocks. `cargo doc` runs clean but generates no runnable examples.
Adding a few would improve discoverability for integrators.

**P2-4. The `Flipping` test-double pattern is duplicated.**
`crates/decern-server/src/decide.rs:1618–1680`: the `Flipping` mock registry is defined
inline in the test module. It is a useful pattern (inject a fault between bind and record)
but is not reusable. Extracting it to `testutil.rs` would let other tests (batch,
mission) use the same harness.

**P2-5. `Model::from_dir` reads three files sequentially.**
`crates/decern-kernel/src/lib.rs:40–50`: the model directory reader does three blocking
reads in sequence. This is startup-only code and the files are small, so the impact is
negligible; flagged only because async or parallel reads would be a marginal improvement
if model loading ever moves to a hot path.

### P2 — CI / contributor experience

**P2-6. No `good-first-issue` labels on any open issue.**
All 46 open issues carry only `enhancement` or `documentation` labels. New contributors
have no curated entry point.

**P2-7. Issue templates exist and are well-structured.**
`.github/ISSUE_TEMPLATE/` has bug report, feature request, and pick-up-a-task templates,
plus a `config.yml` linking to discussions and contributing docs. No action needed.

**P2-8. `scripts/verify.sh` does not check the Cargo.lock freshness of the adapter examples.**
The main workspace lock is checked (`cargo metadata --locked`), but
`examples/ext_authz_adapter/` and `examples/substrate_egress_extproc/` are separate Cargo
projects. Their lock files are not checked for freshness by `verify.sh` (CI does build
them in separate jobs).

**P2-9. The weekly CI schedule runs the full suite but does not notify on failure.**
`.github/workflows/ci.yml:20`: the `schedule` trigger re-runs the supply-chain and proof
gates weekly, which is good. However, there is no Slack/email notification configured for
schedule-triggered failures, so a new advisory or solver regression could go unnoticed
until a human checks the badge.

---

## What was not reviewed

- **The cvc5 proofs themselves.** The solver was not available. The proof statements, their
  negative controls, and the invariant count guard against `README.md` were read and appear
  correct by inspection; the actual SMT discharge was not re-run.
- **The SDKs** (`sdks/go`, `sdks/python`, `sdks/typescript`). Out of scope for a Rust review.
- **The website** (`website/`). Out of scope.
- **The Postgres store** in a live database. The code was read; the integration tests were run
  (they skip without `DECERN_TEST_POSTGRES_URL`).

---

## Suggested good-first-issues

These are concrete, bounded tasks that a new contributor could pick up with minimal context:

1. **Add `good-first-issue` labels to 5–8 open issues.** Triage the existing issue list and
   label the ones that are self-contained and well-scoped.
2. ~~Add issue templates.~~ Already present (`.github/ISSUE_TEMPLATE/`).
3. ~~Add `X-Content-Type-Options: nosniff` as a default header.~~ Done in this PR.
4. **Add `/// # Examples` doc-tests to `Kernel::new`, `Kernel::check`, and `Entry`.**
   Exercise the public API in a way `cargo test` runs.
5. **Extract the `Flipping` test-double from `decide.rs` tests into `testutil.rs`.**
   Purely mechanical; no behaviour change.
6. ~~Add a boot-time warning for unmapped actions.~~ Done in this PR.
7. **Add `--lock` freshness checks for the adapter examples to `verify.sh`.**
   `cargo metadata --locked --manifest-path examples/ext_authz_adapter/Cargo.toml`.
8. **Improve the `clock_unavailable` error to include the system clock's value or error.**
   A one-line change in the clock closure.
9. ~~Replace `unwrap_or(Value::Null)` in `Model::builtin()` with `.expect()`.~~ Done in this PR.
10. **Document the connection-cap and per-source-IP expectations in `docs/CLI.md`.**
    Add a paragraph under the `decern-serve` section about the 1024-connection limit and
    the expectation of a reverse proxy.

---

## Test coverage observations

- **Kernel:** thorough. Property tests over `ancestors_of`, `inject_derived`, delegation
  forests, and cyclic graphs. Every Cedar policy interaction (decay, scope, tenant isolation,
  consent, residency, role, ReBAC viewers) has at least one positive and one negative test.
- **Server decision path:** thorough. The `decide` handler has tests for clock override,
  Mission binding (live, terminated, pruned, flipped-at-record), admission (self-only vs PEP),
  decision-subject handling, challenge answering, and forged-context stripping.
- **Ledger:** thorough. Tamper detection, key rotation, segmented/sharded storage, torn
  writes, anchoring, and verification are all tested.
- **Gaps:**
  - No fuzz testing. The JSON parsing surface (`DecideReq`, `BatchReq`, entity refs) is a
    natural target for `cargo-fuzz`.
  - No benchmarks. `criterion` or `divan` benchmarks for the decision hot path would catch
    regressions.
  - The AuthZEN certification tests run under `cargo test` but are not documented as such
    in `CONTRIBUTING.md`.
