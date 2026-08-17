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
- [`.agent/`](.agent/README.md) — how work is done here, method only, no project history:
  - [`.agent/methods/`](.agent/methods/README.md) — proof-first, small diffs, adversarial
    review, and how to decompose a change too big for one diff.
  - [`.agent/methods/graph-orchestration.md`](.agent/methods/graph-orchestration.md) — shaping
    work that needs more than one loop, with [`workflow-template.js`](.agent/methods/workflow-template.js)
    as the runnable form.
  - [`.agent/standards/registry.yaml`](.agent/standards/registry.yaml) — every external spec
    decern implements, what conformance means for each, and when it was last read.
  - [`.agent/standards/comments.md`](.agent/standards/comments.md) — the comment standard,
    enforced by `scripts/verify.sh` wherever a grep can enforce it.

## Conventions
- Rust 2024, toolchain pinned in `rust-toolchain.toml`. Don't bump it casually.
- No TLS stack: the core libraries and the `decern`/`decern-serve` binaries pull no
  TLS, no OpenSSL and no `cmake`. That is the claim, and it is not "zero compiled
  native code" — `cedar-policy` → `stacker` → `psm` compiles a small assembly routine
  in every build, the default one included. The optional `decern-store-postgres` crate
  (multi-host deployments need TLS) is the documented exception, and the binaries don't
  depend on it. See that crate's README and [DEPENDENCIES.md](DEPENDENCIES.md). New
  deps must be permissive-licensed and cheap to audit.
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

## Changelog entry
If a user would notice the change, add one file to [`changelog.d/`](changelog.d/README.md) in the
same commit, named `<section>-<slug>.md` — the prefix picks the section, the body is the entry
verbatim. CI fails a change under `crates/` or `sdks/` that has neither a fragment nor the
`no-changelog` label. Check it renders with `./scripts/changelog.sh --preview`.

Write it for whoever reads the release notes, not for the reviewer of the diff: what it does, and
where the guarantee stops. Don't label it breaking, and don't write a migration guide — this is a
pre-1.0 audience, so state the change plainly and let that be the migration. End it with
`Authored by @handle`, naming the human whose work it is, and `reported by @handle` where someone
else found the defect.

## What a change can break without failing

The gates catch a red proof and a broken test. These are the ones that compile, pass, and
still cost a guarantee:

- **A caller posture is a `CallerAuth` implementation, never a parallel guard.** The trait and
  the single guard live in `crates/decern-server/src/caller.rs`; each credential posture
  implements it in its own module (`bearer.rs`, `sig.rs`, `spiffe.rs`) and knows nothing of the
  others, so the guard dispatches once and a posture added later cannot skip a step by being
  wired in differently. Adding one means implementing the trait and joining the `ArgGroup` in
  `main.rs` — not a second `guard()`. The two *workload* postures additionally bind a caller to
  the principals it may name; a posture that authenticates a workload and does not bind it is a
  hole.
- **Some fields must never reach the kernel.** `asserted_by`, the decision subject, and a
  subject-side challenge are recorded or answered, and are removed from the context before the
  decision function runs — so a forged one can neither escalate nor deny (`decide.rs`,
  `mission.rs`; `forged_context_asserted_by_is_stripped_from_ledger_entry` is the pattern to
  copy). Adding a field a request can set means deciding, explicitly, which side of that line
  it sits on, and testing the answer.
- **The record is written before the answer is served.** An unrecordable decision is a `503`,
  never a bare allow. Any new path that answers must append first.
- **A standard-facing change starts by re-reading the standard.**
  [`.agent/standards/registry.yaml`](.agent/standards/registry.yaml) lists every spec decern
  implements, what conformance means here, and the date the text was last read. Specs move,
  and memory does not track them: fetch the current text before changing the surface, then
  update that entry — a new caller posture, wire format or header means a new entry, not a
  silent one. An entry that no longer matches the code is the same defect as a doc that
  overstates.
- **A claim in a doc is part of the product.** The project's whole pitch is that it is
  checkable, so a sentence that overstates is a defect the same way a wrong return value is.
  Say what the code does, name the limit in the same breath, and when two files state the same
  claim, change both. Prefer deleting a claim to softening it.

## Where not to go

decern decides and records; it does not enforce, issue credentials, or run approval UX. See
[ROADMAP.md](ROADMAP.md)'s non-goals before starting something large — an OAuth server, a
gateway, or an approval product inside `decern-serve` will be declined on scope, however good
the code is.

## Sign-off (DCO)
Sign off every commit (`git commit -s`) — see [CONTRIBUTING.md](CONTRIBUTING.md).
