<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributing to decern

Thanks for helping. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Local verify loop

Every change must pass the canonical verify script before you open a PR:

```
./scripts/verify.sh
```

It runs build, test, the cvc5 proofs, clippy, fmt, docs, cargo-deny, and the no-lineage guard — the
same gates CI runs. Prerequisites: the pinned toolchain (`rust-toolchain.toml`), **cargo-deny**
(`cargo install cargo-deny`), and **cvc5** on `PATH` (or `$CVC5`) for the proof tests.

While iterating on a change that cannot reach authorization semantics — an SDK, a doc, CLI
output — you can run every other gate without installing a solver first:

```
./scripts/verify.sh --skip-proofs
```

That is a local convenience, not a shortcut past the bar. It prints that the proofs were
skipped and **exits non-zero even when everything else passes**, so a skipped run can never be
mistaken for a green one. CI always runs the full loop, and the proofs still gate the merge —
run the script with no flags before you open the PR.

## Sign-off (DCO)

Every commit must be signed off under the **Developer Certificate of Origin 1.1**
(<https://developercertificate.org/>): sign-off certifies you have the right to submit the
work under Apache-2.0. Sign off with:

```
git commit -s
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer derived from your
`user.name` and `user.email`, so set both. Commits without a valid sign-off cannot be merged.

## PRs

Keep changes minimal and focused, and match the surrounding code. **Open an issue to discuss first**
for anything large or design-changing — a short back-and-forth avoids a wasted PR. For a small,
obvious fix, **just raise a PR**. Link the issue you're closing (`Closes #NN`) where there is one.

Where to start: [ARCHITECTURE.md](ARCHITECTURE.md) maps each contribution area to the crate that owns
it, and [`help wanted`](https://github.com/anivar/decern/labels/help%20wanted) issues are picked to be
approachable. A PR is reviewed before it merges; see [GOVERNANCE.md](GOVERNANCE.md).

## Agentic contributions

decern is built to be contributed to by agents as well as people. If you're an agent:

- Start from [`AGENTS.md`](AGENTS.md) (the working method) and [`.agent/standards/`](.agent/standards/)
  (the conventions, including the comment standard). `.agent/` is method only — no project history.
- The bar is identical to a human PR: [`./scripts/verify.sh`](scripts/verify.sh) green (build, test,
  cvc5 proofs, clippy, fmt, docs, cargo-deny, standards guard) and honest, scoped commits.
- A **human sponsors the change and signs off the DCO** (`git commit -s`) — the sign-off certifies a
  person stands behind the submission, whoever wrote the diff.
- Touching authorization semantics (the kernel decision, the model, an invariant)? Keep `decern prove`
  green and, if you add a guarantee, add its negative control too.
