<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributing to decern

Thanks for helping. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Local verify loop

Every change must pass the canonical verify script before you open a PR:

```
./scripts/verify.sh
```

It runs build, test, the cvc5 proofs, clippy, fmt, docs, cargo-deny, and the no-lineage / standards guard — the
same gates CI runs. Prerequisites: the pinned toolchain (`rust-toolchain.toml`), **cargo-deny**
(`cargo install cargo-deny`), **python3** for the standards-registry check, and **cvc5** on
`PATH` (or `$CVC5`) for the proof tests. Only cvc5 is proof-specific — the rest are needed
even with `--skip-proofs`.

While iterating on a change that cannot reach authorization semantics — an SDK, a doc, CLI
output — you can run every other gate without installing a solver first:

```
./scripts/verify.sh --skip-proofs
```

That is a local convenience, not a shortcut past the bar. It prints that the proofs were
skipped and **exits non-zero even when everything else passes**, so a skipped run can never be
mistaken for a green one. CI always runs the full loop, and the proofs still gate the merge —
run the script with no flags before you open the PR.

## Changelog entries

A change a user would notice ships with its own entry, as a file in
[`changelog.d/`](changelog.d/README.md), in the same pull request:

```
changelog.d/fixed-small-order-keys.md
```

The filename prefix picks the section (`added-`, `changed-`, `fixed-`, `security-`, `removed-`,
`deprecated-`); the file holds the entry as it should appear. `scripts/changelog.sh --release`
folds them into `CHANGELOG.md` at release time, and the release notes are that section.

Writing it here rather than in `CHANGELOG.md` means it is written while you still have the context,
it is reviewed alongside the code it describes, and two pull requests never collide on the same
lines. Check yours renders before pushing:

```
./scripts/changelog.sh --preview
```

End the entry with who did the work — `Authored by @you`, and `reported by @them` where someone
else found the defect. Your name belongs in the release notes, not only in the commit log.

A refactor, a test, a comment or a CI change needs no entry — say so and apply the `no-changelog`
label.

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
approachable. A PR is reviewed before it merges; see [GOVERNANCE.md](GOVERNANCE.md). The norm is that a PR
merges only with **every** job green — not only the required ones: a red advisory job is a claim
about the change that someone has to answer. The maintainer can override that norm deliberately —
a workflow can be wrong too — and an override is stated on the PR, not stepped around silently.

## Agentic contributions

decern is built to be contributed to by agents as well as people. If you're an agent:

- Start from [`AGENTS.md`](AGENTS.md) (the working method) and [`.agent/standards/`](.agent/standards/)
  (the conventions, including the comment standard). `.agent/` is method only — no project history.
- The bar is identical to a human PR: [`./scripts/verify.sh`](scripts/verify.sh) green (build, test,
  cvc5 proofs, clippy, fmt, docs, cargo-deny, no-lineage / standards guard) and honest, scoped commits.
- A **human sponsors the change and signs off the DCO** (`git commit -s`) — the sign-off certifies a
  person stands behind the submission, whoever wrote the diff.
- Touching authorization semantics (the kernel decision, the model, an invariant)? Keep `decern prove`
  green and, if you add a guarantee, add its negative control too.
