<!-- SPDX-License-Identifier: Apache-2.0 -->
## What & why

<!-- One or two lines. Link the issue if there is one (`Closes #NN`). For a small, obvious fix a
     linked issue isn't required — just say what it changes. Larger/design changes should have been
     discussed in an issue first (see CONTRIBUTING.md). -->

## Checklist
- [ ] `./scripts/verify.sh` passes (build · test · cvc5 proofs · clippy `-D warnings` · fmt · docs · cargo-deny · standards guard)
- [ ] If this touches authorization semantics (kernel decision, model, invariants), `decern prove` stays green — and a new guarantee ships with its negative control
- [ ] A user-visible change carries an entry in [`changelog.d/`](../changelog.d/README.md) — or the `no-changelog` label, if a reader would notice nothing
- [ ] Commits are DCO signed off (`git commit -s`)
- [ ] Comments follow [`.agent/standards/comments.md`](../.agent/standards/comments.md)

<!-- Agent-authored PRs are welcome under the same rules — a human sponsors the change and signs off the DCO. -->
