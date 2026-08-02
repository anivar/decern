<!-- SPDX-License-Identifier: Apache-2.0 -->
# Methods

How to make a change in decern. Method only — no project history.

## Proof-first
The guarantees are the product. Any change to authorization semantics — the kernel decision
function, the Cedar model, or an invariant — must keep the proofs green (`./scripts/verify.sh`
runs them). A proof statement must never claim more than the solver checks. If a change would
weaken an invariant, it needs a stronger invariant, not a weaker one.

## Small, verifiable diffs
Keep each change focused and reversible. Run `./scripts/verify.sh` before every commit; a red
gate blocks the change. Prefer a test that fails first, then the fix.

## Adversarial review
For anything touching authorization, delegation, or the ledger, review the change as an attacker:
what request, state, or ordering breaks the guarantee? Add the negative control that would catch
the regression (see the per-invariant controls in `decern-proof`).

## Decompose the large
A change too big to hold in one diff is too big to review. Split it along the dependency graph:
land the leaf pieces with their tests first, then the parts that build on them.
