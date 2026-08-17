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

## Shape the work before making it
Whether a change is one loop or several parallel branches is a decision, and it is cheaper made
before the first edit than after. [`graph-orchestration.md`](graph-orchestration.md) covers finding
which dependencies are real, grounding parallel work once instead of per-branch, keeping concurrent
edits from overwriting each other, and the difference between a gate that ran and a gate that
checked anything. [`workflow-template.js`](workflow-template.js) is that shape, runnable.

When the change set intersects a standard-facing surface, ground from the registry first —
[`standards-graph.md`](standards-graph.md) and
[`workflow-template-standards.js`](workflow-template-standards.js). 
`python3 scripts/standards.py for <path>…` builds the shared brief and dimensions once.
