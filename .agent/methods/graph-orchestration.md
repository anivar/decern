<!-- SPDX-License-Identifier: Apache-2.0 -->
# Shaping work: graphs, loops, and what verification is for

How to decide the *shape* of a change before making it, and how to keep the checks honest once
several agents are working at once. Method only — no project history.

Most work here is narrower than it looks and gets rushed anyway. The two failure modes are
opposite: serialising work that had no dependency between its parts, and parallelising work whose
parts were never independent. Both are decided before the first edit.

## Find the real edges

Write the steps down, then draw an edge only where one step consumes another's output. Edges that
survive that test are real; the rest are an artefact of having written the list top to bottom.

Independent nodes run at once. Dependent nodes do not, and no amount of concurrency changes that.
Two reads of different files are independent. "Design the schema" and "write the migration" are not,
however much you want them to be.

Width below three is a loop wearing a graph's clothes. The coordination costs more than it saves,
and a loop keeps its context, which is usually what the work actually needed.

## Ground once, then fan out

Build one dense factual brief and hand the *same* brief to every branch. Branches that each
re-derive context drift apart, and reconciling that drift costs more than the parallelism won.

Give each branch a clean context window and ask for a condensed result. An orchestrator that reads
every file itself has spent its context on material it will not use, and quality falls with it. The
point of a subagent is not extra hands; it is a separate window whose contents never enter yours.

## Isolate concurrent edits

Agents editing the same working tree will overwrite each other's uncommitted work — one `git add -A`
sweeps up whatever a neighbour left half-written, and both changes land in a commit that describes
one of them. Give each concurrent writer its own worktree, or serialise the writes.

Symptoms worth recognising, because they are quiet: a commit whose message names one change and
whose diff contains two; a branch pointer that moved under a running agent; two agents reporting the
same branch name with different contents.

## Verify what was claimed, not what was run

A gate is only worth what it actually exercises. Three failures from this repo, each caught after a
green report:

- A traversal documented as breadth-first was implemented depth-first. Its two tests used a linear
  chain, where both orders produce the same answer, so neither test could fail. **A test that cannot
  distinguish the bug from the fix is not coverage.** The replacement uses a branching tree, where
  the orders differ.
- A route registered with an outdated path syntax compiled cleanly and panicked when the router was
  built. The report said "builds successfully", and it did. **Building is not running.** The
  endpoint is now driven through the router in a test.
- An explanation printed `not checked (verified)` for a signature it had not checked. Every test
  passed, because none asserted on that line. **Output nobody asserts on is not tested.**

Write the failing test first, and prove it fails for the stated reason before trusting it green. A
negative control — an equivalent input the check must reject — is what turns a passing test into
evidence.

## Review adversarially where it counts

Anything touching authorization, delegation, tenancy, or the ledger gets read as an attacker, by
someone who did not write it: what request, state, or ordering breaks the guarantee? Ask for
refutation rather than approval — a reviewer told to find problems finds different things than one
told to check the work.

An agent's own account of its work is a claim, not a result. Re-run the gate yourself.

## Cost is part of the design

A wide graph over cheap work is waste. Bound the fan-out, and widen it only after a narrower run has
shown the width was the constraint. If a run consumed a large budget and returned findings a single
reader would have found, that is a design error, not a tuning problem.

## The checklist

1. Draw the graph; delete the fake edges. Loop if width is under three.
2. Ground once; hand every branch the same brief and a clean window.
3. Isolate concurrent writers, or serialise them.
4. Write the failing test first; give it a negative control.
5. Adversarially review anything touching a guarantee.
6. Run `./scripts/verify.sh` yourself before believing any of it.

A runnable version of this spine is in [`workflow-template.js`](workflow-template.js).
