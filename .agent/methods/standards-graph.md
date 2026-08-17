<!-- SPDX-License-Identifier: Apache-2.0 -->
# Standards registry and graph engineering

How the standards registry plugs into the shape in [`graph-orchestration.md`](graph-orchestration.md).
Method only — no project history.

## What the registry is, as a graph

| Graph concept | In the registry |
|---|---|
| Node (standard) | An entry under `standards:` with `url`, `verified`, `conformance` |
| Node (surface) | A path in `surface:` (file or directory prefix) |
| Edge | `implements` — the file is governed by that spec |
| Non-node | `non_surface:` — watched files that are deliberately not mapped |

An edge is **not** a dataflow dependency. Two files that share a standard can still be
edited in parallel: apply the fake-edge test before serialising work.

## Ground once from paths

Before fanning out review (or edit) branches over a change set, build **one** brief:

```sh
python3 scripts/standards.py for crates/decern-server/src/sig.rs
python3 scripts/standards.py brief path/a path/b    # markdown only
python3 scripts/standards.py graph --paths path/a   # nodes + edges JSON
```

`for` returns JSON with:

- `standards` — every entry whose `surface` intersects the paths
- `grounding` — the shared factual brief (hand unchanged to every branch)
- `dimensions` — independent review axes (fake-edge tested; width capped)
- `graph` — the induced bipartite graph for tooling that wants nodes/edges

Branches that each re-`grep` the registry will drift. Ground with this output once.

## Fan-out shape

Width under three is a loop. When `dimensions` has three or more independent axes, each
axis is one Find branch; Verify refutes; Synthesize asks what no dimension could see.

Caller-posture surfaces (`sig.rs`, `bearer.rs`, `spiffe.rs`, `caller.rs`) get posture
dimensions (fail-open / binding / replay). Other surfaces get the default three
(correctness / fail-open / tests). Conformance text may add at most two extras.

Runnable skeleton: [`workflow-template.js`](workflow-template.js) — pass
`args.target` and optionally `args.dimensions` from `for`'s JSON, and put `grounding`
into the Ground brief (or skip re-deriving it).

## What verify enforces

`python3 scripts/standards.py check` (via `scripts/verify.sh`):

- every `surface` and `non_surface` path exists
- every entry has `verified:` (`YYYY-MM-DD` or `pinned`)
- every watched `crates/decern-server/src/*.rs` is in a `surface` or `non_surface`

A green build still does not mean the agent re-read the spec. The registry rule and the
grounding brief do. Update `verified` and the conformance note in the same change that
touches a surface.
