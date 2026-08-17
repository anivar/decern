<!-- SPDX-License-Identifier: Apache-2.0 -->
# standards

`registry.yaml` lists every external spec decern implements. Each entry carries the
spec's `url`, the files that implement it (`surface`), a machine-readable `verified`
date (`YYYY-MM-DD` or `pinned`), what conformance means here, and — for files that look
standard-facing but are not — a top-level `non_surface` list.

## Start from the file you are about to change

```sh
python3 scripts/standards.py for crates/decern-server/src/sig.rs
python3 scripts/standards.py brief crates/decern-server/src/spiffe.rs
```

That names every governing spec, emits a shared grounding brief for parallel agents, and
suggests independent review dimensions. Prefer this over `grep -B14`: the script is what
graph orchestration grounds on ([`../methods/standards-graph.md`](../methods/standards-graph.md)).

Then fetch each url and read the current text — specs move, and working from memory is how
a surface drifts out of conformance without any test noticing. Build to what it says now,
add or update a test that pins the behaviour, and update the entry's conformance note and
its `verified` date in the same change.

## Integrity

`python3 scripts/standards.py check` (also via `./scripts/verify.sh`) fails when a surface
path is missing, a watched server module is in neither `surface` nor `non_surface`, or an
entry lacks `verified`. A file that is standard-facing and appears in no list is still a
defect: add it to a standard, or to `non_surface` with intent.
