<!-- SPDX-License-Identifier: Apache-2.0 -->
# .agent

The working method for agents and humans in this repo — how to make a change here, not what
has been changed. Method, and one record that moves with the code: the standards registry,
which says when each specification was last read and which files implement it.

It holds `methods/` — how to make a change, and how to shape one wide enough to need
shaping (including grounding parallel work from the standards registry) — and `standards/`,
the registry of external specs decern implements and the rule for staying conformant. Read
the current spec before you touch its surface, and verify before you commit (see
`../AGENTS.md`). Lookup and integrity: `python3 scripts/standards.py`.
