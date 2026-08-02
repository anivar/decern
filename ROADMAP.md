<!-- SPDX-License-Identifier: Apache-2.0 -->
# Roadmap

Aspirations, not commitments. Direction may change; nothing here is promised. What already ships is
in the [README](README.md) and [CHANGELOG](CHANGELOG.md) — this file is only what's ahead.

## Near-term

- **Mission-lifecycle service** — expose the approval-backed, attenuated Mission through the PDP
  (approve / look up / terminate), with every transition recorded to the tamper-evident ledger.
- **Authority-graph tooling** — downward traversal (revocation blast-radius) over the directory, and
  a graph export (DOT / Mermaid).
- **Decision-under-mission** — gate a decision on the Mission that justifies it, so a recorded allow
  names the approved, attenuated task it was performed under.
- **Anchor verification command** — verify a lone ledger file against an external anchor from the
  CLI, closing the "verify without trusting the operator" loop offline.
- **Decision-subject column** — record the subject of a decision (the party it affects), distinct
  from who requested it and from the accountable-owner (which already ships).

## Later

- **Richer AuthZEN conformance** — broaden request/response coverage toward the full spec.
- **More client SDKs** — beyond the Python and TypeScript clients that ship today.
- **Additional ledger head-store backends** — new implementations behind the same `LedgerHeadStore`
  trait.

Want to pick one up? See [ARCHITECTURE.md](ARCHITECTURE.md#where-to-start-contributing) and the
[`help wanted`](https://github.com/anivar/decern/labels/help%20wanted) issues.
