<!-- SPDX-License-Identifier: Apache-2.0 -->
# Roadmap

The public direction, in rough order. Aspirations, not commitments — priorities move as deployments
and contributors teach us more, and nothing here carries a date. Shipped behavior lives in the
[README](README.md) and [CHANGELOG](CHANGELOG.md).

## Positioning

decern is the **decision plane**: an AuthZEN PDP over a Cedar kernel with an SMT-checked forbid
envelope, Missions for approval-backed delegation, and a fail-closed ledger. It decides and records;
it does not enforce. Identity providers and MCP/A2A gateways sit on the other side of that line as
identity and enforcement peers — compose with them; do not absorb OAuth, service mesh, or approval
UX into `decern-serve`.

## Shipped

- **Mission-lifecycle service** — approve / look up / terminate over HTTP, every transition
  recorded to the tamper-evident ledger (`/mission/v1/*`).
- **Decision-under-mission** — `--require-mission` gates decide on a live Mission; server-derived
  approval flags; Mission ref + `parameter_digest` + optional `decision_subject` on the Entry.

## Next — the secure agent-action path

- **Default money path behind Mission** — require a Mission for MoveMoney without the opt-in flag
  (read-only default, mutation gated).
- **Decision-subject column** — the party a decision is *about*, distinct from who asked and from
  the accountable-owner. Recorded today alongside a Mission; the work ahead is deriving it where
  the directory can, rather than accepting it named.
- **Anchor verification command** — verify a lone ledger file against an external anchor from the
  CLI, closing the "verify without trusting the operator" loop offline.
- **MCP evaluation mapping** — document a thin `tools/call` → AuthZEN evaluate mapping with a golden
  test, so a gateway can call decern per tool invocation. A worked integration example, not an
  enforcement product ([#6](https://github.com/anivar/decern/issues/6)).

## After that — interoperability and operator tooling

- **Authority-graph tooling** — downward traversal (revocation blast-radius) over the directory, and
  a graph export (DOT / Mermaid) ([#2](https://github.com/anivar/decern/issues/2)).
- **`decern explain`** — a "why" for any decision, reconstructed from the recorded entry
  ([#1](https://github.com/anivar/decern/issues/1)).
- **Richer AuthZEN conformance** — broaden request/response coverage; align Mission "not yet
  decidable → human approve" with AuthZEN's pending-approval patterns without forking the API.
- **Identity admit** — accept token-exchange claims (`sub` + `act`) into subject and sponsor so an
  externally issued agent identity is not body-spoofable; optional workload principals later.
- **Real-time revocation + signed kill-switch feed** — runtime overlay plus a poll feed
  ([#3](https://github.com/anivar/decern/issues/3)); a complement to an IdP's own logout, not a
  replacement.

## Later — adoption and ecosystem hardening

- **More client SDKs** — Mission APIs on the Go, Python and TypeScript clients.
- **Additional ledger head-store backends** — new implementations behind the same `LedgerHeadStore`
  trait.
- **Portable delegation ceiling (watch)** — if a cross-vendor agent-credential chain stabilizes,
  consume it as an upstream authority ceiling beneath the local Mission and policy, rather than
  reimplementing credential issuance inside the PDP.
- **Production evidence** — publish reproducible deployment profiles and, with permission, name
  independent adopters in [ADOPTERS.md](ADOPTERS.md). Adoption is evidence, never inferred from
  stars, integrations, or affiliated demonstrations.

## Explicit non-goals

- Building another MCP firewall, model gateway, or Slack/mobile approval product.
- Putting OAuth / IdP / vendor credential vaults inside `decern-serve`.
- Dropping SMT proofs or negative controls to chase gateway feature parity.

Want to pick one up? See [ARCHITECTURE.md](ARCHITECTURE.md#where-to-start-contributing) and the
[`help wanted`](https://github.com/anivar/decern/labels/help%20wanted) issues.
