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

## Next — the accountable-operations path

Close the loop from decided to enforced to revocable to accountable.

- **Real-time revocation + a signed kill-switch feed** — runtime overlay plus a poll feed a
  gateway can hold open ([#3](https://github.com/anivar/decern/issues/3)); a complement to
  an IdP's own logout, not a replacement.

## After that — anchors and verifiable releases

Trust that survives the operator, and releases that survive us.

- **`decern anchor`** — fetch and store a published tree head from the CLI
  ([#36](https://github.com/anivar/decern/issues/36)).
- **Anchoring for sharded deployments** — one commitment story for multi-shard logs
  ([#37](https://github.com/anivar/decern/issues/37)).
- **crates.io trusted publishing** — nine publisher entries, no stored token
  ([#57](https://github.com/anivar/decern/issues/57)).
- **Verify a release without trusting us** — one script that checks signatures and
  provenance ([#62](https://github.com/anivar/decern/issues/62)).
- **Reproducible builds, or the honest reason why not**
  ([#65](https://github.com/anivar/decern/issues/65)).

## Later — adoption and ecosystem hardening

- **Mission APIs in the client SDKs** — the clients cover the evaluation endpoint; the
  Mission lifecycle is not exposed yet ([#64](https://github.com/anivar/decern/issues/64)).
- **A worked example for each thing decern can prove**
  ([#66](https://github.com/anivar/decern/issues/66)).
- **Authority-graph export** — DOT and Mermaid renderings of the directory; the
  blast-radius half shipped, the export half remains
  ([#91](https://github.com/anivar/decern/issues/91)).
- **Richer AuthZEN conformance** — metadata discovery
  ([#92](https://github.com/anivar/decern/issues/92)) and broader request/response
  coverage; align Mission "not yet decidable" with AuthZEN's pending-approval patterns
  without forking the API.
- **Identity admit** — the verified caller is now *recorded* (`asserted_by`); *admitting*
  token-exchange claims (`sub` + `act`) into subject and sponsor, so an externally issued
  agent identity is not body-spoofable, is the open half.
- **Additional ledger head-store backends** — new implementations behind the same
  `LedgerHeadStore` trait (no issue yet; propose one).
- **Portable delegation ceiling (watch)** — if a cross-vendor agent-credential chain
  stabilizes, consume it as an upstream authority ceiling beneath the local Mission and
  policy, rather than reimplementing credential issuance inside the PDP.
- **Production evidence** — publish reproducible deployment profiles and, with permission,
  name independent adopters in [ADOPTERS.md](ADOPTERS.md). Adoption is evidence, never
  inferred from stars, integrations, or affiliated demonstrations.

## Explicit non-goals

- Building another MCP firewall, model gateway, or Slack/mobile approval product.
- Putting OAuth / IdP / vendor credential vaults inside `decern-serve`.
- Dropping SMT proofs or negative controls to chase gateway feature parity.

Want to pick one up? See [ARCHITECTURE.md](ARCHITECTURE.md#where-to-start-contributing) and the
[`help wanted`](https://github.com/anivar/decern/labels/help%20wanted) issues.
