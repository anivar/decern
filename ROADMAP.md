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
  approval flags; Mission ref and the digests it was bound to on the Entry.
- **Anchoring** — a signed tree head over HTTP, and `decern verify --anchor`, so a record dropped
  after it was committed is detectable by someone who is not the operator.
- **Decision-subject column** — the party a decision is taken *upon*, distinct from who asked and
  from the accountable owner, carried as a pseudonymous handle and never reaching the decision.
  Implements [draft-aravind-oauth-decision-subject-00](https://datatracker.ietf.org/doc/draft-aravind-oauth-decision-subject/).
- **A subject-side challenge surface** — the party a decision was about can register a signed
  challenge; it is stripped from the context before the kernel runs, answered afterwards, and the
  answer and its reason recorded. What a deployment supports is published at
  `/.well-known/decern-subject-side-disclosure`.
- **What was decided about one party** — `GET /audit/v1/subject`, each decision with an inclusion
  proof against the returned head. Bounded, and it says when it truncates.
- **`decern explain`** — a faithful reading of one recorded decision, chain verified first.
- **Revocation blast radius** — who else loses authority if this principal is revoked.
- **Portable digests** — an entry binds named digests, and numbers canonicalize as RFC 8785
  §3.2.2.3 requires, so a digest is reproducible by any conformant implementation rather than only
  by decern.
- **Strict signature verification** — small-order public keys are rejected on every path, so a key
  supplied by the party being audited cannot make an arbitrary log verify.
- **Releases anyone can check** — signed binaries with a CycloneDX SBOM, an archived DOI per
  release, and SDKs published from CI with no stored credential.
- **Caller verification** — `decern-serve` validates RFC 9068 access tokens on the deciding
  routes (issuer, audience per RFC 8707, expiry, optional scopes), or accepts a declared
  authenticating front with `--trust-proxy`; a server with neither refuses to start. Caller-only
  by design: the AuthZEN subject is deliberately not taken from the token's `sub`.

## Next — the secure agent-action path

- **A worked MCP integration** — an MCP server that consults decern before it runs a tool, with the
  decision recorded and verifiable afterwards. MCP's own specification says the protocol cannot
  enforce its security principles; this is what filling that gap looks like, as an example rather
  than a product ([#46](https://github.com/anivar/decern/issues/46)).
- **Enforcement adapter** — a generic forward-auth shim so any gateway can call the PDP and fail
  closed ([#6](https://github.com/anivar/decern/issues/6)).
- **Default money path behind Mission** — require a Mission for MoveMoney without the opt-in flag
  (read-only default, mutation gated).

## After that — interoperability and operator tooling

- **Authority-graph export** — DOT and Mermaid renderings of the directory
  ([#2](https://github.com/anivar/decern/issues/2)).
- **Richer AuthZEN conformance** — broaden request/response coverage; align Mission "not yet
  decidable → human approve" with AuthZEN's pending-approval patterns without forking the API.
- **Identity admit** — accept token-exchange claims (`sub` + `act`) into subject and sponsor so an
  externally issued agent identity is not body-spoofable; optional workload principals later.
- **Real-time revocation + signed kill-switch feed** — runtime overlay plus a poll feed
  ([#3](https://github.com/anivar/decern/issues/3)); a complement to an IdP's own logout, not a
  replacement.

## Later — adoption and ecosystem hardening

- **Mission APIs in the client SDKs** — the Go, Python and TypeScript clients cover the
  evaluation endpoint; the Mission lifecycle is not exposed yet.
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
