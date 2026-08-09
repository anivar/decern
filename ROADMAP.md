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
- **A worked MCP integration** — `examples/mcp/`: an MCP server (revision 2026-07-28, no SDK)
  that validates its caller and consults the PDP before every tool call, arguments digest-bound
  onto the record; denials surface as a satisfiable `403 insufficient_scope` or an `isError`
  tool result, per the spec's own error layering.
- **Caller verification** — `decern-serve` validates RFC 9068 access tokens on the deciding
  routes (issuer, audience per RFC 8707, expiry, optional scopes), or accepts a declared
  authenticating front with `--trust-proxy`; a server with neither refuses to start. Caller-only
  by design: the AuthZEN subject is deliberately not taken from the token's `sub`.
- **The asserting caller on the record** — under bearer validation a decision carries
  `asserted_by` (token subject, client, issuer, as verified); absent under a trusted front,
  where the server verified nothing itself. Recorded, never a decision input.
- **Named policy reasons** — the builtin model annotates every policy, so a denial says
  `F-money` in `reasons` and in `decern explain`, not a position that shifts.
- **A worked MCP integration** — `examples/mcp/`: an MCP server (stateless revision, no SDK)
  that validates its caller and consults the PDP before every tool call, arguments
  digest-bound onto the record; serves earlier-revision clients through the spec's own
  backward-compatibility clause, and has run its whole allow/deny/step-up matrix end to end
  with Claude Code as the client.
- **An enforcement adapter** — `examples/ext_authz_adapter/`: a generic forward-auth shim
  (NGINX `auth_request`, Traefik `forwardAuth`, Envoy `ext_authz`) that fails closed on
  deny, missing forwarded headers, or an unreachable PDP. Contributed by @sameer-kireap.
- **Bearer tokens in every SDK** — the Go, Python and TypeScript clients can present an
  access token, absent entirely when unconfigured.

## Next — the accountable-operations path

Close the loop from decided to enforced to revocable to accountable.

- **Record who asserted a mission transition** — Mission.Approve creates live authority
  while `approver` is a body field; the verified caller belongs on that record exactly as
  it now sits on decisions ([#87](https://github.com/anivar/decern/issues/87)).
- **Approval derived at the decision point by default** — `human_approved` from the request
  body is the compatibility posture, not the destination; make the Mission-derived path the
  default and the body flag the opt-in ([#25](https://github.com/anivar/decern/issues/25)).
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
