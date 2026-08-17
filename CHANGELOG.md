<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-08-17

The first release published to crates.io since 0.2.0. `cargo install decern-cli decern-server`
now installs the server that establishes its own callers: 0.3.0 was tagged, signed and released
on GitHub but never reached the registry, so its caller-authentication work — RFC 9421 signed
requests, SPIFFE JWT-SVIDs, and the bind that stops a workload speaking for anyone else —
arrives here for anyone installing the usual way. See the
[0.3.0 notes](https://github.com/anivar/decern/releases/tag/v0.3.0) for that work and its limits.

### Changed

- **crates.io publishes by OIDC, with no stored token.** The crates authenticate the way
  the PyPI and npm packages already do: the registry mints a credential for the run, and the job
  revokes it at the end. Trust is pinned per crate to this repository, the workflow filename and
  the `crates-io` environment. The 0.2.0 release stopped mid-publish on a token scoped
  `publish-new`, which does not cover new versions of crates that already exist; a minted
  credential cannot fall out of scope, because it does not outlive the run. Authored by @anivar.
- **The diagrams and the website describe the caller postures.** The decision-flow and
  architecture diagrams name every posture, the workload bind and `caller_mismatch`,
  proofs taken over the model rather than the deployment, and `--anchor` rather than the chain
  alone as what detects a dropped tail. Editable SVG sources ship beside the PNGs.
  Authored by @anivar.
- **`AGENTS.md` states the guarantees the gates cannot check.** The `CallerAuth` seam a new
  caller posture must implement rather than route around, the context fields that must never
  reach the kernel, the record-before-serve contract, and the rule that a claim in the
  documentation is part of the product. Authored by @anivar.

### Fixed

- **The compiled-native-code claim is stated identically everywhere.** `AGENTS.md` and
  `decern-store-postgres` described the default binaries as carrying zero compiled-C-FFI
  dependencies. The accurate claim, already stated in `README.md` and `DEPENDENCIES.md`, is that
  the default build pulls no TLS stack, no OpenSSL and no `cmake` — `cedar-policy` → `stacker`
  → `psm` compiles a small assembly routine in every build, the default included.
  Authored by @anivar.
- **The sample records in the README and on the website are reproduced from live runs.** The
  site showed a record carrying no `asserted_by` directly beneath the claim that every record
  carries one; it had been captured under `--trust-proxy`, which records no caller by design.
  The README's record showed `"reasons":["F-money"]` for an input that returns an empty
  `reasons`, because neither the caller nor the resource exists in the builtin model, so the
  denial comes from the Mission requirement instead. Both are replaced with records from 0.3.x
  runs, and the site's `decern verify` line now names the key id of the record above it.
  Authored by @anivar.

### Known limits in this release

Unchanged from 0.3.0. This release alters no decision, ledger or caller-authentication
behaviour; the standing set — consent, log pinning, `--trust-proxy`, replay, standing tokens,
and what the proofs actually cover — is listed in the
[0.3.0 notes](https://github.com/anivar/decern/blob/main/CHANGELOG.md#030---2026-08-15) and
applies verbatim.

## [0.3.0] - 2026-08-15

### Added

- **Adapter supply-chain gate and house-voice README.** `examples/ext_authz_adapter` gains a
  `cargo deny` supply-chain check step in its CI workflow (`.github/workflows/ext-authz-adapter.yml`)
  and brings its documentation into decern's house voice. Authored by @sameer-kireap.
- **The record says who asserted the request.** Under any credential posture a decision
  carries `asserted_by` — the caller's subject, client and issuer, exactly as the server
  verified them — so a hardened deployment's log reads "the gateway asked about alice",
  not only "alice". Absent under `--trust-proxy`: an assertion the server did not verify
  itself does not belong on a permanent record. Never a decision input, and
  `decern explain` prints it. Authored by @anivar.
- **`asserted_by` on Mission lifecycle records.** Under any credential posture, `Mission.Approve` and `Mission.Terminate` ledger records now record the verified caller identity (`asserted_by`). Absent under `--trust-proxy`. Forged `context.asserted_by` values supplied in request bodies are stripped across all endpoints before recording. Authored by @sameer-kireap.
- **`decern-serve` can validate the access token itself.** `--bearer-issuer`,
  `--bearer-audience` and `--bearer-issuer-key` (repeatable) make the deciding and
  mission-lifecycle routes require an RFC 9068 `at+jwt` bearer token: EdDSA over an
  operator-configured key, issuer matched exactly, audience containing this server per
  RFC 8707 §2, all required claims present. `--bearer-scope` (repeatable) additionally
  requires scopes, refusing a verified token without them as `403 insufficient_scope`.
  Absent or invalid tokens get `401`; every refusal carries an RFC 6750 challenge.
  Verification is signature-checking against configured keys, never fetching, so the
  default build still carries no TLS stack. The subject-side routes — the anchor, the
  disclosure, `/audit/v1/subject` — stay open by intent, and the disclosure now reports
  how callers are established. Authored by @anivar.
- **An ext_authz HTTP enforcement adapter.** `examples/ext_authz_adapter` is a generic,
  standalone HTTP external authorization shim for `decern-serve`. Translates incoming HTTP
  gateway requests carrying forwarded headers into AuthZEN evaluations, failing closed with
  403 on policy deny or any missing forwarded header, and 503 on PDP error, timeout, unreachable PDP,
  or malformed response. Authored by @sameer-kireap.
- **A worked MCP integration** under `examples/mcp/`: an MCP server (spec revision
  2026-07-28, no SDK) that validates its client's access token and consults
  `POST /access/v1/evaluation` before every tool call — subject from the token, the
  exact arguments digest-bound onto the record. A Deny a fresh grant could satisfy is
  `403 insufficient_scope` with a challenge that actually works on retry; a Deny no
  re-authorization can fix is a tool result with `isError`. The walkthrough proves the
  nine invariants over the example's own model and ends by recomputing the argument
  digest from the arguments and finding it on the verified ledger. Authored by @anivar.
- **A direct test for the `asserted_by` context strip.** `mission_entry` already stripped
  a caller-supplied `context.asserted_by` before recording, but no test called it with
  one — there is no live path through `mission_approve`/`mission_terminate` today that
  reaches it. `mission_entry_strips_a_context_supplied_asserted_by` calls the function
  directly to prove the defense-in-depth fires, so a future change that makes the path
  reachable does not silently lose the guarantee.
- **`@id` annotations name policies in decision reasons.** A model that annotates a
  policy with `@id("F-money")` gets that name in `reasons` and in `decern explain`,
  instead of a position that shifts when a policy is added; duplicate names refuse to
  load. A model without annotations keeps the positional ids it always had — the
  builtin model is unchanged. Authored by @anivar.
- **Every SDK client can send a bearer token.** An optional token on the Go, Python and
  TypeScript clients, sent as `Authorization: Bearer` on every request when set and
  absent entirely when not — for a deployment that requires access tokens on the
  evaluation endpoint. The client carries a token the application already holds;
  acquiring one stays the issuer's business. Authored by @anivar.
- **A runnable walkthrough for sender-constrained callers.**
  `examples/signed-request/` serves the proven builtin model to a caller that must prove
  possession of a configured key on every request, and shows the property a bearer
  credential cannot give: the *same* token, byte-identical and unexpired, is refused when
  the RFC 9421 signature comes from a different key. Also covers refusal for signature
  age alone, refusal when a valid signature is replayed against a different path, the
  deployment disclosing its own caller posture, and the ledger naming the caller the
  server verified via `asserted_by`. Runs in CI. Authored by @anivar.
- **`decern-serve` can require proof of possession on every request, not just a bearer
  token.** `--signed-agent-key` (repeatable, `ID=HEX`) and `--signed-audience` make the
  deciding and mission-lifecycle routes require an RFC 9421 HTTP Message Signature over
  `@method`, `@authority`, `@path` and `signature-key`, bound to an RFC 7800 `cnf.jwk`
  claim matching a key configured here for the claimed agent identifier. Unlike bearer
  validation, a leaked token alone is not enough here: it must also be signed, per
  request, by the key it is bound to. Verification is against configured keys only —
  no live key discovery, no outbound HTTP client — and an agent identifier with no
  configured key is refused before any cryptography runs. One posture per deployment:
  one is required to start, and naming a second is a startup failure. Authored by
  @anivar.
- **`decern-serve` can establish its caller from a SPIFFE JWT-SVID.**
  `--spiffe-trust-domain TRUST_DOMAIN=PATH` (repeatable) and `--spiffe-audience` make the
  deciding and mission-lifecycle routes require a JWT-SVID, presented as a `Bearer`
  credential per JWT-SVID §5.2 and verified against a JWK Set pinned at startup. Trust
  domains are matched exactly, so a domain that merely shares a prefix cannot present as a
  configured one; the bundle is filtered to `use: jwt-svid` keys and refused at boot if it
  carries none, an entry without a `kid`, or a key this build cannot verify with. Bundles
  are configured, never fetched, so this adds no TLS stack and no reliance on a SPIFFE
  control plane being reachable. **`ES256` only** — `RS*`/`PS*` would require a crate
  carrying an unpatched key-recovery advisory, so a SPIRE deployment issuing RSA SVIDs is
  not interoperable, which the docs state rather than soften. A verified `spiffe://…`
  identity is recorded as the caller and never minted into the authority graph: what a
  decision may be *about* is unchanged. `examples/spiffe/` runs the whole posture with no
  SPIRE daemon. Authored by @anivar.
- **The four caller postures are now one clap group.** Naming two at once is a startup
  failure rather than a matrix of `conflicts_with` pairs that has to grow with each
  posture. Authored by @anivar.
- **A SPIFFE caller is a workload, and binds to itself.** Like a signed-request agent, a
  verified `spiffe://…` identity may only name itself as AuthZEN `subject`, mission
  `approver`, stored approver on terminate, and directory principal, unless it is listed
  in `--pep`. A mismatch is `403 caller_mismatch`. Without this the second posture would
  have reopened the escalation the first one closed. Authored by @anivar.
- **The README shows views and clones**, accumulated rather than the fourteen days GitHub keeps
  before discarding them. Authored by @anivar.

### Changed

- **The builtin model names its policies.** Decision reasons and `decern explain` now say
  `P-read` or `F-money` instead of `policy0`-style positions. Records written before this
  change keep the positional ids they were written with — a record is a statement about
  the moment it was made, and renaming it afterwards would be editing history.
  Authored by @anivar.
- **The MCP example serves shipping clients.** Real clients still speak the 2025-06-18
  lifecycle; the example now serves them through the transport spec's own
  backward-compatibility clause — a clearly-marked legacy path that adds no
  authorization surface and is deletable when clients carry per-request metadata.
  Verified end to end with Claude Code as the client: allow, tenant-deny as a tool
  error the model reads, approved money movement, and the insufficient-scope 403 —
  all recorded and verified on the ledger. Authored by @anivar.
- **The TypeScript SDK requires Node 24**, the active LTS line, which is now also the only version
  it is tested against.
- **Both SDK packages carry their source, homepage and issue tracker.** The npm package also
  publishes a signed provenance statement, which the registry validates against `repository.url` —
  so the field is required, not decoration.
- **Number digits come from `ryu-js`**, Ryu adapted to ECMAScript's own rules — which is what
  RFC 8785 §3.2.2.3 defers to, and the generator the maintained JCS crates use. Output is
  unchanged: still byte-identical to V8 across 3.1M doubles. Authored by @anivar.
- **The SDK package pages say what decern does.** Both descriptions opened with "client for the
  decern PDP", which tells a reader who has not heard of decern nothing at all. Each page now
  explains what the server is for, links the website, repository and command reference, and shows
  how to verify a decision after the fact. Authored by @anivar.
- **The SDK package pages lead with working code.** Install and a complete example first,
  the server's story after, on all three clients. Badges now come from our own
  infrastructure, like the main README's. Registry pages update with the next patch
  release of each package. Authored by @anivar.
- **The README badges are served from our own infrastructure** rather than a third party, so
  reading the page no longer makes a request to img.shields.io. Values are live from crates.io,
  npm, PyPI, docs.rs and the Actions API. Authored by @anivar.
- **`decern-serve` refuses to start unless the caller posture is named.** Either the bearer
  flags establish callers here, or `--trust-proxy` states that something in front already
  authenticates them — the proxy deployment every earlier version assumed, now a choice the
  operator writes down. A bind with neither used to warn; a warning is what a startup script
  discards, so it is now a refusal, and the quickstart passes `--trust-proxy` explicitly.
  A standing token whose `typ` is `at+jwt` is also now refused: an access token proves the
  right to call this server, not standing as the party a decision was about.
  Authored by @anivar.

### Fixed

- **The subject-audit projection no longer parses the log under the append lock.** It
  held the same mutex every decision needs while deserializing every record and deriving
  every proof — a way to slow the server's ability to decide. The lock is now held twice,
  briefly: once to copy raw bytes out, once to sign the head; parsing, matching and
  proving happen unlocked, and only matched records are parsed in full.
  Authored by @anivar.
- **The subject-side disclosure names the audit projection the way the route reads it.**
  It advertised `/audit/v1/subject/{handle}` while the route takes `?handle=` — a party
  following the deployment's own pointer got a routing 404 that reads as "no records
  about you". Authored by @anivar.
- **The MCP example mints a Mission for MoveMoney instead of asserting approval.**
  `examples/mcp/server.py` used to relay a verified OAuth scope into
  `context.human_approved` directly. Since MoveMoney now requires a Mission
  unconditionally, that assertion is refused — the example instead calls
  `POST /mission/v1/approve` when the scope is present and names the resulting
  Mission in the decision context, demonstrating the pattern a real PEP should use.
- **`--require-mission` no longer promises server-derived consent.** Its help text said
  client-supplied `human_approved` and `consent` are "derived server-side from the verified
  Mission". Only `human_approved` is, and only for `MoveMoney`; `consent` is stripped and
  never put back, because a Mission is an approver's grant and not the resource owner's
  consent. An operator who turned the flag on *to make consent server-derived* got
  fail-closed on-behalf-of PII access and a contract that was not true. The flag's behaviour
  is unchanged — the text now describes it. Authored by @anivar.
- **The ledger signing key is no longer written world-readable.** `decern-serve --key`
  created the seed file with `std::fs::write`, which uses the process umask — commonly
  `0644`. That key signs every record and every tree head, so a readable copy on a shared
  host was enough to forge history that verifies. The server now routes through
  `decern-crypto`'s existing key discipline: created at `0600`, never overwritten, and a
  key that is group- or other-readable is refused rather than loaded silently, so a file
  opened up by a later `chmod` fails closed. The seed is zeroized on both paths. Existing
  key files keep working unchanged, provided their permissions are not open. Authored by
  @anivar.
- **The TypeScript lockfile carries the package version.** `package-lock.json` had missed
  the 0.2.0 bump; both of its version fields now match `package.json`, and the release
  checklist names the lockfile so it cannot be missed again. Authored by @anivar.

### Security

- **Agent Badge verification uses `verify_strict`.** The path that admits a principal
  into the authority graph now rejects small-order keys and non-canonical signatures,
  matching the ledger and the caller postures. A badge that only passed the cofactorless
  equation is refused. Authored by @anivar.
- **The ledger is no longer world-readable.** It was created at the process umask —
  commonly `0644` — while the signing key and the mission registry beside it are `0600`,
  which made the audit log the readable one of the three. It holds decision subjects and
  the pseudonymous handles the subject-side audit route is keyed by. Now `0600` on
  creation, and an existing ledger is tightened when it is next opened rather than left
  readable forever. Sealed segments go from `0444` to `0400` for the same reason. Unlike
  the signing key, a group- or other-readable ledger is tightened rather than refused:
  failing an existing deployment's next append would be worse than fixing it in place.
  Authored by @anivar.
- **The Envoy `ext_authz` snippet no longer forwards a client-supplied subject header.**
  `allowed_headers` forwards whatever is on the request, so the documented config passed a
  client's own `x-forwarded-subject` straight to the adapter — the exact bypass the README
  warns about, in the README. The NGINX example overwrites the header and the Traefik one
  sets `trustForwardHeader: false`; the Envoy one now strips it and says why filter
  ordering has to be checked. Authored by @anivar.
- **A Mission is not a data subject's consent.** `POST /access/v1/evaluation` no longer
  sets `context.consent = true` when a live Mission covers `AccessPII`. The grant is an
  approver's `pii:read`; F-consent is a claim about the resource owner, and the two are
  not the same. Client-supplied `consent` is still stripped under a Mission, so OBO PII
  access requires a consent signal that did not come from the grant. Self-access is
  unchanged: the owner does not need consent. Authored by @anivar.
- **MoveMoney now requires a Mission unconditionally.** Previously, a request naming
  `context.human_approved: true` directly could move money whenever an operator had not
  turned on `--require-mission` — the flag only made the *server*-derived guarantee apply
  to every action; MoveMoney itself had no floor beneath it. `decern-serve` now denies any
  MoveMoney decision that does not name a live, verified Mission, regardless of
  `--require-mission`. Read and AccessPII keep the existing opt-in behavior.
  **Migration:** a deployment gating money through its own PEP by asserting
  `human_approved` in the request body, without using Missions, must switch to approving a
  Mission (`POST /mission/v1/approve`) and naming it in `context.mission` before this
  upgrade — the old body assertion is now denied rather than honored.
- **Signed-request callers may only name themselves.** Under `--signed-agent-key`, the
  authenticated agent must equal the AuthZEN `subject`, the mission `approver`, the
  stored approver on terminate, and the principal id on
  `/directory/v1/principals/{id}/descendants`. A mismatch is 403 `caller_mismatch` —
  the credential was accepted; the name is not theirs. `--pep <ID>` (repeatable) names
  agents that remain PEPs. Bearer validation and `--trust-proxy` are unchanged: those
  postures authenticate a gateway, which legitimately asks about other parties.
  Authored by @anivar.
- **Signed POST requests now cover the body.** `--signed-agent-key` requires
  `Content-Digest` (RFC 9530, `sha-256` only) as a fifth covered component on POST,
  verified against the bytes the handler will see. A captured signature over one JSON
  body cannot authorize a different one at the same path. GET is unchanged: it has no
  body to cover. Verbatim replay of the same path and body is still accepted within
  the freshness window — there is no nonce cache. Authored by @anivar.

### Known limits in this release

Stated here rather than left to be discovered, because the project's claim is that it is
checkable. None of these is a regression; all are the honest state of 0.3.0.

- **Consent has no server-side signal.** On the default path a request body's `consent` is
  still honoured, the same shape that was closed for money and not for personal data. With
  `--require-mission`, on-behalf-of access to PII fails closed rather than becoming
  server-derived — a Mission is an approver's grant, not the data subject's consent.
- **The running server does not pin the log it extends.** `decern verify --anchor`, against
  a tree head you published somewhere the operator does not control, is what detects a
  dropped tail. The append path loads no commitment, and `--anchor` is not available for
  `--sharded`. A chain alone proves internal consistency, not completeness.
- **`--trust-proxy` is a complete PDP to anyone who can reach the port.** It is a statement
  about your topology, not a mode. The quickstart uses it; the quickstart is not a
  production posture.
- **A bearer token issued to a workload is a PEP credential.** Only the signed-request and
  SPIFFE postures bind a caller to the principals it may name. Bearer and `--trust-proxy`
  deliberately do not.
- **SPIFFE is `ES256` only.** `RS*`/`PS*` need a crate carrying an unpatched key-recovery
  advisory that this project's supply-chain gate refuses, so an RSA-signed SVID will not
  verify ([#117](https://github.com/anivar/decern/issues/117)).
- **Replay of a captured credential is not prevented.** A signed request verifies again
  inside its freshness window; a bearer or SPIFFE token until it expires. There is no nonce
  cache, and a decision is not idempotent — a replayed allow records again.
- **Standing tokens are the weakest JOSE path.** Unlike bearer and SPIFFE they do not
  require a `typ`, do not refuse `crit`, do not gate `nbf`, and do not close the header set.
  They cannot change a decision — a challenge is stripped before the kernel runs — but a
  forged or early one can write a false challenge answer onto the record.
- **`ReevaluateWithSubjectContext` is a label, not a re-evaluation.** The kernel is not run
  a second time and the context is not changed; the outcome classifies the basis of a
  challenge. The decision bit is the original one.
- **The proofs cover the model, not the server.** Nine invariants, discharged as policy
  subsumption over the model's symbolic input space, with two reasoning over attributes the
  kernel derives in Rust before the prover runs. They do not see a deployment's
  `entities.json`, the clock, the HTTP layer, the Mission lifecycle, or caller binding. See
  [What "proven" covers](docs/CLI.md#what-proven-covers).

## [0.2.0] - 2026-08-08

### Added

- **The authority a decision was taken against, on the record.** Every decision recorded by the PDP
  carries `DIGEST_AUTHORITY` — the policy, schema and entity graph as they stood. The chain shows a
  record was not altered; this shows what it was decided against, so a later reading can tell
  whether that authority is still in force. Computed once at load.
- **Anchoring.** `decern-serve` publishes a signed RFC 9162 tree head at `GET /anchor/v1/tree-head`;
  `decern verify --anchor <file>` proves the log still extends a commitment published earlier, so a
  record dropped after it was committed is detectable by someone who is not the operator.
- **`GET /audit/v1/subject?handle=<h>`** — the decisions recorded about one party, each with an
  inclusion proof against the returned head. Bounded, and says when it truncates.
- **The decision subject, as a pseudonymous handle.** A decision records whom it was taken *upon* —
  distinct from who asked for it, and from the accountable owner who stands behind it: a `handle`,
  an optional `scheme` naming where it could be resolved, and an optional `purpose` that keeps one
  party from being linked across contexts. Resolving a handle to a person is left to whoever holds
  that authority. This implements `draft-aravind-oauth-decision-subject-00`.
- **A subject-side challenge surface.** The party a decision was about can register a signed
  challenge; it is removed from the context before the kernel runs, answered afterwards, and the
  answer and its reason are recorded. Standing tokens are verified against issuer keys configured
  with `--standing-issuer-key`. What a deployment supports is at
  `GET /.well-known/decern-subject-side-disclosure`.
- **`decern explain`** — a faithful reading of one recorded decision, chain verified first.
- **Revocation blast radius** — `Directory::descendants_of` and
  `GET /directory/v1/principals/{id}/descendants`.
- **[docs/CLI.md](docs/CLI.md)** — a command reference for both binaries.
- **A Go client SDK** — `go get github.com/anivar/decern/sdks/go`, alongside the Python and
  TypeScript clients. Authored by @sivasanjeevs.
- **A failed SDK call carries the HTTP status and response body** on `DecernError`, so a caller can
  tell a denial from a misconfigured endpoint without reading the server's logs.
  Authored by @sameer-kireap.
- SDK clients cap the error-body read at 64 KiB and report truncation. Authored by @vjymisal0.

### Changed

- **Digests are recorded by name.** `Entry::digests` maps a name to a digest, so a consumer of
  `decern-ledger` records what its own decisions depend on under names it chooses without a schema
  change here, and a reader who does not recognise a name still sees that something was pinned and
  whether it matches. `DIGEST_PARAMETERS` holds the arguments a decision authorized; `decern-serve`
  adds `DIGEST_AUTHORITY`. Ordered, because the map sits inside the bytes the hash chain covers.
  The digest itself is `jcs::digest`.
- **Numbers canonicalize as RFC 8785 §3.2.2.3 requires, so a digest is reproducible by anyone.**
  §3.2.2.3 defines a JSON number as an IEEE-754 double serialized the way ECMAScript prints it:
  `3` rather than `3.0`, `100000000000000000000` rather than `1e20`, `0.000001` rather than `1e-6`.
  A digest over a value carrying such a number agrees with one computed by any other conformant
  implementation, and `3` and `3.0` — the same double — digest alike. Verified against V8 across
  3.1M doubles. An integer outside the interoperable range of ±(2^53−1) keeps every digit rather
  than rounding to the nearest double, so two distinct ids can never share a digest. The hash chain
  does not canonicalize: it commits to each entry's exact stored bytes.

### Fixed

- **The subject projection is bounded.** `GET /audit/v1/subject` stops at a fixed number of
  decisions and reports that through a `truncated` flag, rather than holding the lock an append
  needs while it reads an unbounded log.

### Security

- **A public key can no longer verify a signature nobody made.** RFC 8032 §5.1.7 permits the
  cofactorless verification equation, and against a small-order public key one signature satisfies
  it for every message — so a key supplied by the party being audited could make any log verify.
  Records, checkpoints, tree heads and the offline evidence-bundle check all use the strict check,
  which rejects small-order keys and non-canonical encodings.

## [0.1.1] - 2026-08-02

### Fixed

- **Mission: a terminated grant could revive to Active after its own expiry.** The registry evicted the
  terminated tombstone at expiry and `approve()` had no future-expiry guard, so re-approving an
  identical lapsed grant returned Active. Fixed at both layers — `approve()` refuses an already-expired
  mission, and the store retains terminated tombstones past expiry and is self-monotone (refuses
  re-registering an expired entry). A registry-layer enforcement bug found by the pre-release audit;
  the proven kernel (`decay` et al.) and the tamper-evident ledger were unaffected and would have
  recorded the transition. (#7, #8)

### Changed

- Honesty corrections from the pre-release audit: the transitive-closure derivation is covered by
  re-derivation **unit** tests (not "property tests"); the default build is not zero-compiled-native
  (cedar → stacker → psm compiles an assembly routine via `cc`), corrected in the README and on the
  site; and `decern verify` now prints a prominent notice when run without `--pubkey`, since a
  chain-only pass is not a full verify. (#9, #10)

## [0.1.0] - 2026-08-02

Initial release.

### Added

- Deterministic authorization kernel with **9 SMT invariants** (money-gate, isolation, decay,
  attenuation-edge, scope-gate, revocation-gate, residency-gate, role-gate, consent-gate)
  discharged over the entire input space by cvc5.
- Proven delegation attenuation.
- Append-only, Ed25519-signed, hash-chained tamper-evident decision ledger.
- Derived **accountable-owner** column on decisions recorded by the PDP: the root of the subject's
  delegation chain, resolved server-side from the directory (never a request input) — a recorded
  accountability column, not a decision gate.
- `decern` CLI: `prove`, `decide`, `verify`.
- `decern-serve` PDP: AuthZEN 1.0 Access Evaluation `POST /access/v1/evaluation` (with `/decide`
  as an alias) — request `{subject, action:{name}, resource, context}`, response `{decision}` with
  any reasons (allow) or errors (deny) under `context`; plus `GET /pubkey`, `GET /healthz`.
  Fail-closed (a decision whose audit record cannot be written returns 503, never the Allow).
- `decern-serve` Mission-lifecycle service over `decern-identity`: `POST /mission/v1/approve`,
  `GET /mission/v1/{s256}`, `POST /mission/v1/{s256}/terminate`. An approver grants an agent a scoped,
  fail-closed-attenuated Mission (an approved tool the approver does not hold, or an expiry beyond
  theirs, is refused and nothing is recorded); each accepted transition is recorded to the
  tamper-evident ledger and is not reported as succeeded unless that record was written; a terminated
  Mission never revives. Backed by the durable `MissionRegistry` (`--missions <PATH>`, default
  `decern-missions.json` alongside the ledger).
- `decern-serve --sharded <dir>` hosted mode: several server processes on one host share one
  tamper-evident ledger (one hash chain per tenant) via a `flock` file head store; each decision is
  recorded to its subject's tenant shard. Mutually exclusive with `--ledger`.
- Multi-host sharded mode: `--sharded` also accepts a `postgres://` URL (Postgres advisory-lock head
  store, `decern-store-postgres`) when `decern-serve` is built with `--features postgres`. Off by
  default, so the shipped binary stays pure Rust; the postgres URL is never echoed in logs.
- `examples/quickstart.sh`: prove -> serve -> decide -> verify -> tamper-fails.
- Pure Rust, zero compiled-C-FFI dependencies; toolchain pinned via `rust-toolchain.toml`.
