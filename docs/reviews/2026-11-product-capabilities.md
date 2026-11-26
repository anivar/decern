<!-- SPDX-License-Identifier: Apache-2.0 -->
# Product capabilities and gap analysis — November 2026

Reviewer: independent external review (commit 21adf1f, 2026-11-26)

---

## What decern is

decern is a deterministic authorization decision point that records. It answers one question
— "may this principal do this action on this resource, right now?" — and writes the answer
to a signed, hash-chained ledger before returning it. The answer is never served without the
record. The model's safety invariants are machine-checked over the whole symbolic input space
by an SMT solver, not tested on examples.

It is not an enforcement point, an identity provider, a credential vault, an approval UI, or
a gateway. It decides and records; enforcement is someone else's job.

## Who would adopt it

1. **Agent infrastructure teams** that deploy LLM agents with tool-calling authority and need
   an auditable decision point between the agent and the tools. The MCP and Substrate
   integrations target this directly.
2. **Platform teams** that want a Cedar-based PDP with a tamper-evident audit trail, where
   "who decided what, and can anyone check?" matters more than sub-millisecond latency.
3. **Compliance-sensitive B2B SaaS** that needs provable tenant isolation, consent gates on
   PII, and human-approval gates on high-risk actions, with a verifiable record.
4. **Security researchers and auditors** drawn to the SMT-proven invariant model: a decision
   point whose safety properties are stated precisely and machine-checked.

Unlikely adopters today: teams needing sub-millisecond decisions (the fsync-per-decision
single-file backend is the bottleneck), teams whose authorization model does not map to
Cedar's principal/action/resource triple, or teams that need a hosted SaaS PDP.

---

## Capability map

### CLI (`decern`)

| Command | What it does |
|---|---|
| `decern prove` | Discharges 9 safety invariants over the Cedar model's whole symbolic input space via cvc5. Negative controls per invariant. |
| `decern decide` | One offline decision against the model, without a server or ledger. |
| `decern verify` | Verifies a ledger's hash chain and every Ed25519 signature. Supports `--anchor` for tree-head-based tamper detection. Single-file, segmented, and sharded ledgers. |
| `decern explain` | Reads one recorded decision back as prose or JSON, with chain and signature verification. |

### PDP server (`decern-serve`)

**Core decision surface (AuthZEN 1.0):**
- `POST /access/v1/evaluation` — single decision (AuthZEN §6.1)
- `POST /access/v1/evaluations` — batch decisions with short-circuit semantics (AuthZEN §7)
- `POST /access/v1/search/{subject,resource,action}` — search endpoints (AuthZEN §8)
- `GET /.well-known/authzen-configuration` — PDP metadata discovery

**Mission lifecycle (approval-backed authority):**
- `POST /mission/v1/approve` — human-approved, scoped, time-bounded authorization grant
- `GET /mission/v1/{s256}` — mission state query
- `POST /mission/v1/{s256}/terminate` — irrevocable termination

**Audit and verification:**
- `GET /pubkey` — signing key(s) for offline verification
- `GET /anchor/v1/tree-head` — signed RFC 9162 Merkle tree head
- `GET /audit/v1/subject?handle=<h>` — subject-side audit with inclusion proofs
- `GET /.well-known/decern-subject-side-disclosure` — challenge/caller posture disclosure
- `GET /directory/v1/principals/{id}/descendants` — delegation blast-radius preview

**Caller postures (5, mutually exclusive):**
1. **Bearer** (`--bearer-issuer`) — RFC 9068 access token, EdDSA only
2. **Signed request** (`--signed-agent-key`) — RFC 9421 HTTP message signature + RFC 7800 `cnf`
3. **SPIFFE** (`--spiffe-trust-domain`) — JWT-SVID against pinned trust bundles
4. **AAuth** (`--aauth-provider`) — draft-hardt-oauth-aauth-protocol agent tokens
5. **Trusted proxy** (`--trust-proxy`) — authentication delegated to a front

**Ledger backends:**
- Single-file JSONL (default, one writer, `flock`)
- Segmented directory (automatic rollover by size/time/epoch)
- Sharded directory (`flock` head store, per-tenant isolation)
- Sharded Postgres (multi-host, `--features postgres`, advisory locks)

### Cedar model (builtin)

- One principal type for humans, agents, and machines (`kind` attribute)
- Delegation chains with transitive attenuation (scopes, expiry, roles, jurisdictions)
- 4 permits: `P-read`, `P-move`, `P-pii`, `P-rebac` (Zanzibar-style viewer relations)
- 7 forbids: `F-revoked`, `F-residency`, `F-role`, `F-tenant`, `F-decay`, `F-money`, `F-consent`
- 9 SMT-proven invariants with negative controls
- CIAM v3: organizations, roles, data residency, consent gates

### Integration adapters (examples)

| Adapter | Integration point | Mode |
|---|---|---|
| `examples/mcp/` | MCP tool server (Python) | In-process: per-tool-call AuthZEN evaluation |
| `examples/ext_authz_adapter/` | HTTP forward-auth (NGINX, Traefik, HAProxy, Envoy) | Gateway sidecar: translates auth_request to AuthZEN |
| `examples/substrate_egress_extproc/` | Agent Substrate egress (Envoy ext_proc) | Egress sidecar: enforce or record mode |
| `examples/signed-request/` | Direct agent integration | Agent signs every request with its key |
| `examples/spiffe/` | SPIFFE mesh | JWT-SVID caller establishment |
| `examples/aauth/` | AAuth agent protocol | Agent token + request signature |

### Client SDKs

| SDK | Package | Dependencies |
|---|---|---|
| Python | `decern` (PyPI) | stdlib only, Python >= 3.11 |
| Go | `github.com/anivar/decern/sdks/go` | stdlib only |
| TypeScript | `decern` (npm) | zero deps, global `fetch`, Node >= 24 |

All three cover: `evaluate`, `evaluations` (batch), `search_{subjects,resources,actions}`,
`verify`, `explain`, and mission lifecycle (`approve`, `get_mission`, `terminate`).

---

## Capability gaps versus what an adopter needs

Ranked by impact on adoption. Comparisons are with OPA/Rego, Cedar/AVP, OpenFGA, and the
AuthZEN 1.0 specification.

### Gap 1 — `scope_for_action` is a code-level allowlist (P0, issue #378)

The mapping from Cedar actions to Mission scopes is a 3-entry `match` in Rust. An action
added to the model but not to this function has no scope mapping; without
`--require-mission`, the action proceeds with no Mission check and caller-supplied
approval flags ride through unsupervised. OPA and Cedar/AVP have no equivalent gap because
their scope/permission models are defined entirely in policy, not in host code.

**Impact:** a custom model with actions beyond the builtin three quietly degrades the
Mission guarantee. This is the single most important fix for adoption.

### Gap 2 — No fuzz testing on the JSON parsing surface

`DecideReq`, `BatchReq`, entity refs, and the JOSE/JWK parsers process attacker-controlled
JSON. OPA, Cedar, and OpenFGA all have fuzz targets in their CI. decern has none.

**Impact:** a panic or logic error in parsing could be a denial-of-service or, worse, a
fail-open path.

### Gap 3 — No doc-tests or runnable examples on public API types

`decern-kernel`, `decern-ledger`, and `decern-identity` export public types with no
`/// # Examples` blocks. Cedar, OPA, and OpenFGA all ship rich API examples. An integrator
reading docs.rs today sees type signatures and module docs but no runnable code.

**Impact:** adoption friction for Rust integrators who want to embed the kernel or ledger
directly.

### Gap 4 — No decision receipts returned to the caller

decern records every decision but does not return a receipt (a signed reference or
inclusion proof) in the evaluation response. The AuthZEN 1.0 spec does not require this,
but the roadmap (ROADMAP.md phases 2-3) names it as the core of the next design line:
"a signed receipt with every decision." Today an adopter can verify the ledger offline
(`decern verify`) but cannot prove to a third party that a specific decision was made
without access to the ledger file.

OPA and Cedar/AVP do not return receipts either, but SCITT (RFC 9535) and the decern
roadmap itself identify this as the differentiating capability. The gap is acknowledged
and planned; it is not missing by oversight.

### Gap 5 — No real-time revocation or policy reload

Revoking a principal or changing the authority graph requires restarting `decern-serve`
with a new model. OPA supports bundle-based policy reload; Cedar/AVP supports live policy
updates; OpenFGA supports live tuple writes. decern's model is loaded once at boot.

**Impact:** an operator who needs to revoke a compromised agent must restart the PDP,
which interrupts all in-flight decisions. The roadmap (phase 4) plans "revocations as
entries" but this is not yet implemented.

### Gap 6 — No OpenTelemetry or structured observability

`decern-serve` logs to stdout/stderr with no structured format, no trace context
propagation, and no metrics endpoint. OPA ships a Prometheus endpoint and OpenTelemetry
integration. An operator today has the healthz endpoint and the ledger; there is no way
to monitor decision latency, error rates, or queue depth in real time.

### Gap 7 — Single-writer bottleneck on the default backend

The single-file ledger fsyncs per decision (or per batch). Under sustained load this is
the throughput ceiling. The sharded backend parallelizes across tenants, and the Postgres
backend parallelizes across hosts, but neither is the default. An adopter evaluating
decern with the quickstart hits the single-file backend and may conclude the system is
slower than it is.

### Gap 8 — No hosted or managed deployment option

Every comparable system has a hosted option: OPA has Styra DAS, Cedar has Amazon Verified
Permissions, OpenFGA has Okta FGA. decern is self-hosted only. The roadmap does not
include a hosted offering.

---

## Comparison summary

| Capability | decern 0.7 | OPA/Rego | Cedar/AVP | OpenFGA | AuthZEN 1.0 spec |
|---|---|---|---|---|---|
| Policy language | Cedar | Rego | Cedar | DSL (Zanzibar) | n/a (wire format) |
| SMT-proven invariants | 9 invariants | no | no | no | n/a |
| Tamper-evident ledger | yes (Ed25519 chain) | no | no | no | not specified |
| AuthZEN evaluation API | yes (§6.1, §7, §8) | no (REST, not AuthZEN) | no | no | defines it |
| Batch evaluation | yes (§7, 3 semantics) | no | no | yes (check) | defines it |
| Search endpoints | yes (§8, all 3) | no | no | yes (list) | defines it |
| Decision receipts | not yet (roadmap) | no | no | no | not specified |
| Live policy reload | no (restart) | yes (bundles) | yes (API) | yes (API) | n/a |
| Caller postures | 5 | 1 (bearer) | 1 (IAM) | 1 (API key) | n/a |
| Client SDKs | Python, Go, TS | many | Java, Rust | many | n/a |
| Hosted option | no | Styra DAS | AVP | Okta FGA | n/a |
| Fuzz testing | no | yes | yes | yes | n/a |
| Doc-test examples | no | yes | yes | yes | n/a |

---

## Prioritized fix/improvement list

1. **scope_for_action fail-closed** (Gap 1, P0) — make unmapped actions deny under a Mission
   instead of silently skipping the scope check. Issue #378.
2. **Fuzz targets** (Gap 2) — `cargo-fuzz` targets for `DecideReq`, `BatchReq`, and entity
   ref parsing.
3. **Doc-test examples** (Gap 3) — runnable `/// # Examples` on `Kernel::new`, `Kernel::check`,
   `CheckResponse`, `Ledger`, `Entry`.
4. **Decision receipts** (Gap 4) — the roadmap's core differentiator; phased work, not a
   single PR.
5. **Structured logging / metrics** (Gap 6) — a tracing subscriber and a `/metrics` endpoint.
