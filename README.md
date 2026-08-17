<!-- SPDX-License-Identifier: Apache-2.0 -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/decern-mark-dark.svg">
    <img src="docs/img/decern-mark.svg" alt="decern" width="76" height="76">
  </picture>
</p>

# decern

A deterministic authorization kernel whose safety properties are **machine-checked by an
SMT solver over the model's whole symbolic input space**, not just tested on examples —
with a hash-chained, tamper-evident decision ledger anyone can verify without trusting the
operator. What that covers, and what it deliberately does not, is
[stated precisely](docs/CLI.md#what-proven-covers).

<p align="center">
  <a href="https://github.com/anivar/decern/actions/workflows/ci.yml"><img alt="CI" src="https://anivar.net/badge?src=ci&repo=anivar/decern"></a>
  <a href="https://crates.io/crates/decern-cli"><img alt="crates.io" src="https://anivar.net/badge?src=crates&name=decern-cli"></a>
  <a href="https://docs.rs/decern-ledger"><img alt="docs.rs" src="https://anivar.net/badge?src=docsrs&name=decern-ledger"></a>
  <a href="https://pypi.org/project/decern/"><img alt="PyPI" src="https://anivar.net/badge?src=pypi&name=decern"></a>
  <a href="https://www.npmjs.com/package/decern"><img alt="npm" src="https://anivar.net/badge?src=npm&name=decern"></a>
  <a href="LICENSE"><img alt="License" src="https://anivar.net/badge?label=license&value=Apache-2.0"></a>
  <a href="https://doi.org/10.5281/zenodo.21848620"><img alt="DOI" src="https://zenodo.org/badge/1319971099.svg"></a>
  <a href="https://github.com/anivar/decern/graphs/traffic"><img alt="views" src="https://anivar.net/traffic?repo=decern&m=views"></a>
  <a href="https://github.com/anivar/decern/graphs/traffic"><img alt="clones" src="https://anivar.net/traffic?repo=decern&m=clones"></a>
</p>

[Website](https://decern.anivar.net/) · [Commands](docs/CLI.md) · [Roadmap](ROADMAP.md) ·
[Releases](https://github.com/anivar/decern/releases) · [Security](SECURITY.md)

The industry standardizes how authority is *represented* — tokens, delegation envelopes,
decision-request formats — and defers the *guarantee* (that attenuation holds, that nothing
was dropped from the log, that a decision stayed within its mandate) to implementer policy.
decern is the guarantee.

## Quickstart

```sh
cargo install decern-cli decern-server
```

Two binaries: `decern` to prove and verify, `decern-serve` to answer requests. Prebuilt,
signed binaries for Linux (x64/arm64), macOS (Apple Silicon) and Windows (x64) are on the
[releases page](https://github.com/anivar/decern/releases). Only `decern prove` needs the
**cvc5** solver on `PATH`; serving answers does not.

```sh
# 1. Prove every invariant over the model's input space (cvc5)
decern prove

# 2. Run the PDP (writes a tamper-evident ledger); this walkthrough is its own caller
decern-serve --ledger /tmp/decern.jsonl --trust-proxy &

# 3. Decide over HTTP (AuthZEN-shaped) — corp reads a claim it owns
curl -s localhost:8080/access/v1/evaluation -H 'content-type: application/json' -d '{
  "subject":  {"type":"Principal","id":"corp"},
  "action":   {"name":"Read"},
  "resource": {"type":"Resource","id":"claim1"}
}'

# 4. Verify the ledger (hash chain + every signature)
decern verify --ledger /tmp/decern.jsonl \
  --pubkey "$(curl -s localhost:8080/pubkey | jq -r .kid)"
```

[`examples/quickstart.sh`](examples/quickstart.sh) runs the whole loop — prove → serve →
decide → verify → tamper-is-rejected — end to end. Thin AuthZEN 1.0 clients are published
for applications:

```sh
uv add decern                              # Python
npm install decern                         # TypeScript / JavaScript
go get github.com/anivar/decern/sdks/go    # Go
```

## What is proven

A decision is a pure function of `(principal, authority graph, policy, now)` — humans,
agents, and workloads are one principal type, decided by the same function. **9 invariants**
over it are discharged by an SMT solver (cvc5) across the model's entire symbolic input
space, not sampled. Each statement is calibrated to exactly what the solver checks, so a
proof never claims more than the machine verified — two invariants reason over attributes
the kernel derives in Rust before the prover runs, and say so:

- **money-gate** — no privileged money action without explicit approval
- **isolation** — no decision ever crosses a tenant boundary
- **decay** — no decision once authority has expired
- **attenuation-edge** — no access without ownership, a delegation ancestor, or an explicit grant
- **scope-gate** — bounded actions require their scope
- **revocation-gate** — a revoked principal is allowed nothing
- **residency-gate** / **role-gate** / **consent-gate** — data-bound access conditions

## What is recorded

Every decision lands in an append-only, Ed25519-signed, hash-chained ledger, and is served
**only if its record was written** — an unrecordable decision returns 503, never a bare
allow. A crash-torn tail heals; truncating committed history is detected.

<p align="center"><img src="docs/img/decision-flow.png" alt="decern decision flow: one of four postures establishes the caller, the proven kernel evaluates, the decision is recorded to the tamper-evident ledger, and it is served with 200 only when the record was written, else 503; an unestablished caller is refused before evaluation" width="900"></p>

Here a caller in one tenant is refused a `Read` on another's resource — the tenant-isolation
forbid fires by name, the `sponsor` resolves to the principal ultimately answerable, the exact
request is digest-bound, and `prev` is the chain link:

```json
{"entry":{"seq":1,"ts_ms":1786928909000,
          "subject_type":"Principal","subject_id":"corpB",
          "action":"Read","resource_type":"Resource","resource_id":"claim1",
          "context":{"now":1786928909},"decision":false,"reasons":["F-tenant"],
          "sponsor":{"kind":"Principal","id":"corpB"},
          "digests":{"authority":"cb03c58cb1f689cc270f99791138dbd913d25bd50c6ee2f70a41206ad795f9be",
                     "parameters":"7d7d40f9016baf94f82ca2281d46c67fd6cea62d2f8c782c5d34978946c185ed"}},
 "prev":   "252398ebc68779cd1a8c12cdacea6f9bdfa749bdddc665de2b9d2ec010f10725",
 "hash":   "f43ecf0babe9c9e1cc6473bb0ebedda458b27776ddb674dd0a8e42b3ac92ebf2",
 "sig_b64":"Aq2OkDXAHh4S+pbrmJv4YouAk4b5y7MnCmoE/r424YF6tMNnjsywTq0d9U2v4QLeYdbaK1r6evaE8p8HL+nVCg==",
 "kid":    "e94659fb957a66fd5a553211f67a193c7ce2b620f3b4547612c16fba8d56016f"}
```

Beyond the decision itself, a record carries accountability columns. The
**accountable-owner** is the root of the subject's delegation chain, resolved server-side —
a delegate's record names the principal ultimately answerable for it, and none of these columns
ever changes the allow/deny outcome. Under any credential posture, **asserted_by** names the
caller the server verified when it took the request — subject, client, issuer — and is
absent under a trusted front, where the server verified nothing itself. The
**decision subject** is the party a decision is
taken *upon* — a different question from who asked and who answers for it — carried as a
pseudonymous handle per
[`draft-aravind-oauth-decision-subject-00`](https://datatracker.ietf.org/doc/draft-aravind-oauth-decision-subject/).
It is stripped before the kernel runs (who a decision is about cannot change what it is),
recorded only when it adds something, and refused outright when it identifies a person —
this log cannot be edited, so that request is the last moment such a value can be kept out.

### The subject side

A hash chain proves a log holds together, which its writer can always arrange. So the
operator publishes a signed commitment somewhere they do not control (`GET
/anchor/v1/tree-head` — a Merkle root and size, disclosing nothing about what was decided),
and anyone can later check the log still extends it:

```sh
decern verify --ledger /tmp/decern.jsonl --pubkey <kid> --anchor anchor.json
```

A log truncated below its anchored size fails that check while still passing an ordinary
verify: dropping a committed record stops being a rule someone broke and starts being
arithmetic that does not work.

The party a decision was about gets the other direction. `GET /audit/v1/subject?handle=<h>`
returns what was decided about one handle, each record with an inclusion proof — checked
against an anchor obtained separately, because proofs and an unanchored head from the same
source prove only internal consistency. And a party who believes a decision was wrong can
**challenge** it: a signed standing token in the decision context, stripped before the
kernel runs (a forged challenge can neither escalate nor deny), answered afterwards on the
record, with evidence kept as a digest. What a deployment actually supports — including the
outcomes it declines to offer — is at `GET /.well-known/decern-subject-side-disclosure`,
read from its running configuration so the claim cannot drift from the binary.

## Missions

`decern-serve` also serves a **Mission lifecycle**: an approver grants an agent a scoped,
fail-closed-attenuated authorization context — "these tools, until this time." A Mission
exceeding what its approver holds is refused; every accepted transition is recorded before
it is reported; a terminated Mission never revives. The registry is durable and local —
sovereign, consulted in-perimeter, no phone-home.

```
POST /mission/v1/approve            {approver, agent, description, approved_tools, capabilities?, expiry}
GET  /mission/v1/{s256}             -> {reference, state: active|terminated, expiry}
POST /mission/v1/{s256}/terminate   -> {reference, state: terminated}
```

## Deployment

`decern-serve` refuses to start unless told how its callers are established, and naming two
postures is also a startup failure. It validates RFC 9068 bearer tokens (`--bearer-issuer`),
RFC 9421 signed requests (`--signed-agent-key`) or SPIFFE JWT-SVIDs
(`--spiffe-trust-domain`) itself — all against keys configured at startup, never fetched —
or `--trust-proxy` states that something in front already authenticates them. The two
workload postures additionally bind a caller to the principals it may name. Which routes are
guarded, which stay open on purpose, and why is in [docs/CLI.md](docs/CLI.md)'s
trust-boundary section.

Four worked examples ship, all runnable and CI-tested and none published as crates:
[`mcp/`](examples/mcp/) consults decern before every tool call,
[`ext_authz_adapter/`](examples/ext_authz_adapter/) puts it behind NGINX, Traefik or Envoy,
and [`signed-request/`](examples/signed-request/) and [`spiffe/`](examples/spiffe/) each run
a workload posture end to end, minting their own credentials.

`--sharded <dir>` replaces the single file with a per-tenant sharded ledger several
processes on one host extend safely (`flock` head store); `--sharded postgres://…` does the
same across hosts (`--features postgres` — the one optional TLS dependency). Audit either
with `decern verify --sharded`.

## Architecture

Two binaries over seven small crates: a proven decision core, an SMT proof harness, a
tamper-evident ledger, and pure-Rust persistence and primitives.

<p align="center"><img src="docs/img/architecture.png" alt="decern architecture: decern and decern-serve (four postures) over the kernel, identity, proof, ledger, store, and crypto crates" width="860"></p>

## Known limitations

The list below is the standing set. Each release also states what it does **not** claim —
see [Known limits in 0.3.1](CHANGELOG.md#known-limits-in-this-release), which covers
consent, log pinning, `--trust-proxy`, replay, and what the proofs actually cover.

- **How far a credential constrains the content depends on the posture.** Bearer validation
  and `--trust-proxy` do not constrain it at all, because a gateway legitimately asks about
  other parties — so a bearer token issued to a workload carries no bind. The workload
  postures bind a caller to itself unless it is listed in `--pep`. `--require-mission` is what
  makes decision approval server-derived, and `/audit/v1/subject` stays outside the guard on
  purpose, so treat handles as secrets and rate-limit that route at whatever fronts the
  server. The full map is in
  [docs/CLI.md](docs/CLI.md#the-trust-boundary-stated-plainly).
- **`FileLedgerHeadStore` is single-host.** The sharded ledger's reference backend uses an
  exclusive `flock` per shard: correct multi-process exclusion on one host (Unix only), not
  a distributed store. Multi-host deployments use the Postgres head store instead.
- **The default build is not free of compiled native code.** No TLS, no OpenSSL, no cmake —
  but `cedar-policy` → `stacker` → `psm` compiles a small assembly routine through `cc`.
  The honest claim is "no TLS/OpenSSL/cmake in the default build," not "zero compiled
  native code."

## Contributing

Welcome, from people and from agents. Start at
[ARCHITECTURE.md](ARCHITECTURE.md#where-to-start-contributing) or the
[`help wanted`](https://github.com/anivar/decern/labels/help%20wanted) issues. Open an issue
first for anything design-changing; just raise a PR for a small, obvious fix. Every change
passes [`./scripts/verify.sh`](scripts/verify.sh) and is
[DCO](https://developercertificate.org/) signed off (`git commit -s`). Agent contributors
start at [AGENTS.md](AGENTS.md); a human still signs off the DCO. Details:
[CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), plus
[ADOPTERS.md](ADOPTERS.md), [RELEASES.md](RELEASES.md) and
[DEPENDENCIES.md](DEPENDENCIES.md) for project-health evidence.

## Citing

Each release is archived with a DOI. Cite the concept DOI —
[10.5281/zenodo.21848620](https://doi.org/10.5281/zenodo.21848620) — which always resolves
to the newest version; [CITATION.cff](CITATION.cff) carries the metadata.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
