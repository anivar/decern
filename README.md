<!-- SPDX-License-Identifier: Apache-2.0 -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/decern-mark-dark.svg">
    <img src="docs/img/decern-mark.svg" alt="decern" width="76" height="76">
  </picture>
</p>

# decern

A deterministic authorization kernel whose safety properties are **machine-checked over
every possible input**, not just tested on examples — with a hash-chained, tamper-evident
decision ledger anyone can verify without trusting the operator.

The industry standardizes how authority is *represented* — tokens, delegation envelopes,
decision-request formats — and defers the *guarantee* (that attenuation holds, that nothing
was dropped from the log, that a decision stayed within its mandate) to implementer policy.
decern is the guarantee.

## Architecture

Two binaries over seven small crates: a proven decision core, an SMT proof harness, a
tamper-evident ledger, and pure-Rust persistence and primitives.

<p align="center"><img src="docs/img/architecture.png" alt="decern architecture: decern and decern-serve binaries over the kernel, identity, proof, ledger, store, and crypto crates" width="860"></p>

## What is proven

A decision is a pure function of `(principal, authority graph, policy, now)`. **9 invariants**
over that function are discharged by an SMT solver (cvc5) across the entire input space — not
sampled. Each statement is calibrated to exactly what the solver checks, so a proof never
claims more than the machine verified:

- **money-gate** — no privileged money action without explicit approval
- **isolation** — no decision ever crosses a tenant boundary
- **decay** — no decision once authority has expired
- **attenuation-edge** — no access without ownership, a delegation ancestor, or an explicit grant
- **scope-gate** — bounded actions require their scope
- **revocation-gate** — a revoked principal is allowed nothing
- **residency-gate** / **role-gate** / **consent-gate** — data-bound access conditions

## What is recorded

Every decision lands in an append-only, Ed25519-signed, hash-chained ledger. A crash-torn tail
heals; an attacker truncating committed history is detected. The audit trail is externally
verifiable — a signature proves a record is authentic, the chain proves nothing was dropped.

A decision is served **only if its audit record was written** — an unrecordable decision returns
503, never a bare allow:

<p align="center"><img src="docs/img/decision-flow.png" alt="decern decision flow: a request is evaluated by the proven kernel, recorded to the tamper-evident ledger, and served with 200 only when the record was written, else 503" width="860"></p>

Each decision recorded by the PDP also carries a derived **accountable-owner**: the root of the
subject's delegation chain, resolved server-side from the directory (never a request input). A
delegate's record names the principal ultimately answerable for it; a root principal sponsors
itself; a caller the directory doesn't recognize has none. It is a recorded accountability column,
not a decision gate — it never changes the allow/deny outcome.

## Missions

`decern-serve` also serves a **Mission lifecycle** over `decern-identity`: an approver grants an
agent a scoped, fail-closed-attenuated authorization context — "these tools, until this time." A
Mission whose `approved_tools` exceed what the approver holds, or whose expiry outlives the
approver's, is refused and nothing is recorded. Every accepted transition is written to the same
tamper-evident ledger before it is reported as succeeded (a 503 otherwise); a terminated Mission
never revives. A Mission's reference `s256` is a pure function of its approval parameters
(approver, agent, description, approved_tools, capabilities, expiry), so re-approving an *identical*
terminated grant is refused as a 409 — a fresh grant must differ in at least one approved field.

```
POST /mission/v1/approve            {approver, agent, description, approved_tools, capabilities?, expiry}
                                    -> {approver, s256, reference}
GET  /mission/v1/{s256}             -> {reference, state: active|terminated, expiry}
POST /mission/v1/{s256}/terminate   -> {reference, state: terminated}
```

The registry is durable and local (`--missions <PATH>`, default `decern-missions.json` alongside
the ledger) — sovereign, consulted in-perimeter, no phone-home.

## Principals

Humans, agents, and workloads are one principal type, decided by the same proven function.

## Quickstart

Requires the pinned toolchain (`rust-toolchain.toml`) and the **cvc5** solver on `PATH` for the proofs.

```sh
# 1. Prove all invariants hold over every input (cvc5)
cargo run -p decern-cli -- prove

# 2. Run the PDP (writes a tamper-evident ledger)
cargo run -p decern-server -- --ledger /tmp/decern.jsonl &

# 3. Decide over HTTP (AuthZEN-shaped) — corp reads a claim it owns
curl -s localhost:8080/access/v1/evaluation -H 'content-type: application/json' -d '{
  "subject":  {"type":"Principal","id":"corp"},
  "action":   {"name":"Read"},
  "resource": {"type":"Resource","id":"claim1"}
}'

# 4. Verify the ledger (hash chain + every signature)
cargo run -p decern-cli -- verify --ledger /tmp/decern.jsonl \
  --pubkey "$(curl -s localhost:8080/pubkey | jq -r .kid)"
```

Hosted (multi-process, single host): `decern-serve --sharded <dir>` runs the multi-process sharded
ledger instead of the single file — several `decern-serve` processes on one host share one
tamper-evident ledger, one hash chain per tenant, coordinated by the `flock` file head store.
Audit that deployment with `decern verify --sharded <dir> --pubkey <kid>`, which checks every
shard's hash chain and signatures and exits non-zero if any shard fails.

Hosted (multi-host): `--sharded` also accepts a `postgres://` URL, backed by the
`decern-store-postgres` advisory-lock head store, so replicas on *different* hosts share one ledger.
That backend needs a TLS stack, so it is behind a build flag — `cargo build -p decern-server
--features postgres` — and the default binary carries no TLS stack. The postgres URL is never logged.

`--sharded` and `--ledger` are mutually exclusive.

[`examples/quickstart.sh`](examples/quickstart.sh) runs the whole loop — prove → serve → decide →
verify → tamper-is-rejected — end to end. Contributors run [`./scripts/verify.sh`](scripts/verify.sh)
(every gate) before a PR; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Known limitations

- **Trust boundary — the HTTP endpoints are unauthenticated by design.** Both the
  decision PDP (`/access/v1/evaluation`, `/decide`) and the mission-mutation endpoints
  (`/mission/v1/approve`, `/mission/v1/{s256}/terminate`) trust their caller: the mission
  endpoints take `approver` as a request-body field and do **not** authenticate it. Deploy
  `decern-serve` behind an authenticating proxy (or on a trusted network) that derives and
  validates the caller's identity — in particular the mission `approver` — and keep the
  bind loopback (`--addr`, default `127.0.0.1:8080`) unless such a proxy fronts it. Binding
  a non-loopback `--addr` logs a startup `WARN` for this reason.

- **Sharded ledger head store — `FileLedgerHeadStore` is single-host.** The
  persistent reference backend for the sharded ledger (`decern-store`) uses an
  exclusive advisory file lock (`flock LOCK_EX`) per shard to serialize each
  read-then-append critical section. That gives correct **multi-process**
  exclusion on **one host** (Unix only), and is the sovereign single-node
  default. It is **not** a multi-*host* distributed store — `flock` is
  host-local. For multi-*host* deployments, `decern-store-postgres` implements
  the same `LedgerHeadStore` trait over Postgres transaction advisory locks
  (`--sharded postgres://…`, build with `--features postgres`); it adds a TLS
  provider (compiled C) and so is optional and off by default.

- **The default build is not free of compiled native code.** It pulls no TLS
  stack, no OpenSSL and no cmake, but `cedar-policy` → `stacker` → `psm` compiles a
  small assembly stack-switching routine through `cc`, so building the default
  binaries needs a C/assembler toolchain. The honest claim is "no TLS/OpenSSL/cmake
  in the default build," not "zero compiled native code."

## Contributing

Contributions are welcome — from people and from agents. Good places to start are in
[ARCHITECTURE.md](ARCHITECTURE.md#where-to-start-contributing) (each area mapped to the crate that
owns it) and the [`help wanted`](https://github.com/anivar/decern/labels/help%20wanted) issues.

- **Open an issue to discuss first** for anything large or design-changing — a short back-and-forth
  saves a wasted PR. For a small, obvious fix, **just raise a PR**; the linked discussion isn't
  required for those.
- Every change must pass [`./scripts/verify.sh`](scripts/verify.sh) (build · test · cvc5 proofs ·
  clippy · fmt · cargo-deny · standards guard) and be [DCO](https://developercertificate.org/)
  signed off (`git commit -s`).
- **Agent contributors:** [`AGENTS.md`](AGENTS.md) is your entry point, and
  [`.agent/`](.agent/) holds the method and standards. Agent-authored PRs are welcome under the
  same rules — a human still sign-offs the DCO.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full loop and [GOVERNANCE.md](GOVERNANCE.md) for how
changes are reviewed and merged.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
