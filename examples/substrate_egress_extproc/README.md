<!-- SPDX-License-Identifier: Apache-2.0 -->
# substrate-egress-extproc

An Envoy `ext_proc` adapter that evaluates [Agent Substrate](https://github.com/agent-substrate/substrate)
actor **egress** against an AuthZEN 1.0 PDP such as `decern-serve`.

Substrate's egress gateway can call an additional external processor on every outbound request,
*after* it has authenticated the actor and applied its own egress policy — the
`--experimental-additional-egress-extproc-service` augment path. This adapter is that service: for
each request it reads the verified actor identity and the destination, asks the PDP, and either
blocks the request (enforce) or records the decision and lets it through (record). It is
**decide-and-record only** — the forward proxy, the actor mTLS CONNECT, credential injection and the
Network Egress Contract stay in Substrate's `atenet-egress`; this adapter never proxies traffic. The
in-gateway counterpart for ordinary HTTP gateways is
[`../ext_authz_adapter/`](../ext_authz_adapter/README.md) — same decision point, a different hook.

---

## How it wires

```
actor ──egress──▶ atenet-egress (Envoy)            substrate-egress-extproc        decern-serve
                   │  authenticates the actor,         (this adapter)               (--trust-proxy)
                   │  applies its EgressPolicy, then
                   └─ ext_proc: request headers +  ──▶ map → AuthZEN  ──▶ POST /access/v1/evaluation
                      filter_state['dev.ate.actor.identity']            ◀── {"decision": bool}
                   ◀─ continue / 403 (enforce only) ◀─
```

Point Substrate at the adapter when installing the egress gateway:

```bash
go run ./cmd/ate-setup deploy ... \
  --experimental-additional-egress-extproc-service=ate-system/substrate-egress-extproc:50051
```

Substrate emits an `ext_proc` filter with `failure_mode_allow: false` (an unreachable adapter
denies), `request_header_mode: SEND`, and `request_attributes: ['dev.ate.actor.identity']`. The
cluster to the adapter is HTTP/2 over **mTLS TLS 1.3** with a pinned SNI/SAN, so in-cluster the
adapter must serve TLS.

Run `decern-serve` in `--trust-proxy` mode: Substrate is the authenticating front that has already
proven the actor, so the PDP trusts the forwarded identity on a private network. Co-locate the two
(same pod, loopback) so the adapter→PDP hop is not a second network hop.

```bash
decern-serve --ledger /run/decern.jsonl --key /run/decern.key --addr 127.0.0.1:8080 --trust-proxy
substrate-egress-extproc --listen-addr 0.0.0.0:50051 --pdp-url http://127.0.0.1:8080 --mode enforce \
  --tls-cert /etc/certs/tls.crt --tls-key /etc/certs/tls.key --tls-client-ca /etc/certs/ca.crt
```

---

## Modes — enforce vs record

decern gives two things on one call: a proven **decision** and a signed, contestable **record**.
The mode chooses which one drives the egress.

- **`enforce` (default).** Fail-closed; decern is in the request path. A decern allow proceeds; a
  decern deny, or any failure (no identity, no destination, PDP unreachable), returns `403`. Use it
  when decern is the egress authority.
- **`record`.** Fail-open; decern is off the critical path. The adapter records the decision in
  decern for the subject to contest, then lets the request through **whatever** decern says or does
  — a decern outage never blocks egress, and a request decern could not be asked about goes through
  unrecorded. Use it when Substrate's own `EgressPolicy` already enforces
  destinations and decern's value is the contestable log. Pair it with `observability_mode` on the
  Substrate filter so Envoy does not wait on the callout at all.

`record` is often the better fit: Substrate already enforces, and decern's differentiator here is
the record, not a second allow/deny — so you get the contestable audit without decern becoming an
availability bottleneck. `enforce` is the default only because fail-closed is the safe default.

---

## CLI options

| Flag | Default | Description |
|---|---|---|
| `--listen-addr` | `127.0.0.1:50051` | Address for the ext_proc gRPC server. An in-cluster deployment binds `0.0.0.0` (with TLS). |
| `--pdp-url` | `http://127.0.0.1:8080` | AuthZEN PDP base URL; `/access/v1/evaluation` is appended. |
| `--mode` | `enforce` | `enforce` (block on deny/failure) or `record` (never block; record only). |
| `--identity-attr` | `filter_state['dev.ate.actor.identity']` | The ext_proc attribute key Substrate's atenet dispatch sets and reads the actor identity under. |
| `--subject-type` | `Actor` | AuthZEN subject entity type. |
| `--resource-type` | `Destination` | AuthZEN resource entity type. |
| `--pdp-timeout-secs` | `1` | Deadline for the whole PDP exchange; keep it below Substrate's `message_timeout` (2s). |
| `--pdp-bearer-token` | *(none)* | Optional bearer token for the PDP. Prefer `PDP_BEARER_TOKEN` in the env. |
| `--tls-cert` / `--tls-key` | *(none)* | Serve the ext_proc over TLS. Required in-cluster; without them the server is plaintext h2c (local dev only). |
| `--tls-client-ca` | *(none)* | CA bundle to verify Substrate's client certificate (mutual TLS). |

---

## Request mapping

| ext_proc input | AuthZEN field |
|---|---|
| attribute `filter_state['dev.ate.actor.identity']` — the actor's SPIFFE id, a plain string | `subject.id` (with `subject.type` = `--subject-type`) |
| request `:method` | `action.name` |
| request `:authority` (or `host`) — the egress destination | `resource.id` (with `resource.type` = `--resource-type`) |

The identity is read exactly as Agent Substrate's own atenet dispatch reads it: the string value of
the CEL attribute key, which the gateway sets from the verified actor certificate and the actor does
not control. decern
matches the ids against the ids its model declares; map destinations and methods to the model's
resource and action names, or declare the model in those terms. An id the model has never heard of
denies, which is the correct default.

> **Destination granularity.** The resource is the inner request's `:authority`, which carries the
> port only when the actor specified `host:port`. The reliable dialed port lives in Substrate's
> `dev.ate.connect.authority` filter state, which the augment does not forward today; forwarding it
> (one line in the Substrate filter's `request_attributes`) would let the adapter key on `host:port`
> reliably. Until then, write host-level egress policy.

---

## What the modes do on each condition

| Condition | `enforce` | `record` |
|---|---|---|
| PDP returns `{"decision": true}` | continue | continue (recorded) |
| PDP returns `{"decision": false}` | `403` | continue (recorded) |
| No verified actor identity | `403` | continue |
| Missing `:method` or `:authority` | `403` | continue |
| PDP unreachable / timeout / non-2xx / malformed / over 64 KiB | `403` | continue (not recorded) |

In `enforce`, Substrate's own `failure_mode_allow: false` denies independently if the adapter is
unreachable, so the egress fails closed end to end.

---

## Where it fits

- **One coarse layer, not the only one.** decern's richest value — the decision-subject, the
  operator-of-record, contestability — is at *consequential* decisions (move money, read a record),
  reached through the in-process [`../mcp/`](../mcp/) guard or the app-gateway
  [`../ext_authz_adapter/`](../ext_authz_adapter/). This adapter adds a coarse network guardrail/audit
  at egress. Run them against one `decern-serve`.
- **Every egress request becomes a recorded decision.** That is decern's point, and its cost: a
  ledger entry per outbound request. On chatty egress that is a lot of writes — prefer `record`
  (and, where available, sampling at the Substrate filter), or keep decern at the higher-value
  decision points, if the volume does not justify a recorded egress trail.
- **No decision cache — deliberate.** A cache would cut PDP load but break "every decision is in the
  ledger", which is the whole point. Substrate's `EgressPolicy` already has a per-actor cache for the
  coarse enforcement; decern's job here is the record. Do not add one.

---

## Trust boundary

The adapter trusts only the actor identity Substrate delivers as a request **attribute**, which the
actor cannot set, and the `:method`/`:authority` the gateway parsed. It never trusts the actor's own
claims. In-cluster the adapter must require Substrate's client certificate (`--tls-client-ca`), so
only the egress gateway can reach it; without that, whoever reaches the adapter could ask for any
decision. The default `--listen-addr` is loopback for exactly this reason.

---

## Build and run

```bash
cd examples/substrate_egress_extproc
cargo build --release
cargo test

# local dev, plaintext, PDP on loopback, record mode:
./target/release/substrate-egress-extproc --pdp-url http://127.0.0.1:8080 --mode record
```

Its own Cargo project, outside the decern workspace; it pulls a gRPC/TLS stack that the core decern
binaries deliberately do not.
