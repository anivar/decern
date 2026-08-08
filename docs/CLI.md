<!-- SPDX-License-Identifier: Apache-2.0 -->
# Command reference

Two binaries. `decern` proves the model and reads the record; `decern-serve` answers requests and
writes it. Nothing here needs the other to be running, except where it says so.

```sh
cargo install decern-cli decern-server
```

Or take a prebuilt, signed binary for Linux (x64/arm64), macOS (Apple Silicon) or Windows (x64)
from the [releases page](https://github.com/anivar/decern/releases). Only `decern prove` needs the
**cvc5** solver on `PATH`; nothing else does.

---

## `decern prove`

Discharge every safety invariant over the whole input space with cvc5. Not a test run — the solver
either shows an invariant holds for every input the model admits, or hands back the input where it
does not.

```sh
decern prove
```

| Option | Meaning |
|---|---|
| `--model <DIR>` | Model directory (`authority.cedar`, `authority.cedarschema`, `entities.json`). Omit for the built-in model. |
| `--cvc5 <PATH>` | Path to the solver, if it is not on `PATH`. |
| `--timeout <SECS>` | Per-suite timeout. Default `120`. |

Prints one line per invariant and a count. **Exit 0 only if every invariant proved**; a
counterexample is printed with the invariant it refutes.

```
PASS  money-gate         no privileged money action without explicit approval
...
9/9 invariants proven
```

Run it after any change to the model, the kernel decision function, or an invariant. The nine
proven statements are the kernel's, and only the kernel's — see [Scope](#what-proven-covers).

---

## `decern decide`

One decision against the model, without a server or a ledger. For working out what the model says,
not for production traffic.

```sh
decern decide --subject Principal:corp --action Read --resource Resource:claim1
```

| Option | Meaning |
|---|---|
| `--subject <TYPE:ID>` | Required. e.g. `Principal:alice`. |
| `--action <NAME>` | Required. As the model spells it, e.g. `Read`, `MoveMoney`. |
| `--resource <TYPE:ID>` | Required. e.g. `Resource:doc1`. |
| `--context <JSON>` | Decision context. Must carry `now` (epoch seconds). Default `{"now":0}`. |
| `--model <DIR>` | Omit for the built-in model. |

Prints `ALLOW` or `DENY`, then the reasons and any causes. Nothing is recorded: this does not touch
a ledger, so it is not an audit trail and should not be treated as one.

---

## `decern verify`

Check a ledger. The hash chain is always checked. Signatures are checked when you supply the key —
and a run without one says so rather than reading as a clean pass.

```sh
# chain + every signature
decern verify --ledger /tmp/decern.jsonl --pubkey <kid>

# and prove the log still extends a commitment published earlier
decern verify --ledger /tmp/decern.jsonl --pubkey <kid> --anchor anchor.json

# every shard of a hosted deployment
decern verify --sharded /var/lib/decern --pubkey <kid>
```

| Option | Meaning |
|---|---|
| `--ledger <PATH>` | A single file or a segmented directory. Required unless `--sharded`. |
| `--sharded <DIR>` | A `flock` head-store directory: every shard is verified, and any failing shard fails the run. |
| `--pubkey <HEX>` | Ed25519 public key. Without it, signatures are **not** checked. |
| `--anchor <FILE>` | A tree head published earlier. Also proves nothing at or below the anchored size was rewritten, reordered or dropped. Not for `--sharded`. |

**Why `--anchor` is the one that matters.** A hash chain proves a log holds together, which whoever
wrote it can always arrange — rewrite the records, rechain them, and an ordinary verify passes. A
commitment published earlier, somewhere the operator does not control, is what makes a dropped
record detectable. Get one from `GET /anchor/v1/tree-head` and keep it somewhere they cannot reach.

Failures name what happened: `TRUNCATED` when the log is shorter than the anchor commits to,
`DIVERGED` when history at or below that point was rewritten, `ANCHOR SIGNATURE INVALID` when the
anchor is not signed by the key you supplied.

Exit 0 on a clean verify, non-zero on any failure.

---

## `decern explain`

What one recorded decision says, read from the record alone.

```sh
decern explain --ledger /tmp/decern.jsonl --seq 0 --pubkey <kid>
decern explain --ledger /tmp/decern.jsonl --seq 0 --json
```

| Option | Meaning |
|---|---|
| `--ledger <PATH>` | Single file or segmented directory. Required. |
| `--seq <N>` | Which record, 0-based. Required. |
| `--pubkey <HEX>` | Check the signature too. Without it the line says `not checked`. |
| `--json` | Machine-readable instead of prose. |

It verifies the chain **before** explaining, so a record whose chain does not hold fails loudly
rather than getting a tidy explanation of a forgery.

What it is not: a re-derivation. It does not re-run policy, and it does not tell you what today's
directory would decide. It is a faithful reading of what was written down, which is a different and
narrower thing — and the record says which authority it was decided against (`digests.authority`),
so you can tell whether that authority is still the one in force.

---

## `decern-serve`

The PDP. Answers decisions, records each one before serving it, and serves the Mission lifecycle.

```sh
decern-serve --ledger /tmp/decern.jsonl
```

| Option | Meaning |
|---|---|
| `--ledger <PATH>` | Single-file ledger. The default backend. Mutually exclusive with `--sharded`. |
| `--sharded <DIR_OR_URL>` | Hosted. A directory gives a per-shard `flock` head store (several processes, one host). A `postgres://` URL gives a multi-host head store and needs `--features postgres`. |
| `--key <PATH>` | 32-byte hex signing seed, created if absent. Omit for an ephemeral key — which means nothing you record today verifies tomorrow. |
| `--missions <PATH>` | Mission registry. Default `decern-missions.json` beside the ledger. |
| `--require-mission` | Refuse any decision that does not name a live Mission. Approval flags are then derived from the grant, never from the request body. |
| `--standing-issuer-key <HEX>` | An issuer whose standing tokens this deployment accepts. Repeatable. Omit to accept no challenges. |
| `--addr <ADDR>` | Default `127.0.0.1:8080`. A non-loopback bind logs a startup warning, for the reason below. |

**A decision is served only if its record was written.** An append that cannot be committed returns
503 — never a bare allow. That is the property the whole thing rests on, and it is why a slow or
unavailable ledger degrades into refusals rather than into unrecorded permissions.

### Endpoints

| Method | Path | What |
|---|---|---|
| `POST` | `/access/v1/evaluation` | The decision. AuthZEN-shaped. `/decide` is an alias. |
| `GET` | `/pubkey` | The key records are signed with, so a verifier can fetch it once and keep it. |
| `GET` | `/anchor/v1/tree-head` | A signed commitment to the log's current state — publish it somewhere you do not control. |
| `GET` | `/audit/v1/subject?handle=<h>` | What was decided *about* one party, with inclusion proofs. |
| `GET` | `/directory/v1/principals/{id}/descendants` | Who else loses authority if this principal is revoked. |
| `POST` | `/mission/v1/approve` | Grant a scoped, fail-closed-attenuated Mission. |
| `GET` | `/mission/v1/{s256}` | Its state. |
| `POST` | `/mission/v1/{s256}/terminate` | End it. A terminated Mission never revives. |
| `GET` | `/.well-known/decern-subject-side-disclosure` | What this deployment does about challenges, read from its running configuration. |
| `GET` | `/healthz` | `ok`. |

### The trust boundary, stated plainly

**Every endpoint is unauthenticated by design.** The decision endpoint and the mission mutations
trust their caller — `approver` is a body field and is not authenticated. Run `decern-serve` behind
a proxy that derives and validates the caller, and keep the bind on loopback until one is there.

`/audit/v1/subject` deserves its own sentence: it returns records *about a person*. The handle is
pseudonymous and matched exactly, so it answers someone who already knows their own handle — but
that is the whole of the access control, and it is not a substitute for the proxy.

---

## A full loop

```sh
# 1. prove the invariants hold over every input
decern prove

# 2. run the PDP
decern-serve --ledger /tmp/decern.jsonl --key /tmp/decern.key &
KID=$(curl -s localhost:8080/pubkey | jq -r .kid)

# 3. publish a commitment somewhere you do not control
curl -s localhost:8080/anchor/v1/tree-head > anchor.json

# 4. decide
curl -s localhost:8080/access/v1/evaluation -H 'content-type: application/json' -d '{
  "subject":  {"type":"Principal","id":"corp"},
  "action":   {"name":"Read"},
  "resource": {"type":"Resource","id":"claim1"}
}'

# 5. verify the chain, the signatures, and that the log still extends the commitment
decern verify --ledger /tmp/decern.jsonl --pubkey "$KID" --anchor anchor.json

# 6. read one decision back
decern explain --ledger /tmp/decern.jsonl --seq 0 --pubkey "$KID"
```

[`examples/quickstart.sh`](../examples/quickstart.sh) runs prove → serve → decide → verify →
tamper-is-rejected end to end.

---

## What "proven" covers {#what-proven-covers}

The nine invariants are discharged by cvc5 over the whole input space of the kernel's decision
function. That is the claim, and it stops there.

Everything else in this reference is runtime enforcement: the Mission gate, the challenge surface,
the anchoring, the projections. They are tested, not proven, and a statement that blurs the two
would be worth less than either.
