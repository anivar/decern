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

A denial, read back (from a live run; `asserted_by:` appears when the deployment validates
bearer tokens and the record carries the verified caller):

```
seq:           1
subject:       Principal:agent-7
action:        MoveMoney
resource:      Resource:account9
decision:      DENY

chain:
  prev:       78d312d1b88a75d8441e19920408e3a8438ec2d547e7b5496636ba37a4bed8a6
  hash:       7bd414059c27b912b87ba359d362830d81a63163c06c7d9ca0c7f5d0ac335205
  signature:  yes (verified)
  signed_by:  46a941e7d9536df4922254a6a3cf983bd90ea3d2264c44390257adca00468fff

reasoning:
  - F-money

bound to:
  authority    cb03c58cb1f689cc270f99791138dbd913d25bd50c6ee2f70a41206ad795f9be
  parameters   5b86c3bfd81d4092515553da5c4063222554e8e7b5a053271699e78b4628f04b
```

It verifies the chain **before** explaining, so a record whose chain does not hold fails loudly
rather than getting a tidy explanation of a forgery.

What it is not: a re-derivation. It does not re-run policy, and it does not tell you what today's
directory would decide. It is a faithful reading of what was written down, which is a different and
narrower thing — and the record says which authority it was decided against (`digests.authority`),
so you can tell whether that authority is still the one in force.

The `bound to:` block prints every digest the entry binds. `digests.parameters` is a JCS SHA-256
over exactly `{subject, action, resource, context, mission, decision_subject}` as the server
evaluated them — `entry.context` is byte-for-byte the digested context, so the value is
recomputable from the record alone, by anyone, with any RFC 8785 implementation.

---

## `decern-serve`

The PDP. Answers decisions, records each one before serving it, and serves the Mission lifecycle.

```sh
decern-serve --ledger /tmp/decern.jsonl --trust-proxy
```

| Option | Meaning |
|---|---|
| `--model <DIR>` | Model directory. Omit for the built-in model. |
| `--ledger <PATH>` | Single-file ledger. The default backend. Mutually exclusive with `--sharded`. |
| `--sharded <DIR_OR_POSTGRES_URL>` | Hosted. A directory gives a per-shard `flock` head store (several processes, one host). A `postgres://` URL gives a multi-host head store and needs `--features postgres`. |
| `--key <PATH>` | 32-byte hex signing seed, created if absent. Omit for an ephemeral key — which means nothing you record today verifies tomorrow. |
| `--missions <PATH>` | Mission registry. Default `decern-missions.json` beside the ledger. |
| `--require-mission` | Refuse any decision that does not name a live Mission. Approval flags are then derived from the grant, never from the request body. |
| `--standing-issuer-key <HEX>` | An issuer whose standing tokens this deployment accepts. Repeatable. Omit to accept no challenges. |
| `--bearer-issuer <URL>` | The `iss` an access token must carry, matched exactly. Turns on bearer validation for the guarded routes; requires `--bearer-audience` and at least one `--bearer-issuer-key`. |
| `--bearer-audience <URI>` | This deployment's resource identifier, which a token's `aud` must contain (RFC 8707 §2). |
| `--bearer-issuer-key <HEX>` | An Ed25519 key access tokens may be signed by. Repeatable, so a key rollover is two configured keys rather than a window with none. |
| `--bearer-scope <SCOPE>` | A scope every token must carry. Repeatable; all are required, and a verified token missing one is refused `403 insufficient_scope`. Omit for no scope check. |
| `--signed-agent-key <ID=HEX>` | An agent identifier this deployment recognizes and the one Ed25519 key it may sign requests with. Repeatable: one entry per agent, and a key rollover is a second entry rather than an atomic swap. Turns on RFC 9421 + RFC 7800 sender-constrained request validation for the guarded routes; requires `--signed-audience`. Conflicts with `--bearer-issuer`/`--trust-proxy`. An identifier with no entry here cannot authenticate under this mode, by design: keys are configured, never fetched. |
| `--signed-audience <URI>` | This deployment's resource identifier, which a signed request's bound token's `aud` must contain. Required with `--signed-agent-key`, same role as `--bearer-audience`. |
| `--trust-proxy` | Accept every caller, because something in front already authenticates them. Conflicts with `--bearer-issuer` and `--signed-agent-key`; one posture is required to start. |
| `--addr <ADDR>` | Default `127.0.0.1:8080`. |

**A decision is served only if its record was written.** An append that cannot be committed returns
503 — never a bare allow. That is the property the whole thing rests on, and it is why a slow or
unavailable ledger degrades into refusals rather than into unrecorded permissions.

### Endpoints

| Method | Path | Caller | What |
|---|---|---|---|
| `POST` | `/access/v1/evaluation` | guarded | The decision. AuthZEN-shaped. `/decide` is an alias. |
| `GET` | `/pubkey` | open | The key records are signed with, so a verifier can fetch it once and keep it. |
| `GET` | `/anchor/v1/tree-head` | open | A signed commitment to the log's current state — publish it somewhere you do not control. |
| `GET` | `/audit/v1/subject?handle=<h>` | open | What was decided *about* one party, with inclusion proofs. |
| `GET` | `/directory/v1/principals/{id}/descendants` | guarded | Who else loses authority if this principal is revoked. |
| `POST` | `/mission/v1/approve` | guarded | Grant a scoped, fail-closed-attenuated Mission. |
| `GET` | `/mission/v1/{s256}` | guarded | Its state. |
| `POST` | `/mission/v1/{s256}/terminate` | guarded | End it. A terminated Mission never revives. |
| `GET` | `/.well-known/decern-subject-side-disclosure` | open | What this deployment does about challenges and callers, read from its running configuration. |
| `GET` | `/healthz` | open | `ok`. |

"Guarded" routes require the caller to be established; "open" routes are open by intent — they are
operational, published on purpose, or answerable only to a party who already holds the handle they
ask about.

### The trust boundary, stated plainly

**A server that cannot say how its callers are established does not start.** Every deployment
names one of two postures:

- **Bearer validation** (`--bearer-issuer`, `--bearer-audience`, `--bearer-issuer-key`, optionally
  `--bearer-scope`): the guarded routes require an RFC 9068 `at+jwt` access token — EdDSA over a
  configured key, issuer matched exactly, audience containing this server, expiry honored. Absent
  or invalid gets `401` with an RFC 6750 challenge; a valid token missing a required scope gets
  `403`. Verification is signature-checking against configured keys, never fetching, so this adds
  no TLS stack and no reliance on a third party being reachable.
- **Sender-constrained validation** (`--signed-agent-key`, `--signed-audience`): the guarded routes
  require an RFC 9421 HTTP Message Signature over `@method`, `@authority`, `@path`, and
  `signature-key`, bound to an RFC 7800 `cnf.jwk` claim matching a key configured here for the
  claimed agent identifier. Where bearer validation accepts a token as long as it is presented
  before it expires — a leaked bearer JWT is replayable as-is — this mode requires proof of
  possession of the signing key on every single request. Verification is against configured keys
  only, same no-fetch posture as bearer validation, and an agent identifier with no configured key
  is refused before any cryptography runs.
  [`examples/signed-request/`](../examples/signed-request/README.md) runs this mode end to end,
  including the beat that separates it from a bearer credential: the *same* token, refused when the
  signature comes from a different key.
- **`--trust-proxy`**: every caller is accepted, because the operator states that something in
  front — an authenticating proxy, a service mesh, the OS boundary around a local walkthrough —
  has already established who is calling. The flag is that statement. It is exactly the old
  behaviour, now a named choice rather than a default.

What bearer validation establishes is **the caller, not the content**. The mission `approver` is
still a request-body field: a verified gateway asserts it, and `--require-mission` remains what
makes approval server-derived for decisions. The AuthZEN subject is likewise deliberately not
taken from the token's `sub` — an enforcement point legitimately asks about parties other than
itself.

`/audit/v1/subject` deserves its own sentence: it returns records *about a person*, and it stays
**outside the guard on purpose** — the party a decision was about will not hold a credential for
the deployment that decided it. The handle is pseudonymous and matched exactly, so it answers
someone who already knows their own handle and tells everyone else nothing; treat handles as
secrets, and rate-limit this route at whatever fronts the server.

---

## A full loop

```sh
# 1. prove the invariants hold over every input
decern prove

# 2. run the PDP; this walkthrough is its own caller, so say so
decern-serve --ledger /tmp/decern.jsonl --key /tmp/decern.key --trust-proxy &
KID=$(curl -s localhost:8080/pubkey | jq -r .kid)

# 3. decide
curl -s localhost:8080/access/v1/evaluation -H 'content-type: application/json' -d '{
  "subject":  {"type":"Principal","id":"corp"},
  "action":   {"name":"Read"},
  "resource": {"type":"Resource","id":"claim1"}
}'

# 4. publish a commitment somewhere you do not control. A tree head over an empty log
#    commits to nothing, so take it once there is a decision to be held to.
curl -s localhost:8080/anchor/v1/tree-head > anchor.json

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
