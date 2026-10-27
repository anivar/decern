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

Discharge every safety invariant over the model's whole symbolic input space with cvc5. Not a test
run — the solver either shows an invariant holds for every input the model admits, or hands back the
input where it does not. What that covers is narrower than it sounds; see
[Scope](#what-proven-covers).

```sh
decern prove
```

| Option | Meaning |
|---|---|
| `--model <DIR>` | Model directory (`authority.cedar`, `authority.cedarschema`, `entities.json`). Omit for the built-in model. |
| `--cvc5 <PATH>` | Path to the solver, if it is not on `PATH`. |
| `--timeout <SECS>` | Bound on the whole run. Default `120`. cvc5 also stops itself 60 seconds after it starts (`--tlimit=60000`), so solver work past that fails the run however high this is set. |

Prints one line per invariant and a count. **Exit 0 only if every invariant proved**; a
counterexample is printed with the invariant it refutes.

```
PASS  money-gate         MoveMoney is never allowed unless the context carries human_approved = true
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

# a ledger whose key was rotated: --pubkey once per key that signed it
decern verify --ledger /tmp/decern.jsonl --pubkey <retired-kid> --pubkey <kid>
```

| Option | Meaning |
|---|---|
| `--ledger <PATH>` | A single file or a segmented directory. Required unless `--sharded`. |
| `--sharded <DIR>` | A `flock` head-store directory: every shard is verified, and any failing shard fails the run. |
| `--pubkey <HEX>` | Ed25519 public key. Repeatable, once per key that signed the log. A record naming a `kid` is checked against that key and one without against each key given, and a record is refused when its key had already been followed by another key in the same file, segmented ledger or shard. With `--ledger` the output lists each key with the record it started at. Without one, signatures are **not** checked. |
| `--anchor <FILE>` | A tree head published earlier. Also proves nothing at or below the anchored size was rewritten, reordered or dropped. Not for `--sharded`. |

**Why `--anchor` is the one that matters.** A hash chain proves a log holds together, which whoever
wrote it can always arrange — rewrite the records, rechain them, and an ordinary verify passes. A
commitment published earlier, somewhere the operator does not control, is what makes a dropped
record detectable. Get one from `GET /anchor/v1/tree-head` and keep it somewhere they cannot reach.

Failures name what happened: `TRUNCATED` when the log is shorter than the anchor commits to,
`DIVERGED` when history at or below that point was rewritten, `ANCHOR SIGNATURE INVALID` when the
anchor is not signed by any key you supplied.

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
| `--pubkey <HEX>` | Check the signature too. Repeatable, as for `decern verify`. Without it the line says `not checked`. |
| `--json` | Machine-readable instead of prose. |

A denial, read back (from a live run; `asserted_by:` appears under any credential posture —
bearer, signed request, SPIFFE or AAuth — and is absent under `--trust-proxy`, which verifies
no caller of its own):

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
| `--authzen-type-alias <REQUEST=MODEL>` | A request entity type and the model entity type it names (`user=Principal`). Repeatable. A PEP spells types in its own terms; the record carries the model's. A type with no alias passes through unchanged. The model type must be one the model's schema declares, or the server does not start. |
| `--public-url <URL>` | This deployment's public base URL, advertised as the policy decision point by `GET /.well-known/authzen-configuration`. `https://`, or `http://` on loopback for a local walkthrough; an origin only. Omit and the document is not served. |
| `--ledger <PATH>` | Single-file ledger. The default backend. Mutually exclusive with `--sharded`. One process writes it, and a second process opening the same file is refused at startup. On Unix the lock is on the ledger file itself, so it holds by any path, link or mount that reaches the file, and readers such as `decern verify` are not blocked; on Windows it is a `<PATH>.lock` file beside the ledger's canonical path, which a hard link to the ledger, or a link made before the ledger existed, does not share, and the ledger's directory must be writable. On a network filesystem it holds only where the filesystem honours the lock. |
| `--sharded <DIR_OR_POSTGRES_URL>` | Hosted; requires `--key`. A directory gives a per-shard `flock` head store (several processes, one host). A `postgres://` URL gives a multi-host head store and needs `--features postgres`, which the release binaries are not built with; the scheme is matched regardless of case, any other scheme is refused, and no message repeats the URL. The URL, any password in it included, is visible in the process list to other users of the host. An append reads the shard's head, not its records. A directory store written by 0.6.0 or earlier is read as it is and converted one shard at a time, at that shard's next append. An earlier release refuses a store holding a shard this release created or finished converting, so stop every replica before upgrading; there is no way back. The first boot against a Postgres store adds a column to `decern_ledger_head`, which needs the role that owns the table, and gives up after 5 seconds behind another session holding it. |
| `--key <PATH>` | 32-byte hex signing seed, created at `0600` and synced to disk if absent, never overwritten, and refused as the path of `--ledger` or `--missions`, by any spelling or link. A key readable by group or other is **refused**, not loaded — it signs every record and tree head, so a readable copy is enough to forge history that verifies. Both permission rules are Unix only: on Windows a missing key file is refused rather than created, and an existing one is loaded without checking who can read it. Omit for an ephemeral key, which means nothing you record today verifies tomorrow; the startup line says `(ephemeral)`, and a ledger file that is not empty or a `--sharded` store refuses one. A ledger with records is extended only by `--key` with every other key that signed it given as `--retired-key`: a record under a key in neither refuses the start, naming the record's key id, where the record names its key, beside the ones this boot holds, and, for any ledger file that is not empty, a `--key` naming a file that does not exist refuses too, both before anything is written, except that under a Postgres head store that already holds shards, and no `--retired-key`, the key file is created first. An empty ledger file is a new ledger. Under `--sharded` every shard is verified under these keys at boot, chain and every signature, one signature check per record. A store with no shards boots under any key, so two replicas started at once on an empty store under different keys both boot; each then refuses with `503` to record into a shard the other wrote first, and the store holds shards under both keys: start the first replica alone, or give every replica the same key before any starts. A shard another replica creates later is checked at the next restart. |
| `--retired-key <HEX>` | Public key of a ledger key this deployment rotated away from, as the startup line or `GET /pubkey` printed it while it signed. Repeatable, once per earlier key; requires `--key`, which must then name a key file that already exists. Records it signed keep verifying, and the server never signs with it. Verification refuses a record under it from its successor's first record on, within one log: for a single-file or segmented ledger that is everything after the rotation, while a sharded store is checked shard by shard, so a retired key can still sign a shard its successor has not signed. To rotate, make the new key file first, `(umask 077; openssl rand -hex 32 > new.key)`, then stop the server and start it with `--key new.key` and the old key's id here. A sharded deployment stops every replica and starts each the same way: a replica still on the old key refuses with `503` to record into a shard the new key has signed. To undo a rotation, rotate again to another new key. Do not put a retired key back under `--key`: one a later key has followed in the ledger or in any shard refuses to start. A retired key equal to `--key`'s, or given twice, refuses to start. |
| `--missions <PATH>` | Mission registry. Default `decern-missions.json` beside the ledger, or in the working directory under `--sharded postgres://…`. It is a file on one host: under `--sharded postgres://…` each replica has its own, so a Mission approved or terminated through one replica is unknown to, or still live on, the others. |
| `--require-mission` | Refuse any decision that does not name a live Mission. Client-supplied `human_approved` and `consent` are then stripped; `human_approved` is re-derived from the grant for MoveMoney. `consent` is **not** re-derived — a Mission is an approver's grant, not the resource owner's consent — so this makes on-behalf-of PII access fail closed rather than server-derived. A Mission binds only `Read` (scope `read`), `MoveMoney` (`move_money`) and `AccessPII` (`pii:read`), and under a Mission any other action is denied, so on a custom model this flag denies every action outside those three. |
| `--standing-issuer-key <HEX>` | An issuer whose standing tokens this deployment accepts. Repeatable. Omit to accept no challenges. |
| `--bearer-issuer <URL>` | The `iss` an access token must carry, matched exactly. Turns on bearer validation for the guarded routes; requires `--bearer-audience` and at least one `--bearer-issuer-key`. |
| `--bearer-audience <URI>` | This deployment's resource identifier, which a token's `aud` must contain (RFC 8707 §2). |
| `--bearer-issuer-key <HEX>` | An Ed25519 key access tokens may be signed by; only `EdDSA` tokens verify. Repeatable. Keys are read once at startup, so a rollover is the new key added and the server restarted before the issuer switches, then the old key removed on a later restart. |
| `--bearer-scope <SCOPE>` | A scope every token must carry. Repeatable; all are required, and a verified token missing one is refused `403 insufficient_scope`. Omit for no scope check. |
| `--signed-agent-key <ID=HEX>` | An agent identifier this deployment recognizes and an Ed25519 key it may sign requests with. Repeatable: one entry per agent, and a key rollover is a second entry rather than an atomic swap. Turns on RFC 9421 + RFC 7800 sender-constrained request validation for the guarded routes; requires `--signed-audience` and `--signed-authority`. One posture per deployment: naming a second is a startup failure. An identifier with no entry here cannot authenticate under this mode, by design: keys are configured, never fetched. |
| `--signed-audience <URI>` | This deployment's resource identifier, which a signed request's bound token's `aud` must contain. Required with `--signed-agent-key` and refused without it, same role as `--bearer-audience`. |
| `--signed-authority <AUTHORITY>` | This deployment's authority, which a signed request's `@authority` — the target URI's, or `Host` — must equal, compared without case. A port the request carries is part of it, a default one such as `:443` included, so name the authority exactly as signers send it. Required with `--signed-agent-key` and refused without it: the audience names a resource several deployments may share, so without this a request signed for one of them would verify at another trusting the same agent key. |
| `--pep <ID>` | A workload caller that may name principals other than itself. Repeatable. Applies to every workload posture — `--signed-agent-key`, `--spiffe-trust-domain` and `--aauth-provider`; the id must be one this deployment can already authenticate, since a PEP still has to prove who it is; under `--aauth-provider` that is an agent identifier in a configured provider's domain. Omit to bind every workload caller to itself. |
| `--aauth-provider <ISS=PATH>` | An AAuth agent provider this deployment accepts, named as `https://` and a lowercase host alone, and the JWK Set holding the Ed25519 keys it signs agent tokens with. A usable key names `kty: OKP`, `crv: Ed25519`, `alg: Ed25519` and a `kid`, and no `use` other than `sig`; every other member of the set is skipped. An agent token's `sub` must be an agent identifier, `aauth:local@domain`, in that provider's domain. Repeatable: one entry per provider. Read once at startup and refused there if it carries no usable key, or two usable keys under one `kid`. Turns on AAuth agent-token validation; requires `--aauth-audience`. Keys are configured, never fetched: the draft's `dwk` discovery is deliberately not performed, so an agent whose provider is not named here is refused before any cryptography runs. |
| `--aauth-audience <AUTHORITY>` | This deployment's authority, which a request's authority — the target URI's, or `Host` — must equal. A port the request carries is part of it, a default one such as `:443` included. Required with `--aauth-provider` and refused without it — an agent token carries no `aud`, so without it a request signed for one deployment would verify at another pinning the same provider. |
| `--spiffe-trust-domain <TRUST_DOMAIN=PATH>` | A SPIFFE trust domain this deployment accepts, and the JWK Set holding its JWT-SVID signing keys. Repeatable: one entry per federated domain. Read once at startup and refused there if it carries no `use: jwt-svid` key, an entry without a `kid`, or a key this deployment cannot verify with. Turns on JWT-SVID validation; requires `--spiffe-audience`. |
| `--spiffe-audience <URI>` | This deployment's resource identifier, which an SVID's `aud` must contain. Required with `--spiffe-trust-domain` and refused without it, same role as `--bearer-audience`. |
| `--trust-proxy` | Accept every caller, because something in front already authenticates them. One posture is required to start; naming two is a startup failure. |
| `--addr <ADDR>` | Default `127.0.0.1:8080`. The startup line names the address bound, so port `0` shows the port the system chose. |

**A decision is served only if its record was written.** An append that cannot be committed returns
503 — never a bare allow. That is the property the whole thing rests on, and it is why a slow or
unavailable ledger degrades into refusals rather than into unrecorded permissions.

### Endpoints

| Method | Path | Caller | What |
|---|---|---|---|
| `POST` | `/access/v1/evaluation` | guarded | The decision. AuthZEN 1.0: `subject`/`resource` `{type,id,properties?}`, `action` `{name,properties?}`, optional `context`; `properties` reach the policies as `context.subject`/`context.resource`/`context.action` where the model declares them, from PEP-bound callers only. A context over 64 KiB as sent, properties included, is 413. `/decide` is an alias. |
| `POST` | `/access/v1/evaluations` | guarded | Several decisions in one exchange (AuthZEN 1.0 §7). Top-level `subject`/`action`/`resource`/`context` are defaults an item replaces whole; `options.evaluations_semantic` is `execute_all` (default), `deny_on_first_deny` or `permit_on_first_permit`; answers come back in request order. Each evaluated item is admitted, decided and recorded as a single evaluation is, before the batch is served — as one durable step on the single-file ledger; an item that is not an evaluation, or that this server refuses, is `decision: false` with `context.error` `{status, code, message}` and is not recorded, where a policy deny carries the kernel's `context.errors`. A record that cannot land fails the exchange closed (503) with the items before it already recorded, so a retry records those again. At most 1000 items. Without items, this is the single evaluation. |
| `POST` | `/access/v1/search/subject` | guarded | The subjects of a type that may perform an action on a resource (AuthZEN 1.0 §8.4): every principal of that type is decided as an evaluation would be, over the same prepared context, and the ones permitted come back in the request's type spelling. `subject.id`, if sent, is ignored. A caller bound to itself may not search for subjects. |
| `POST` | `/access/v1/search/resource` | guarded | The resources of a type a subject may perform an action on (§8.5); `resource.id`, if sent, is ignored. |
| `POST` | `/access/v1/search/action` | guarded | The actions the model declares that a subject may perform on a resource (§8.6); `action` is omitted from the request. For all three: no pagination — every result comes in one page, a `page.limit` is accepted and a `page.token` is 400, since this server issued none; a search binds no Mission (refused, 422 `search_under_mission`, under `--require-mission` or with a `context.mission`); a `decision_subject` or a challenge in the context is dropped, nothing being decided about anyone, once admission has held a named handle to the caller's bind as on an evaluation; an action a decision would refuse for want of a Mission (`MoveMoney` in the built-in model) is never a result; parity is with what the authority records, since a fact that lives only in a request's `properties` for the searched side cannot be supplied; `properties` on the searched side describe every candidate (a subject search with `subject.properties` asks which subjects, so described, would be permitted — it is not a filter); an `action` sent to an action search is 400. Each search is recorded once under `Search.Subject`/`Search.Resource`/`Search.Action` with the result ids (up to 1000) and the count, over the context pruned to what the searched action declares (an action search: what any action declares; an unknown action: the clock alone); a subject search's record names no subject and lands in the resource's tenant's shard; its `decision` is `true` — the search ran — with no reasons, so a count of allows must exclude `Search.*`; its parameters digest is over the inputs, so a verifier recomputing it strips `context.search` first. |
| `GET` | `/pubkey` | open | `kid`, the key records are signed with now, and `keys`, every key a record may be verified under: the `--retired-key` keys in the order given, then `kid`. `keys` changes when the deployment rotates; a verifier passes each of them to `decern verify --pubkey`. |
| `GET` | `/anchor/v1/tree-head` | open | A signed commitment to the log's current state — publish it somewhere you do not control. Recomputed at most once a second, holding the lock appends need only to count the records and to sign; between, the last head is served. |
| `GET` | `/audit/v1/subject?handle=<h>` | open | What was decided *about* one party, with inclusion proofs. |
| `GET` | `/directory/v1/principals/{id}/descendants` | guarded | Who else loses authority if this principal is revoked. |
| `POST` | `/mission/v1/approve` | guarded | Grant a scoped, fail-closed-attenuated Mission. Refused (422, nothing recorded) when it exceeds the approver's scopes or expiry, when the approver is revoked, directly or through a delegator, or is the agent itself, or when the agent is not a principal in the approver's tenant. A body that is not an approval request is refused in the same JSON shape, with 400, 413, 415 or 422. A Mission backs a decision only about a subject the model names, approved by another principal the model names (compared by id only), in the same tenant, and only while that approver is unrevoked, unexpired and holds the decision's scope in the model the server runs. |
| `GET` | `/mission/v1/{s256}` | guarded | Its approver, state and expiry, to every established caller — a workload bound to itself included, so a reference a caller can compute or obtain answers who approved what and until when. `active` is the registry's state: whether the Mission backs a given decision is settled when that decision is taken, against the approver's standing then. Unbound because a PEP consults mission state before honoring a grant, and binding the read to the approver would refuse the agent a Mission authorizes. |
| `POST` | `/mission/v1/{s256}/terminate` | guarded | End it. A terminated Mission never revives. |
| `GET` | `/.well-known/decern-subject-side-disclosure` | open | What this deployment does about challenges and callers, read from its running configuration. |
| `GET` | `/.well-known/authzen-configuration` | open | AuthZEN 1.0 PDP metadata: the decision point and its evaluation endpoint, when `--public-url` is set; 404 otherwise. |
| `GET` | `/healthz` | open | `ok`, or `503` once the single-file ledger has stopped after a write error or its lock was poisoned by a panic, or once a Postgres head store has found its connection closed or the thread that holds it has stopped; a restart recovers. |

"Guarded" routes require the caller to be established; "open" routes are open by intent — they are
operational, published on purpose, or answerable only to a party who already holds the handle they
ask about.

### The trust boundary, stated plainly

**A server that cannot say how its callers are established does not start.** Every deployment
names one posture:

- **Bearer validation** (`--bearer-issuer`, `--bearer-audience`, `--bearer-issuer-key`, optionally
  `--bearer-scope`): the guarded routes require an RFC 9068 `at+jwt` access token — EdDSA over a
  configured key, issuer matched exactly, audience containing this server, expiry honored. Absent
  or invalid gets `401` with an RFC 6750 challenge; a valid token missing a required scope gets
  `403`. Verification is signature-checking against configured keys, never fetching, so this adds
  no TLS stack and no reliance on a third party being reachable. RFC 9068 §2.1 requires a
  conforming resource server to support RS256, and this verifies `EdDSA` only, so it applies
  the profile's checks without conforming to it.
- **Sender-constrained validation** (`--signed-agent-key`, `--signed-audience`, `--signed-authority`): the guarded
  routes require an RFC 9421 HTTP Message Signature over `@method`, `@authority`, `@path`, and
  `signature-key`, plus `content-digest` (RFC 9530 `sha-256`) on a POST or any request carrying
  a body, bound to an RFC 7800 `cnf.jwk` claim matching a key configured here for the claimed
  agent identifier. Where bearer validation accepts a token as long as it is presented before it
  expires — a leaked bearer JWT is replayable as-is — this mode requires proof of possession of
  the signing key on every single request, and a captured signature over one POST body cannot
  authorize a different one. A signed agent may additionally only *name itself*: the
  authenticated agent must equal the AuthZEN `subject`, the mission `approver`, the stored
  approver on terminate, and the principal id on `/directory/v1/principals/{id}/descendants`,
  unless it is listed in `--pep`. A mismatch is `403 caller_mismatch` — the credential was
  accepted, the name is not theirs. The same bind covers a request's `properties`, what a PEP
  says about the subject, resource or action (carried into the context as `context.subject`,
  `context.resource` and `context.action` where the action's schema declares them): a caller
  bound to itself may not describe a party through `properties`, nor search for subjects — a
  search names everyone — and each is `403 caller_mismatch`. Verification is against configured
  keys only, same no-fetch posture as bearer validation, and an agent identifier with no
  configured key, or a request whose `@authority` is not `--signed-authority`, is refused before
  any cryptography runs. The bound token must carry an `iss`, but no issuer key verifies the
  token, so a record made under this posture names the agent as subject and client and no
  issuer.
  [`examples/signed-request/`](../examples/signed-request/README.md) runs this mode end to end,
  including the beat that separates it from a bearer credential: the *same* token, refused when
  the signature comes from a different key, and the beats that refuse an authenticated agent
  asking or approving as someone else.
- **SPIFFE JWT-SVID validation** (`--spiffe-trust-domain`, `--spiffe-audience`): the guarded
  routes require a SPIFFE JWT-SVID, presented as a `Bearer` credential per JWT-SVID §5.2 and
  verified against a trust bundle configured for the trust domain its `sub` names. Trust domains
  are matched **exactly** — a prefix comparison would let `example.org.evil` present as
  `example.org`. Bundles are read once at startup and never fetched or reloaded, so this adds no
  TLS stack and no reliance on a third party being reachable, and a new signing key takes
  effect only on restart. SPIRE's default CA and signing-key TTL (`ca_ttl`) is 24 hours, so a
  deployment pinning a SPIRE bundle refreshes it and restarts on that cadence, or SVIDs signed
  by a newer key are refused.
  **`ES256` only.** JWT-SVID permits nine algorithms; `RS*`/`PS*` require the `rsa` crate, which
  carries an unpatched RUSTSEC-2023-0071 timing side-channel that this project's supply-chain gate
  refuses. A SPIRE deployment issuing RSA SVIDs is therefore **not** interoperable here — a real
  limit, stated rather than softened.
  A verified `spiffe://…` identity is recorded as the caller on the decision. Like a
  signed-request agent it is a **workload**, so unless it is listed in `--pep` it may only name
  itself as AuthZEN `subject`, `decision_subject`, mission `approver`, stored approver on terminate, and directory
  principal, and may not describe a party with `properties`; either is `403 caller_mismatch`.
  It is never minted into the authority graph
  either: what a decision may be *about* is unchanged, and stays closed-world exactly as under
  every other posture.
- **AAuth agent tokens** (`--aauth-provider`, `--aauth-audience`): the guarded routes require an
  `aa-agent+jwt` agent token whose header names `alg: Ed25519`, from an agent provider
  configured here, whose own signature verifies against that provider's pinned key, and an
  RFC 9421 signature over the request by the key the token's `cnf` confirms, which must name
  its `alg` too. The token is the `Signature-Key` member under the signature's own label, scheme
  `jwt`. The signature must cover `@method`, `@authority`, `@path` and `signature-key`, and
  `content-digest` on a POST or any request with a body, in any order and beside any other header field;
  an `alg` parameter is not read, `nonce` and `tag` are refused, `expires` is honoured, and
  `created` may be up to 60 seconds either side of this clock. A second `jwt` member in
  `Signature-Key` is refused. An agent token carries no `aud`, so the request's authority must
  equal `--aauth-audience`. A verified agent is a workload, bound to itself as a
  signed-request or SPIFFE caller is, unless listed in `--pep`. This covers the draft's agent
  identity access only; a refusal other than clock skew carries no `Signature-Error` code, so
  an agent that leaves `content-digest` out learns why only from the response body. The [standards
  registry](../.agent/standards/registry.yaml) lists each departure from
  draft-hardt-oauth-aauth-protocol-11.
  [`examples/aauth/`](../examples/aauth/README.md) runs this mode end to end.
- **`--trust-proxy`**: every caller is accepted, because the operator states that something in
  front — an authenticating proxy, a service mesh, the OS boundary around a local walkthrough —
  has already established who is calling. The flag is that statement.

A credential establishes **the caller**. How far that constrains what the caller may talk
*about* is a separate question, and the answer depends on the posture.

Under bearer validation it constrains nothing. The mission `approver` stays a request-body
field the gateway asserts, and the AuthZEN subject is not read from the token's `sub` — an
enforcement point asking about other parties is the entire job. `--trust-proxy` has no verified
identity to bind in the first place.

The workload postures are the opposite. A signed-request, SPIFFE or AAuth caller may only
name itself as subject, decision subject, approver, stored approver on terminate, and directory principal, and
may neither describe a party with `properties` nor search for subjects; a mismatch is
`403 caller_mismatch`. `--pep` is the way out for a workload that genuinely is a gateway.

The corollary is easy to miss: a bearer token issued to a workload is a PEP credential, and
carries no bind at all. If your caller is a workload, give it a workload posture.

`/audit/v1/subject` deserves its own sentence: it returns records *about a person*, and it stays
**outside the guard on purpose** — the party a decision was about will not hold a credential for
the deployment that decided it. The handle is pseudonymous and matched exactly, so it answers
someone who already knows their own handle and tells everyone else nothing; treat handles as
secrets, and rate-limit this route at whatever fronts the server. The other open routes publish
on purpose what an operator may still want to keep off a public network: the tree head gives
the record count, and the subject-side disclosure names the `--pep` entries, trust domains and
providers this deployment accepts.

### Pairing with an identity provider

Bearer validation verifies only an `EdDSA`-signed RFC 9068 `at+jwt` carrying `client_id`,
`jti`, `iat` and, when `--bearer-scope` is set, a space-delimited `scope` claim, against
Ed25519 keys configured here, and never fetches a JWKS. An identity provider that signs access
tokens `RS256` cannot be verified: RSA needs the `rsa` crate, which the supply-chain gate
refuses over RUSTSEC-2023-0071. Such a provider belongs in front: the enforcement point validates the user's token, names the
user as the AuthZEN `subject`, and authenticates itself to decern with its own credential:
a workload posture with the enforcement point listed in `--pep` (otherwise it may only name
itself, and naming the user is `403 caller_mismatch`), an `EdDSA` token minted for it by a
component in front, or `--trust-proxy` inside the network boundary.

Present a service credential here, never an end user's token. Under any credential posture
the token's `sub` is written to every record permanently, and `/audit/v1/subject` returns whole
records to anyone holding a decision-subject handle on one of them.

### What a record keeps

Every decision record keeps, verbatim and permanently: the subject and resource ids, the
action, the context attributes the model's schema declares for that action, the server's
clock, the deciding policy ids, the accountable owner, the Mission named, any decision-subject
handle, and under a credential posture the caller's `sub`, `client_id` and `iss`. A Mission
approval record keeps the approver, the agent, the approved scopes and capabilities, the
expiry and the `description` as sent. The ledger cannot be edited, so none of these can be
erased later. Use pseudonymous ids, keep personal data out of Mission descriptions, and
declare in the schema only attributes you are prepared to keep for the ledger's lifetime.

### Limits

`decern-serve` bounds what one client can make it hold, and answers past a bound rather than
waiting:

| Bound | Value | Past it |
|---|---|---|
| A request's headers to arrive | 10 seconds, the idle wait on a kept-alive connection included | the connection is closed |
| One request, headers to answer | 30 seconds | `503`, `request timed out`; an append already under way still lands, unserved |
| Connections at once | 1,024; HTTP/1 serves one request at a time on each | the next waits in the listen queue |
| Subject audits at once | 1, each reading the whole log into memory; tree-head recomputes run one at a time beside it | the next waits, within the request deadline |
| Shutdown after SIGINT or SIGTERM | 30 seconds for requests in progress | the process exits |
| Request body | 2 MiB | `413` |
| A context, properties included | 64 KiB | `413`, `context_too_large` |
| An entity type, entity id or action name | 1 KiB | `413`, `name_too_large` |
| Items in one batch | 1,000 | `400` |
| What one batch may record: each item's own fields and the defaults it inherits | 16 MiB | `413`, `batch_too_large`, nothing recorded |
| `Signature`, `Signature-Input`, `Signature-Key` | 8 KiB each | `401` |

Under bearer and SPIFFE the credential is checked before the body is read; under signed-request
and AAuth, whose signature covers the body, the body is read first. An error quoting the request
back, such as an unknown action's name, is cut to 512 characters in the answer.

### What a deployment supplies

`decern-serve` leaves these to whatever runs it:

- **Transport security.** It speaks plain HTTP and carries no TLS stack. Bind it to loopback
  or a private network and terminate TLS, or mesh mTLS, in front; a bearer token sent to it
  across an untrusted network travels in clear.
- **Key rollover.** Every issuer key, trust bundle and provider key set is read once at
  startup and never reloaded, and the server handles only SIGINT and SIGTERM. A new key takes
  effect on restart, so configure it before the issuer starts signing with it.
- **Observability.** The server prints one line at startup and nothing else: no request log,
  no metrics, no tracing. A request refused before evaluation (malformed, unauthenticated, or
  naming a party its caller may not) is not recorded, and neither it nor a failed append
  (`503`) leaves a trace in the server. `/healthz` reports only the conditions the route
  table lists, and probes neither the disk nor the database.
- **Ledger retention.** The single-file ledger is one file that grows without bound; nothing
  rolls it over or archives it.
- **Recovery after a write error.** A write, flush or sync error on the single-file ledger,
  on a full disk for example, leaves it refusing every later append: every decision is answered
  `503`, and `/healthz` answers `503` so a liveness probe restarts the server. The restart trims
  an unterminated record and the ledger continues. A record written in full before its sync
  failed is kept, though its request was answered `503`.
- **Recovery after a database restart.** A Postgres head store does not reconnect. Once the
  database closes its connection, by restarting for example, every decision is answered `503`
  until `decern-serve` is restarted. The first decision to find the connection closed turns
  `/healthz` to `503`, so a liveness probe restarts the server; a replica that serves no
  decision after the database restarts answers `ok` until one does. A database that stops
  answering without closing the connection, behind a network partition for example, holds the
  store until TCP gives up: each decision meanwhile is answered `503` at the 30-second request
  deadline, `/healthz` answers `ok`, and `SIGTERM` waits. decern sets no
  connection or query timeout of its own, and the URL goes to the Postgres client as given:
  `connect_timeout` bounds only the socket connect. A database that accepts the connection and
  then stops answering, a stalled server or a proxy with no backend, holds startup with no
  deadline: nothing is served yet, `SIGTERM` is not yet handled, and while its host still
  acknowledges, nothing in TCP ends the wait. Over TCP, how soon a lost database is found is
  left to keepalives (`keepalives_idle`, `keepalives_interval`, `keepalives_retries`; on by
  default, after two idle hours), the operating system's retransmission limit, and, on Linux,
  `tcp_user_timeout`; a Unix-socket URL has none of these.
- **High availability.** The single-file ledger is one process, and a second is refused at startup. `--sharded postgres://…`
  spreads appends across hosts, every replica started with the same `--key`, but leaves each
  with its own Mission registry, and anchoring and `/audit/v1/subject` refuse a sharded ledger.
- **Which model was proven.** Nothing checks that the model `decern-serve` loads is the one
  `decern prove` checked. Run both against the same model directory from the same commit.

---

## A full loop

```sh
# 1. prove every invariant over the model's input space
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

## What "proven" covers

The nine invariants are discharged by cvc5 over the whole **symbolic** input space the Cedar
model admits — policy subsumption against a guard, not a sampled test. Two of them
(`attenuation-edge`, `revocation-gate`) reason over attributes (`principal.ancestors`,
`principal.revoked`) that `decern-kernel`'s `inject_derived` computes from the transitive
delegation chain *before* the prover runs; cvc5 sees those as flat opaque values, so the
derivation itself is trusted Rust covered by property tests. The proofs also do not see a
concrete deployment's `entities.json`, the server's clock, the HTTP layer, the Mission
lifecycle, or caller binding. That is the claim, and it stops there.

Everything else in this reference is runtime enforcement: the Mission gate, the challenge surface,
the anchoring, the projections. They are tested, not proven, and a statement that blurs the two
would be worth less than either.
