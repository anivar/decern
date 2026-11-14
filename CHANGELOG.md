<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0]

0.7.0 is the last feature release of the current design. After it the 0.x line takes security
fixes only, and the next line will be built beside it in this repository, to return a signed
receipt with every decision; the
[roadmap](https://github.com/anivar/decern/blob/main/ROADMAP.md) says how. This release adds
rotation of the ledger signing key, bounds what a caller can make `decern-serve` hold, and closes
several ways a caller, an approver or a second process could obtain an approval or write a record
it should not. Deployments 0.6.0 started can refuse to start, and requests it answered can be
refused; the list below gives each, most disruptive first. The policies, the invariants and the
proofs do not change.

Upgrading from 0.6.0:

- **A directory shard store cannot go back.** Under `--sharded <dir>` each shard is converted at
  the first record written to it, a search's record included, and a shard this release creates
  is marked from the start. 0.6.0 then refuses the whole store, and a 0.6.0 replica left running
  answers `503` for a shard a new replica has written. Stop every replica, copy the directory,
  and upgrade them together.
- **A ledger with a signed-request record or a rotated key cannot go back.** A record written
  under the signed-request posture carries no `iss`, and a ledger whose key was rotated needs two
  keys. `decern verify`, `decern explain` and `decern-serve` from 0.6.0 and earlier read both as
  tampered, so after the first such record or the first rotation only this release opens the
  ledger. A single-file ledger with neither can still be opened by 0.6.0.
- **Postgres.** `--sharded postgres://…` starts only with `--missions-per-host`, and a URL to
  another host only with `sslmode=require`: add both. The first start adds a `signers` column to
  `decern_ledger_head` and needs the role that owns the table. A start now fails after 30
  seconds without a database, where it waited.
- **Signed-request.** `--signed-agent-key` starts only with `--signed-authority`: add it, with
  the host and port the signers' requests carry.
- **AAuth.** An agent token's header and the key in its `cnf` must name `alg: Ed25519`, and the
  token is read from the `Signature-Key` member under the label the signature carries, so an
  agent built for 0.6.0 is refused. A provider key set keeps only keys with `alg: Ed25519` and a
  `kid`, and skips the rest without a message: a set with none stops the start, and a token
  under a skipped key is refused. Reissue the key set and move agents to the draft -11 profile.
- **A store in which a retired key signed after its successor** is not repaired by
  `--retired-key`: it does not start or verify under any set of keys. Move it aside.
- **Missions.** A Mission backs a decision only while its approver is a principal the model
  marks `Human`, is not the agent, is not revoked, is not past its own `expiry` and holds the
  scope. One approved otherwise stays in the registry, still reads as `active`, and every
  decision under it is a Deny whose errors name the reason. Approve it again from a `Human`
  principal in the agent's tenant that holds the scope. A model that does not mark its approvers
  `Human` approves nothing.
- **Models.** A `revoked` that is present and not a boolean no longer loads: make it a boolean.
- **One process writes a single-file ledger.** A restart that starts the new process before the
  old one exits is refused, so stop the old process first. A `--ledger` or `--missions` path
  that names the key file is refused too.
- **`decern verify`** without `--pubkey` exits non-zero: pass `--pubkey` once per key that
  signed, or `--chain-only` where the chain check alone was meant. `--anchor` needs `--pubkey`,
  and `--sharded` on a directory that holds no shard fails.
- **Requests now refused.** A workload not listed in `--pep` that sends `consent`,
  `human_approved` or another party's `decision_subject` gets `403`, and a batch with one such
  item is refused whole: list the workload in `--pep`, or stop sending the keys. A name with a
  control character is `400` and a name over 1 KiB `413`; in a batch that item alone is answered
  `decision: false`. A batch that would record more than 16 MiB is `413` whole, a `Signature`
  header over 8 KiB is refused, and a `challenge_basis` with a non-string item is `422`.
- **Deadlines and bounds.** A connection idle for 10 seconds is closed and a request is
  answered `503` at 30 seconds. Past 512 decisions, searches, audits and Mission calls in
  progress the next is answered `503` at once, and past 1,024 connections the next waits. A
  stopping server gives requests in progress 30 seconds. A decision answered `503` at the deadline may be on
  the ledger; read a Mission's state before repeating an approval or a termination. A clock set
  before 1970 is answered `503`.
- **Names that changed.** A challenge is answered `challenge_classified` where it was
  `reevaluate_with_subject_context`, and the disclosure's
  `challenge_bases_that_reopen_a_decision` is now `challenge_bases_that_bear_on_the_facts`.
  `/pubkey` gains `keys`, a malformed Mission approval is refused in JSON where it was plain
  text, and the tree head is recomputed at most once a second.
- **Clients.** Each raises an error when `decision` is absent or not a boolean, or when a
  success body passes 1 MiB, which the TypeScript client counts only where `fetch` gives a
  stream. The Python client no longer follows a redirect.
- **Libraries and builds.** `ApprovedMission`'s fields are read through accessors,
  `Ledger::rotate` returns a `Result`, `AssertedBy::iss` is an `Option`, `HeadCursor` and
  `VerifyReport` each gain a `signers` field, and `cedar-policy` is pinned at `=4.14.0`. The
  pinned toolchain is Rust 1.100, and CI tests no older compiler.

### Added

- **The ledger signing key can be rotated without starting a new ledger.** `decern-serve
  --retired-key <HEX>`, repeatable, names by its public key a key the deployment rotated away
  from, and `--key` then names a key file made beforehand. Restarted on the new key with the old
  one retired, the server extends the ledger and every record still verifies. `GET /pubkey` keeps
  `kid`, the key signing now, and adds `keys`: the retired keys in the order given, then `kid`.
  `decern verify` and `decern explain` take `--pubkey` once per key, and `decern verify --ledger`
  with `--pubkey` prints each signing key with the record it started at. A sharded deployment
  rotates every replica together: a replica still on the old key refuses to record into a shard
  the new key has signed and answers `503` until it is restarted on the new key; `/healthz` does
  not report it. The same check makes two replicas started together on an empty store under
  different keys each answer `503` for a shard the other wrote first, where both recorded into it
  before. Authored by @anivar.

### Changed

- **A sharded append no longer reads the shard's history.** Under `--sharded`, each append read
  and parsed every record of the tenant's shard under its lock, so an append cost more the longer
  the shard: on the file store, 12.3 ms per append at 1,000 records and 26.1 ms at 5,000 on one
  machine. An append now reads the shard's head alone. The head carries the keys that have signed
  the shard, which the key-rotation guard checks. On the file store a shard is a small head,
  rewritten atomically, and an append-only log; on Postgres the head row alone is read. On the
  same machine an append on the file store costs about 12.5 ms at 1,000, 5,000 and 10,000
  records; the in-memory store takes 17 µs, so nearly all of it is the file store's disk writes.
  A record edited so it no longer parses as JSON is no longer refused by the next append to its
  shard; the next boot's check of every shard and `decern verify --sharded` find it, as they find
  any edit to a record. An append does refuse a log an edit has left with its committed length
  inside a record, rather than cut a committed record there.
  A file store written by an earlier release is read as it is, and each shard is converted at its
  next append. Every shard this release creates carries, from before its first record, a marker
  an earlier release cannot read, and every shard it converts gets one as the conversion
  completes. An earlier release's `decern-serve` and `decern verify` refuse a store holding a
  marked shard rather than read the shard as empty, so stop every replica before upgrading; there
  is no way back to the earlier release. Should an earlier release still write to a converted
  shard, this release refuses that shard rather than overwrite what it wrote.
  A Postgres store gains a nullable `signers` column. The first boot of this release adds it,
  which needs the role that owns `decern_ledger_head`, and gives up after 5 seconds behind
  another session holding the table, naming the statement to run; later boots only check for it.
  An earlier release still writing to the store leaves the column out of date, and the next append
  then reads the history instead of trusting it.
  Authored by @anivar.
- **A Postgres-sharded start says that its Mission registry is this host's.** `decern-serve
  --sharded postgres://…` starts only with `--missions-per-host`, which says that the Mission
  registry is a file on this host alone: a Mission approved or terminated here is unknown to, or
  still live on, every other host. The flag is the deployment's word, which the server cannot check,
  that a Mission's requests and its termination go to the host that holds it; given with a
  single-file or directory ledger it is refused, since the flag would be ignored. 0.6.0 stated
  this in the option table only. Authored by @anivar.
- **`decern verify` with no `--pubkey` fails.** It checked the hash chain, printed a note that no
  signature was checked, and exited 0, so a script reading the exit code passed a log that
  anyone could have rewritten and rechained. It now exits non-zero and names the two ways on:
  `--pubkey <kid>` for each key that signed the ledger, or the new `--chain-only`, which checks
  the chain alone, says so, and exits 0. `--anchor` now needs `--pubkey`: an anchor whose
  signature is not checked was taken at face value. Add `--chain-only` to a script that meant
  the chain check. `decern explain` without `--pubkey` still exits 0 and says the signature was
  not checked. Authored by @anivar.
- **`decern verify --sharded` fails on a directory that holds no shard.** It printed `no shards
  found` and exited 0, so a wrong path, or a store with no record yet, passed a check whose exit
  code is read as "verified". It now exits non-zero and says nothing was verified. A script that
  verifies a store before its first decision fails until the store holds one. Authored by
  @anivar.
- **The AAuth posture verifies draft-hardt-oauth-aauth-protocol-11's signature profile.** An
  agent token's header must name `alg: Ed25519`; the polymorphic `EdDSA` that 0.6 required is
  refused, so an agent built to that shape is refused until it moves. Every key carries a
  fully-specified `alg` consistent with `kty` and `crv`: the key `cnf` confirms is refused
  without one. An `--aauth-provider` key set keeps only the members that name one, carry a
  `kid` and have no `use` other than `sig`, skips the rest, and is refused at startup if none
  is left or two share a `kid`. The token is the `Signature-Key` member under the label the
  signature carries, read as a structured-field dictionary, where it was the member `sig`
  beside a signature labelled `sig1`; a second `jwt`-scheme member is refused. The signature
  must cover the required components in any order and may cover further header fields; an
  `alg` parameter is not read, `nonce` and `tag` are refused, and `expires` is honoured.
  `created` may be up to 60 seconds either side of the server's clock, and an agent token's
  `iat` up to 60 seconds ahead, where both were limited to 5 seconds ahead; further ahead is
  answered with `Signature-Error: error=clock_skew`. Still not met: no other refusal carries a
  `Signature-Error` code, so an agent that leaves `content-digest` off a request with a body,
  which this deployment requires, learns why only from the response body, and that body is not
  problem details; ES256 is not verified. The signed-request posture accepts and refuses what
  it did; its refusal for a missing `Content-Digest` now reads "request carries no
  Content-Digest" where it named POST. Authored by @anivar.
- **A signed request's record names no issuer.** Under `--signed-agent-key`, `asserted_by.iss`
  held the bound token's `iss` claim, which nothing verified: the token is covered by the
  request signature, never checked against an issuer key, so the value was the agent's own
  claim. Records made under this posture now omit `iss`, and `decern explain` says no issuer was
  verified. Records already written keep theirs, and the other postures record the issuer whose
  signature they checked, as before. `decern verify` and `decern explain` from 0.3.0 through
  0.6.0 require `iss` and report a record without it as tampered, so a ledger written under this
  posture is verified with this release or later. In `decern-ledger`, `AssertedBy::iss` is now
  an `Option<String>`.
  Authored by @anivar.
- **A retired ledger key may not sign after its successor.** Verification refuses a record whose
  key had already been followed by another key in the same log, where it accepted a record under
  any key in the ring at any position. A record is attributed to the key its signature verifies
  under, so removing its `kid` does not get past the rule. `decern verify`, `decern-serve` at
  startup and the library apply it; `decern-serve` refuses to start on a `--key` another key has
  already followed, and the library refuses to open a ledger with one or to rotate back to one, so
  `Ledger::rotate` now returns a `Result`, and `VerifyReport` gains `signers`, each key with the
  record it started at. `verify_evidence_bundle` checks each record under the key its `kid` names
  and applies the rule within the bundle's span, where it accepted a record under any pinned key.
  The rule holds within one log: across a single-file or segmented ledger, and shard by shard in a
  sharded store, where a retired key can still sign a shard its successor has not signed. It
  covers records only: a tree head is checked against the keys given, whichever of them signed it,
  and records removed from the end of a log show only against a tree head kept where the operator
  cannot reach. A ledger `decern-serve` signed with one key is unaffected. A shard where replicas
  under different keys took turns, so that one key signed again after the other, now fails even
  with every key given: that can happen to a store that replicas of a release before 0.6.0
  extended without `--key`, and to one that 0.6.0 replicas started together on an empty store
  under different keys. A library caller that rotated back to an earlier key wrote a ledger this
  refuses. Authored by @anivar.
- **A challenge outcome no longer names a re-evaluation that does not happen.** A challenge
  whose standing named the decision subject a record keeps, and whose basis bears on the facts
  a decision was made from, was answered `reevaluate_with_subject_context`, though the kernel
  runs once, without the challenge, and the decision stands as recorded. It is now answered
  `challenge_classified`, in the ledger record and in `outcomes_supported` on the subject-side
  disclosure, which also says what an outcome describes (`outcomes_describe`) and lists those
  bases as `challenge_bases_that_bear_on_the_facts`, renamed from
  `challenge_bases_that_reopen_a_decision`. Records written by earlier releases keep the old
  name for the same answer. A challenge is classified when a basis it gives bears on those
  facts and its standing names a party the decision's record is about: the third party it keeps
  as its decision subject, or, when it keeps none, the requester or the resource's owner. A
  challenge from the requester or the owner was always affirmed. A challenge whose standing
  names no such party is affirmed with the reason "the challenge's standing names no party the
  decision's record is about", in place of a reason about the challenged decision, which the
  server does not read.
  Authored by @anivar.
- **An approved Mission handle is read-only, and a mint is held to the registered approval.**
  `ApprovedMission` is read-only to its holder: `mission`, `state` and `s256` are read through
  accessors of those names, and only `terminate` changes it. A mint under a registry refuses a
  handle whose approved tools or expiry differ from the registered entry, which refuses a Mission
  whose row was written before its tools were recorded, as `decern-serve` already refuses it at the
  decision. The fields were public and `issue_under_mission` took its ceiling from them, so a
  library caller could widen a handle after approval and mint up to the approver's own authority.
  `decern-serve` never exposed that path. Authored by @anivar.
- **A head store's cursor carries the keys that signed its shard.** `HeadCursor` gains `signers:
  Option<ShardSigners>`, so code that builds a `HeadCursor` adds the field; `None` is what a store
  that does not keep them returns. `LedgerHeadStore` gains `with_shard_head`, `has_failed` and
  `is_stalled`, each with a default, so an existing implementation compiles. `LedgerError` gains
  `KeySuperseded`. Added beside them: `Ledger::prefix`, `read_verified_with_keys`,
  `merkle_leaves_with_keys`, `verify_sharded_dir_with_keys`, `ShardedLedger::append_revised`,
  `Directory::revoked` and `decern_identity::mission::HUMAN_KIND`. Authored by @anivar.
- **Each client refuses a success body over 1 MiB.** The error body was already capped at 64 KiB and
  the success body was read whole. The TypeScript client counts the body only where the runtime's
  `fetch` gives a stream. Authored by @anivar.
- **The kernel decides with Cedar 4.14.0, and the proofs compile through `cedar-policy-symcc`
  0.8.0.** Both are exact pins and move together; 0.6.0 pinned 4.13.0 and 0.7.0. A crate that
  depends on a decern library and on `cedar-policy` must name `=4.14.0`. The pinned toolchain is
  Rust 1.100, where 0.6.0 pinned 1.97: the tests and the proofs run on it in CI, the release
  binaries are built with it, and CI tests no older compiler. Authored by @anivar.
- **Release binaries are built from the committed `Cargo.lock`.** The release workflow now passes
  `--locked`, so a release build fails when the lock file does not match the manifests, where it
  used to re-resolve the dependencies without saying so. A build from source is unchanged. Authored
  by @anivar.

### Fixed

- **A second process can no longer fork the single-file ledger.** Two `decern-serve` processes
  pointed at one `--ledger` file both served decisions, each chaining from the same record, so
  the ledger stopped verifying and the next start refused it. Opening a single-file ledger for
  writing now takes an exclusive lock before anything reads the log, and a second writer is
  refused at startup. On Unix the lock is on the ledger file itself, so it holds through any
  path, symbolic or hard link, or mount; on Windows it is a `<ledger>.lock` file beside the
  ledger's canonical path, which a hard link to the ledger, or a link made before the ledger
  existed, does not share. On a network filesystem the lock holds only where the filesystem
  honours it. Readers such as `decern verify` take no lock. A deployment that runs a second
  replica on the same file, or starts the new process before the old one exits, is now refused
  rather than forked. On Unix a child process started while a ledger is open shares its lock
  until it starts its own program, so an open in that moment is refused as a second writer.
  `Ledger::open_anchored` now refuses a ledger whose file is gone when its
  anchor counts a record, as it refuses a truncation; it started a new ledger.
  Authored by @anivar.
- **No Allow under a Mission is recorded after the Mission's termination.** A decision bound to a
  live Mission, then recorded after the Mission was terminated through the same host, was recorded
  and served as the Allow it was evaluated as. The decision is now settled under the ledger's lock
  just before its record lands: one whose Mission was terminated is recorded and answered as a Deny
  with that reason. A Mission terminated at or past its expiry now keeps its termination on record
  for the 30 days a termination is kept past its expiry, rather than being pruned at once, so the
  rule holds then too and `GET /mission/v1/{s256}` reports it terminated. In a `deny_on_first_deny`
  or `permit_on_first_permit` batch each item is recorded before the next is evaluated and the
  semantic follows the decision as recorded, so an item settled to a Deny stops the first and does
  not end the second; `execute_all` records the whole batch as one step on the single-file ledger,
  where the two short-circuit modes record, and sync, one item per step. The order holds on one
  host; under a Postgres store each host has its own Mission registry. Authored by @anivar.
- **A clock set before 1970 is refused rather than read as 1970.** `decern-serve` read such a
  clock as the epoch itself, a time before every expiry, so no principal, Mission or token had
  expired. Every request that needs the time is now answered `503 clock_unavailable` until the
  clock is right; under `--trust-proxy` a batch answers each of its items `decision: false` with
  that code. Under a credential posture the refusal comes before authentication, so an
  unauthenticated caller gets the `503` rather than a `401`. A tree head already computed is still
  served, carrying the time it was signed at.
  Authored by @anivar.
- **A model whose `revoked` is present and not a boolean is refused at load.** The refusal names the
  principal. It loaded with that principal, and every principal under it, active: the parser read
  any non-boolean as false, and the derived value written over the attribute hid the authored one
  from Cedar's schema check. An absent `revoked` is still false. A model
  that carries such a value no longer loads, in `decern-serve`, `decern decide` and `decern prove`
  alike: make it a boolean. Authored by @anivar.
- **A ledger path that names the key file is refused, and a new key file is synced to disk.**
  `decern-serve --ledger k --key k` booted and truncated the key to nothing: the ledger trims an
  unterminated last line, and a key file has none, so the process went on signing with a key no
  longer on disk. The boot now refuses a `--ledger` or `--missions` that names the key file, by
  any spelling of its path or a link to it, and compares `--missions` with `--ledger` the same
  way. The ledger refuses to truncate an unterminated last line that does not begin a record, so
  a file that is not a ledger is never cut. A key file created at boot is synced, with its
  directory, before anything is signed with it. Authored by @anivar.
- **A Postgres head store answers a database error with a `503` instead of hanging.**
  Under `--sharded postgres://…`, a database error before a shard was read, such as the
  connection a database restart closes, left the store's one connection and the request each
  waiting on the other for good. That decision and every later one waited, and `decern-serve` did
  not stop on `SIGTERM`. Such an error is now answered at once with `503`, the store goes on
  to the next request, and the server stops when asked. The store does not reconnect: after the
  database restarts, every decision is refused with `503` until `decern-serve` is restarted. The
  first decision to find the connection closed turns `/healthz` to `503`, so a liveness probe
  restarts the server; a replica that serves no decision meanwhile answers `ok` until one does.
  A database that stops answering without closing the connection, behind a network partition for
  example, still holds the store until TCP gives up: each decision meanwhile is answered `503` at
  the 30-second request deadline, `/healthz` answers `503` once one database call has run for
  30 seconds, and `SIGTERM` waits.
  Authored by @anivar.
- **A Postgres head store bounds its waits.** A start fails after 30 seconds without a ready
  database, where it waited with no deadline, serving nothing and handling no signal; a section
  waits at most 10 seconds for any lock, its shard's first, so a host paused mid-section costs
  each other host `503`s on that shard and, its store serving one section at a time, a wait of up
  to 10 seconds for the sections queued behind, not a hang until it resumes; and `/healthz`
  answers `503` once one database call has run for 30 seconds, a database that stopped answering
  without closing the connection, where it answered `ok` until TCP gave up. The store still sets
  no statement timeout, which a stalled server could not deliver, does not reconnect, and leaves
  the connection's TCP parameters to the URL. Authored by @anivar.
- **A failed directory sync is the anchor's or the manifest's error, never an `Ok`.** On Unix the
  directory open and the sync return their error, so a crash cannot take back an anchor or a
  rollover the caller was told had landed. Both writes discarded that result. A segment rollover
  that fails after its manifest landed stops the ledger, as a half-written record does, until it is
  reopened; one that fails before it is retried on the next append, as before. On a target that is
  not Unix, the Windows build, the directory sync is skipped, as it is for the store's files.
  Authored by @anivar.
- **`/audit/v1/subject` says `truncated` only when a record about the party was left out.** The
  projection stops at 256 records, and it reported the cut as soon as any later record existed,
  so exactly 256 records about a party followed by records about anyone else read as cut. It now
  reports the cut only when a further record names the same handle; a list the bound fits
  exactly is complete.
  Authored by @anivar.
- **A `challenge_basis` array with a non-string item is a malformed challenge.** Answered `422`, as
  every malformed challenge is. The strings were kept and the rest dropped, so `["ownership", 5]`
  was classified as `["ownership"]`, and only an array with no strings at all was refused. Authored
  by @anivar.
- **A malformed Mission approval is refused in JSON.** `POST /mission/v1/approve` answered a body
  that is not an approval request in plain text. It now answers
  `{"error": "mission not approved", "detail": …}`, the shape of every other approval refusal,
  with 400 for JSON that does not parse, 422 for a missing or mistyped field, 415 without a JSON
  content type and 413 past the 2 MiB body limit. The detail quotes the request and is cut at 512
  characters.
  Authored by @anivar.
- **The example adapter's PDP deadline covers the response body, and the body is bounded.** The
  external-authorization adapter's `--pdp-timeout-secs` is a deadline over the whole PDP exchange,
  response body included, and a response body over 64 KiB is refused at the bound. The timeout
  covered the request until the PDP's headers arrived; a PDP that then stalled held the adapter's
  request for as long as it liked, and one that streamed a large body was read into memory whole.
  Authored by @anivar.
- **An organization is not an authorization boundary, and the model says so.** The schema's comments
  and the README say that `Organization` membership and parentage are validated at load and read by
  no built-in policy: an organization is not an authorization boundary, `tenant` is. The comments
  called it the tenancy anchor, which implied an isolation the built-in policy does not provide;
  they call it a grouping now. Authored by @anivar.
- **The parameter digest's documentation claims the binding, not the execution.** It binds a record
  to the arguments decided, so whoever holds the arguments an execution used can tell whether they
  are the ones on record. The comments said the digest "closes the TOCTOU gap between authorized and
  executed", which the ledger cannot see; a PEP that acts on other arguments is caught only by that
  comparison. Authored by @anivar.
- **The README, the website and the Postgres store README say what `--sharded` needs.** Each now
  states that `--sharded` requires `--key` and that `decern verify --sharded` audits a directory
  store only, since a Postgres head store has no `decern verify` path; both READMEs also state
  that a store whose records a key it was not given signed refuses to start, and the README's
  Known-limitations entry on the file head store says when the ledger key is checked, and its
  pointer to the release's known limits no longer lists items from an older release. The website
  drops its version badge, so it carries no version string and no release step has to move one.
  Authored by @anivar.
- **Help text, doc comments and docs no longer contradict what the code does.** The ledger's
  `asserted_by` field was described as present only under bearer validation; it is present
  under every credential posture. The CLI described proving over "every input" rather than the
  model's symbolic input space, and its crate description left out `explain`. The kernel's
  `reasons` were described as present only on an Allow. The Postgres store named a money budget
  that does not exist and said the binaries never depend on it, which a `--features postgres`
  build does. The signed-request posture said only a POST covers `content-digest`. `--help`
  cited sections of the CLI reference by names that are not headings. The MCP walkthrough
  listed five records where its ledger holds six. The README now says the AAuth posture follows
  an individual, unadopted Internet-Draft; that on Windows `decern-serve` does not protect its
  files by permission, refusing to create a `--key` file and loading one without checking who can
  read it; and that the Mission self-approval refusal compares ids only.
  Authored by @anivar.

### Security

- **A caller bound to itself can no longer assert `consent` or `human_approved`.** Under the
  signed-request, SPIFFE and AAuth postures a workload not listed in `--pep` may name only
  itself, and may not describe a party through `properties`; it could still send
  `"consent": true` in `context`, which the consent gate read as the resource owner's word. An
  evaluation or a search from such a caller that carries either key, whatever its value, is
  now refused with `403 caller_mismatch` and nothing is recorded; a batch is refused whole when
  any item, or a default an item inherits, carries one. This holds where the key was dropped
  before: `human_approved` on an action that does not declare it, and either key under a
  Mission, which used to be stripped. Such a workload therefore has no way to carry consent,
  and its access to another party's PII is always denied. A PEP listed in `--pep`, a bearer
  caller and a trusted front may carry the keys as before: `consent` is still the caller's
  word, which decern does not check. The rule knows these two names only; a custom model that
  reads an approval under another name is not covered. Authored by @anivar.
- **A caller bound to itself may not name another party as the decision subject.**
  `context.decision_subject` is the handle the open subject-side audit route is keyed by, and a
  workload posture caller could name any handle, so a record it asserted attached to another
  party's audit view with nothing to tell planted from genuine. The handle now binds as
  `subject.id` does: a workload not listed in `--pep` may name only itself, which the record then
  drops as redundant, and any other handle is `403 caller_mismatch` before anything is evaluated or
  recorded, on the single evaluation, on every batch item, defaults included, and on the searches.
  Bearer and `--trust-proxy` callers are unchanged, as they are for `subject.id`. Authored by
  @anivar.
- **Only a principal the model marks `Human` approves a Mission.** `POST /mission/v1/approve`
  accepted any principal in the tenant that held the scope, an Agent or a Machine included, and
  a Mission so approved set `human_approved` for `MoveMoney`. Approval now refuses an approver
  whose `kind` is not `Human` (422, nothing recorded), and a Mission a registry already holds
  from such an approver backs no decision: a decision under it is denied, and its errors say so.
  The check is the server's, reading `kind` from the model it runs: a model that omits `kind`
  or spells it another way approves nothing, and a workload caller, which may name only itself
  as approver, approves nothing unless its own principal is marked `Human`. The `money-gate`
  proof still covers the flag, not who approved, and whether the caller that names an approver
  speaks for it rests on the caller posture. Authored by @anivar.
- **A Mission stops backing decisions once its approver is revoked, expired or loses the scope.** A
  Mission was held to its approver only at approval, so an approver revoked afterwards, directly
  or through a delegator, kept setting `human_approved` for `MoveMoney` through every Mission it
  had approved, across restarts, until each was terminated or expired. Each decision under a
  Mission now reads the approver from the model the server runs, and a Mission whose approver is
  revoked, past its expiry or no longer holds the scope the decision needs backs nothing: the
  decision is denied, and its errors say so. `POST /mission/v1/approve` refuses a revoked approver too.
  The model is fixed at boot, so a revocation reaches existing Missions at the next restart, as
  it reaches every other decision.
  Authored by @anivar.
- **A principal can no longer approve a Mission for itself.** `POST /mission/v1/approve`, and
  `decern_identity::mission::approve` under it, refuses an approver that is also the agent, and a
  Mission recorded that way by an earlier release no longer backs a decision. Such a Mission set
  `human_approved` for `MoveMoney` with no second principal involved. A deployment that used one id
  for both gives the approval to another principal in the agent's tenant that the model marks
  `Human` and that holds the scope. The refusal compares ids only. Authored by @anivar.
- **The signed-request posture requires `--signed-authority`.** `decern-serve --signed-agent-key` no
  longer starts without `--signed-authority <AUTHORITY>`, this deployment's host and any port
  exactly as its signers' requests carry them, and a signed request whose `@authority` differs is
  refused `401` before any key is consulted. The signature always covered `@authority`, but nothing
  compared it with this deployment, so two deployments trusting the same agent key and audience
  accepted each other's captured requests inside the 60-second freshness window. Add the flag with
  the authority your signers sign for. Authored by @anivar.
- **A Postgres head store refuses a URL to another host that does not require TLS.** The URL went to
  the client as given, and the client's default, `sslmode=prefer`, carries on in plaintext when it
  is told the server has no TLS, which anyone in the network path can say. A `--sharded
  postgres://…` URL, or one given to `PostgresLedgerHeadStore::new`, that names a host other than
  this one must now carry `sslmode=require`: without it the server refuses to start, before it
  connects. A Unix socket, `localhost` and loopback addresses are left alone, judged by `hostaddr`
  when the URL gives one; a name that only resolves to this host counts as another host. Add
  `sslmode=require` to the URL of a deployment that crosses hosts. Authored by @anivar.
- **`decern-serve` bounds what one client can make it hold.** A request's headers must arrive
  within 10 seconds, the idle wait on a kept-alive connection included, and a request still
  waiting on its body after 30 seconds is answered `503`; a ledger append already under way
  finishes first. At most 1,024 connections are held at once, and a stopping server waits 30
  seconds for requests in progress, where a client that sent half a request could keep a
  connection, and a stopping process, alive indefinitely. `Signature` is bounded at 8 KiB like the
  other signature headers, and a repeated label is found without comparing every pair, where a
  large header cost seconds of work before any key was consulted. An entity type, entity id or
  action name over 1 KiB is refused with `413 name_too_large`, and a batch that would record more
  than 16 MiB, its defaults counted once per item that inherits them, is refused whole with `413
  batch_too_large` before anything is recorded; one 123 KB batch could record 120 MB. Bearer and
  SPIFFE callers are authenticated before the body is read, so a caller with no credential is
  refused without the server waiting on its body. An error that quotes the request is cut to 512
  characters in the answer. Authored by @anivar.
- **At most 512 requests are decided, searched, recorded, audited or read as a Mission at once.**
  Each such request runs on a blocking thread and takes one of 512 places; a request that finds them
  taken is answered `503`, `server_busy`, at once, and a request that ran out of time keeps its
  place until its work ends. The Postgres head store also bounds its own queue, at 1,024 sections,
  which the places keep it from reaching. `/healthz` answers `ok` while the places are full, unless
  the store behind them has failed or stalled. Authored by @anivar.
- **An anonymous caller can no longer stall every decision through the tree head.**
  `GET /anchor/v1/tree-head` re-read and re-hashed the whole ledger while holding the lock every
  append needs, on a thread that serves requests: at 150,000 records, twelve anonymous clients
  polling it held a decision for 8 seconds on average. It now notes the record count under the
  lock, reads and hashes that prefix on a blocking thread without it, takes the lock again only
  to sign, and recomputes at most once a second, serving the last head in between; under the
  same load a decision took 5 ms. `/audit/v1/subject` reads the log the same way, one
  projection at a time, since each holds the whole log in memory; the rest wait within the
  30-second request deadline. Decisions, batches and Mission approvals and terminations run on
  blocking threads too, so a slow fsync no longer holds a thread other requests need, and the
  request deadline covers them: a decision whose append has not finished by then is answered
  `503`, and the append still lands.
  Authored by @anivar.
- **A control character in a name is refused, and `decern explain` escapes them.** An entity type,
  entity id or action name was recorded as sent, and `decern explain` printed recorded values as
  they were, so a name carrying terminal control sequences reached the terminal of whoever read the
  record. An evaluation, batch item or search whose subject, resource or action name holds a control
  character is now refused (`400`, `invalid_request`, nothing recorded). `decern explain` writes
  every control character as its escape, a newline included, in each field it prints, which also
  covers records written before this release and printed fields the refusal does not reach: the
  asserted caller, a Mission's reference, the decision subject. The prose form prints neither the
  context nor a challenge; `--json` prints the whole entry as recorded, where JSON escapes only
  U+0000 to U+001F. Characters that are not control characters, a direction override for one, are
  printed as recorded. Authored by @anivar.
- **The Python and TypeScript clients allow only on the JSON boolean `true`.** They read the
  answer's `decision` by truthiness, so a response whose `decision` was the string `"false"`, a
  number or any other non-empty value came back as `allowed`. All three clients now raise an error
  when `decision` is absent or is not a boolean; the Go client, which already refused a wrong type,
  no longer reads an absent or `null` decision as a deny. A conformant decision point always sends a
  boolean, so nothing changes against `decern-serve`. An answer with no `decision`, which each
  client read as a deny, is now an error too. Authored by @anivar.
- **The Python client no longer follows a redirect.** `urllib` re-sends the request headers to the
  redirect target, the bearer token among them. A `3xx` answer is now an error carrying its status
  code. The TypeScript and Go clients still follow redirects with their runtime's defaults, which
  this change did not examine. Authored by @anivar.
- **The ES256 verification path builds on patched constant-time crates.** `crypto-bigint` moves
  to 0.7.8 and `ctutils` to 0.4.5, for timing variability in operations meant to be constant-time
  ([RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387)) and non-constant-time mask
  generation ([RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385)). Both arrive
  through `p256`, which `decern-serve` uses only to verify ES256 SPIFFE JWT-SVIDs, a public-key
  operation; nothing in decern holds a P-256 private key. Authored by @anivar.
- **A `--features postgres` build verifies the database's certificate chain with `rustls-webpki`
  0.103.16.** The pinned 0.103.15 could accept a certificate path through distrusted emSign
  intermediates whose private keys are now public
  ([RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382)). Only a build with the
  Postgres head store carries that crate; the release binaries and every default build pull no TLS
  stack and are not affected. Authored by @anivar.

### Known limits in this release

Carried from 0.6.0: bearer validation verifies `EdDSA` only; keys, trust bundles and provider
key sets load only at startup; no posture keeps a replay cache, so a captured bearer token can
be used until it expires; and two replicas started together on an empty store under different
keys both start, each now answering `503` for a shard the other wrote first, with the store
holding shards under both keys. The AAuth posture now verifies the draft's Ed25519 signature
profile, and still does not verify ES256, signals no refusal but clock skew with a
`Signature-Error` code, and requires `content-digest` on a request with a body. Closed since
0.6.0: the single-file ledger takes a lock, and a Mission's approver is checked at approval and
at each decision. Stated now:

- `GET /audit/v1/subject` reads the whole ledger for every answer, and
  `GET /anchor/v1/tree-head` reads it each time it recomputes: at most once a second, and only
  after a record was written. Both are open. Rate-limit them at whatever fronts the server.
  Under `--sharded` both answer `501`.
- Under `--sharded`, a start and `decern verify --sharded` read each shard's whole history
  under that shard's lock, with no time bound. An append to the shard from another process
  waits meanwhile, and is answered `503` once the wait passes its bound: the 30-second request
  deadline in a directory store, where the record is still written afterwards, or the 10-second
  lock wait under `--sharded postgres://…`.
- Records removed from the end of a log show only against a tree head kept somewhere the
  operator cannot reach. A sharded store has none: the server publishes no tree head for a
  shard and `decern verify --sharded` takes no `--anchor`. Separately, a retired key can still
  sign a shard its successor has not signed.
- No command verifies a Postgres store from outside. `decern verify --sharded` reads a
  directory store only; `decern-serve` checks a Postgres store when it starts, under the key it
  was given.
- The Mission approver check reads `kind` from the model the server runs. It is the server's
  check: the `money-gate` proof covers the approval flag, not who approved, and whether the
  caller that names an approver speaks for it rests on the caller posture. The model is fixed
  at start, so a revocation reaches existing Missions at the next restart; an approver's
  `expiry` acts at the decision.
- The consent rule knows the names `consent` and `human_approved` only, and `consent` from a
  PEP, a bearer caller or a trusted front is still the caller's word.
- A termination answered `503` leaves the Mission terminated in the registry with no record;
  a retry writes it while the registry still holds the Mission.
- Under `--sharded postgres://…` each host has its own Mission registry, and the store sets no
  statement timeout.
- `decern explain` without `--pubkey` exits 0 and says the signature was not checked. Its prose
  form escapes control characters and no other; `--json` prints a record as stored.
- The TypeScript and Go clients follow redirects with their runtime's defaults.
- `/healthz` makes no call of its own to the disk or the database: it answers `503` only after
  a decision has met the failure. The server logs nothing after it starts.
- The Windows build does not protect its files by permission.

## [0.6.0] - 2026-10-20

This release hardens `decern-serve`'s startup and caller configuration. Configurations 0.5.0
started with now refuse to start: `--sharded` without `--key`; a shard store whose records
another key signed, or that holds a shard file with records and no head cursor; `--sharded` with
a scheme other than `postgres://`, or `POSTGRES://…` on a build without the Postgres store;
`--signed-audience`, `--spiffe-audience` or `--aauth-audience` without their posture; the same
`--signed-agent-key` given twice for one agent; an `--aauth-provider` that is not `https://` and
a lowercase host alone; and an AAuth `--pep` that is not an agent identifier in a configured
provider's domain. Requests 0.5.0 accepted are refused when an AAuth token's `sub` is not
`aauth:local@domain` in the issuing provider's domain, its `ps` is not `https://` and a lowercase
host alone, or its `parent_agent` is not an agent identifier. Each is described below.

If you ran `--sharded` without `--key`, 0.5.0 and earlier signed the shared store under a fresh
key on every restart, so only the current run's records verified under the key `/pubkey` named.
No key you can supply extends such a store: move it aside and start with `--key`. Nothing in
the kernel, the Cedar model, the proofs or the SDKs changes.

### Changed

- **An AAuth agent is an agent identifier of the provider that issued its token.** A token's `sub`
  must be `aauth:local@domain` as draft-hardt-oauth-aauth-protocol-11 §5.2 spells it, with `domain`
  the host of the provider named in `iss`; any other `sub` is refused, as is a `parent_agent` that
  is not an agent identifier. Before this, `sub` was taken as sent, so with two providers configured
  either could present the `sub` of the other's agents, including one listed in `--pep`. Under
  `--aauth-provider`, a `--pep` id must be an agent identifier in a configured provider's domain,
  and a provider is named as `https://` and a lowercase host alone (§11.1.1), as is a `ps` claim
  when a token carries one (§5.3.3 step 2), where `https://` with any path was accepted. Authored by
  @anivar.
- **`decern-serve` checks every flag before it writes anything.** A boot refused for a bad
  `--public-url`, a malformed `--standing-issuer-key`, an unknown `--authzen-type-alias` model type
  or a port already taken used to leave the key, the ledger and the Mission registry behind, and
  one refused for an unsupported `--sharded` target the key; it now leaves nothing, so a failed
  deployment can be retried as it stands. `--missions` naming a directory, the shard directory, the ledger file, a path under a file
  or a file that is not JSON, and `--ledger` or `--key` under a directory that does not exist, are
  refused before anything is written; `--ledger` there used to be refused after the key was created,
  and a `--missions` parent directory that does not exist is still created when the registry opens,
  as before. A registry file that is JSON of another shape is refused only when opened, after the
  key and the ledger exist, and leaves its lock file; a failure opening the ledger or the head store
  itself can still leave the key. `--sharded` matches its scheme regardless of case, so
  `POSTGRES://…` reaches the Postgres store instead of becoming a directory named after the URL with
  the password printed in the startup line; any other scheme is refused, and no message repeats the
  URL. `--signed-audience`, `--spiffe-audience` and `--aauth-audience` given without their posture
  are refused instead of ignored. The startup line names the address actually bound. Authored by
  @anivar.

### Fixed

- **`decern-serve` keeps running when it cannot install its Ctrl-C handler.** The failed install
  resolved the shutdown signal at once, so the server stopped as soon as it started; on Unix it now
  waits for SIGTERM alone, as it already did when the SIGTERM handler failed, and elsewhere, with no
  SIGTERM handler, it runs until it is killed. Authored by @anivar.
- **`decern-serve` names all five caller postures where it lists them.** The refusal to start
  with no posture, and the `--trust-proxy` and `--pep` help, named only some of them; they now
  include SPIFFE JWT-SVIDs (`--spiffe-trust-domain`) and AAuth agent tokens (`--aauth-provider`).
  Authored by @anivar.
- **A shard file holding records but no head cursor is refused.** The file head store listed a shard
  only when its cursor was set, so a shard file whose cursor had been removed was skipped by
  `decern verify --sharded` and not counted as history: the store verified as if the file were
  absent, and the next append started the chain again at sequence 0 beside the old records. Such a file is now refused wherever it is read,
  by `decern-serve` at boot before anything is written and by `decern verify --sharded`, as an
  altered store. Authored by @anivar.
- **A second `--signed-agent-key` for the same agent adds a key instead of replacing it.** The
  flag's help, `docs/CLI.md` and the signed-request module all said a key rollover is a second
  entry for the same id with the old one still accepted, but the second entry silently replaced
  the first, so an agent mid-rollover was refused under its old key. Both keys now verify until
  the old one is dropped from the command line: the bound token's `cnf.jwk` must name one of the
  agent's configured keys, and the request signature must verify under that key. The same key
  given twice for one id is refused at startup. Authored by @anivar.

### Security

- **A ledger is extended only by the key that signed it.** `--sharded` without `--key` is refused:
  the shared head store was signed under a fresh ephemeral key on every restart, so each replica's
  records verified under a different key and `/pubkey` only ever named the latest. At boot every
  shard is verified under the key `--key` holds, chain and every signature, one signature check per
  record, as a single-file open already was; a record another key signed refuses the boot, naming
  both key ids where the record names its key. The check runs at boot only: a store with no shards
  boots under any key, so two replicas started at once on an empty store under different keys both
  boot and the store then verifies under neither; start the first replica alone, or give every
  replica the same key before any starts. A shard another replica creates later is checked at the
  next restart. A single-file ledger with records already refused a different key; the refusal now
  names both key ids, and an ephemeral key, or a `--key` file that does not exist, is refused before
  anything is written. An empty ledger file is a new ledger. The startup line marks an ephemeral key
  `(ephemeral)`. Where a Postgres head store already holds shards, a `--key` file that does not
  exist is still created before the refusal. Authored by @anivar.
- **A segment created at rollover is owner-only.** A segmented ledger (`Ledger::open_segmented`)
  created each new segment with the process's default mode, `0644` under the common umask, so
  the records it collected were readable by group and other until the next rollover sealed it
  or the ledger was reopened. Every segment is now created `0600` on Unix; the next rollover
  still seals it `0400`, and a reopen tightens an active segment created before this change,
  as it already did. The manifest beside the segments, which names them with their sequence
  ranges and open times and holds no records, keeps the default mode. Only a segmented ledger
  creates segments: `decern-serve` never opens one (a single file, or a head store under
  `--sharded`), and `decern verify` and `decern explain` read a segmented directory without
  writing to it, so neither was affected. On
  Windows the ledger's files are not written owner-only. Authored by @anivar.

### Known limits in this release

Unchanged from 0.5.0: the AAuth posture does not meet draft-hardt-oauth-aauth-protocol-11 (the
agent token's `alg` must be `EdDSA`, which -11 replaces with `Ed25519`, and the token is taken
from the `Signature-Key` member labelled `sig` while the signature labelled `sig1` is verified, so
no conformant agent passes; this release tightens what the posture checks of a token it does
accept and closes none of those gaps); bearer validation verifies `EdDSA` only; a Mission's
approver is not checked to differ from its agent; the single-file ledger takes no lock; keys,
trust bundles and provider key sets load only at startup; no posture keeps a replay cache; and
what the proofs cover. Stated now: the ledger key check runs at boot only, so two replicas
started at once on an empty store under different keys both boot and fork it. The standards
registry lists each gap.

## [0.5.0] - 2026-10-20

This release fixes a published security advisory, adds the AuthZEN 1.0 batch evaluation, search
and discovery endpoints, and makes the Linux release binaries start. Upgrade if you approve
Missions in a model with more than one tenant: 0.2.0 through 0.4.0 let a principal in one tenant
supply the approval behind a money movement in another
([GHSA-rm33-3hf3-g366](https://github.com/anivar/decern/security/advisories/GHSA-rm33-3hf3-g366)).

Some requests are answered differently: every malformed evaluation request is `400`; signature
headers are parsed as structured fields, so `@method` is signed as sent; a Mission approval for
an agent outside the approver's tenant is `422`; and `/healthz` answers `503` once the ledger has
stopped after a write error. Each is described below.

### Added

- **AuthZEN Access Evaluations.** `POST /access/v1/evaluations` decides several evaluations in
  one exchange (AuthZEN 1.0 §7): top-level `subject`, `action`, `resource` and `context` are
  defaults an item replaces whole; `options.evaluations_semantic` picks `execute_all`,
  `deny_on_first_deny` or `permit_on_first_permit`; answers come back in request order. Every
  evaluated item is admitted, decided and recorded as a single evaluation is, before the batch
  is served — as one durable step on the single-file ledger; an item that is not an evaluation,
  or that this server refuses, is `decision: false` with `context.error` `{status, code,
  message}` and, having decided nothing, is not recorded. Without items the endpoint is the
  single evaluation. At most 1000 items. Discovery advertises `access_evaluations_endpoint`.
  The certification scenario's Batch Core and Batch Properties tests run against
  `examples/authzen-certification/model`. Authored by @anivar.
- **AuthZEN Search.** `POST /access/v1/search/subject`, `/resource` and `/action` (AuthZEN 1.0 §8)
  answer which subjects of a type may perform an action on a resource, which resources of a type a
  subject may act on, and which actions a subject may perform on a resource. Every candidate is
  decided as an evaluation would be, over the same prepared context, so a result is one the
  evaluation endpoint would permit; results come back in the request's type spelling, the searched
  side's id is ignored, and every result comes in one page (pagination is optional in the
  specification and not implemented — a `page.limit` is accepted, a `page.token` is 400). A search
  binds no Mission, is refused under `--require-mission`, and never lists an action a decision
  would refuse for want of one; a caller bound to itself may search for what it may do and not for
  subjects. Each search is recorded once, with the result ids (up to 1000) and the count. Discovery
  advertises the three endpoints. The certification scenario's Search Core and Search Properties
  tests run against `examples/authzen-certification/model`, whose resources now carry `status` and
  whose policies read it, or a PEP's description, so a search finds what an evaluation would
  permit. The searched side's id reaches neither the decision nor the record, which names no
  subject for a subject search and lands in the resource's tenant's shard; a record carries the
  context pruned to what the searched action (or, for an action search, any action) declares.
  `decern-kernel` gains `search_actions` (which prunes per action) and `prune_to_any_declared`; an
  action the schema does not declare now prunes everything but `now`. Authored by @anivar.
- **AuthZEN discovery, and request types in the PEP's own words.** `decern-serve --public-url
  https://pdp.example` serves `GET /.well-known/authzen-configuration` (AuthZEN 1.0 §9), naming
  the decision point and its evaluation endpoint and nothing the deployment does not serve;
  without the flag the document is 404 rather than assembled from a caller's `Host` header.
  `--authzen-type-alias user=Principal` maps a request's entity types onto the model's, and the
  record carries the model's. `X-Request-ID` comes back on every response (§10.1.3). The
  certification scenario's Basic Core and Discovery sub-levels run as tests against
  `examples/authzen-certification/model`. Authored by @anivar.
- **AuthZEN Basic Properties.** What a PEP says about a party — `subject.properties`,
  `resource.properties`, `action.properties` — reaches the policies as `context.subject`,
  `context.resource` and `context.action`, where the action's schema declares it; the rest is
  dropped before evaluation, at every level, and never recorded. Only a caller bound as a PEP
  (`--pep`, a bearer caller, `--trust-proxy`) may describe a party through `properties`; a workload
  bound to itself gets `403 caller_mismatch`, and those three context keys are reserved so there is
  no second way in. The certification scenario's Basic Properties tests (rules 5–8) run against
  `examples/authzen-certification/model`. Authored by @anivar.

### Changed

- **Signature headers are parsed as structured fields.** `Signature-Input` and `Signature` were
  matched against one fixed string shape; the signed-request and AAuth postures now parse them
  as RFC 8941 structured fields and build the RFC 9421 signature base the way the RFC defines it.
  What a signer can notice: `@method` is signed as sent, case included (RFC 9421 §2.2.1),
  where it was uppercased first, so a signature over `POST` no longer covers a request sent as
  `post`. Every line of a signature header is read, joined with `", "` (§2.1), where only the
  first was. The `@signature-params` line is serialized from the parsed input (§3.2 step 7)
  rather than copied, so a signer that signs the serialization §2.3 defines verifies whatever
  optional whitespace its `Signature-Input` carries. `@authority` is host and optional port,
  from an absolute-form request target when there is one and from a single `Host` otherwise,
  where it was always `Host` as sent; a missing or repeated `Host` is refused. A `Host`,
  `Signature-Key`, `Signature-Input`, `Signature` or `Content-Digest` value that is not visible
  ASCII is refused as malformed rather than read as absent, so a GET carrying such a
  `Content-Digest`, once not checked, is refused. Parsing follows RFC 8941 rather than the old
  string shape: a token `keyid`, `created=+1` and a trailing `;` are refused, and a `Signature`
  whose base64 lacks its padding is accepted (RFC 9651 §4.2.7). The profile is otherwise
  unchanged: one signature labelled `sig1`, exactly its covered components in order, `created`
  and `keyid` only, Ed25519 only. The AAuth posture still does not meet
  draft-hardt-oauth-aauth-protocol-11; the standards registry lists where. Authored by @anivar.
- **Every malformed evaluation request is 400, and undeclared context is ignored.** A missing
  field, a wrong type, a body that is not JSON or a content type that is not `application/json`
  answers 400 with the parser's own detail, where the extractor spread them over 400, 415 and 422
  (AuthZEN 1.0 §10.1.1). Context attributes the model's schema does not declare are dropped before
  evaluation instead of denying the request as malformed: no validated policy can read them, so no
  decision can turn on them. Declared attributes keep their schema validation, and what was dropped
  never reaches the ledger. Authored by @anivar.
- **Request bounds are settled at the edge.** An evaluation `context` that is not an object is
  400, as any wrong type is (AuthZEN 1.0 §10.1.1), where it was quietly taken as empty; a
  context over 64 KiB, properties included, is 413 and is neither evaluated nor recorded, and a
  batch whose default context is that large answers each item so without copying it into every
  item. What the record keeps of a `context.mission` is the `{approver, s256}` pair that was
  looked up, never the object as sent. `--authzen-type-alias` refuses to start the server when
  the model type it names is not one the schema declares, or when the request type is one of the
  model's own; `--public-url` is parsed as a URL and refuses a bad port, a bad host or anything
  beyond an origin, and takes any loopback address for a local walkthrough. Authored by @anivar.
- **The Mission read is stated as unbound, and pinned.** `GET /mission/v1/{s256}` answers every
  established caller, a workload bound to itself included, with the Mission's approver, state and
  expiry, so a reference a caller can compute or obtain tells it who approved what and until when.
  It stays unbound because a PEP consults mission state before honoring a grant, and binding it to the
  approver would refuse the agent a Mission authorizes. A test pins the unbound read, so binding it is
  a change of its own. Authored by @anivar.

### Fixed

- **The ledger stops recording after a write error.** When a write failed (a full disk, for
  example), that request was answered `503`, but the next appends went into the file behind the
  partial record. Decisions were served with `200` into a ledger that no longer verified, and
  the server then refused to start. Now a write, flush or sync error on the single-file ledger
  makes it refuse every append until it is reopened, so each later decision is a `503`, and
  `/healthz` answers `503` so a liveness probe restarts the server. The restart trims an
  unterminated record; a record written in full before its sync failed is kept, though its
  request was answered `503`. The sharded ledger writes through its head store, a different
  path this change does not touch. Authored by @anivar.
- **The Linux release binaries start.** The static musl builds of `decern` and `decern-serve`
  failed at startup with "entities error: error during entity deserialization". musl reports
  only the part of the main thread's stack mapped so far, and Cedar refuses to evaluate when
  less than 100 KiB seems left. Reproduced on aarch64; the same failure was measured on x86_64
  on a native kernel under a full-system emulator, and x86_64 appeared to work in Docker on
  Apple Silicon only because that emulation gives the main thread a larger stack. Both binaries
  now run startup, and every `decern` command, on a thread with an explicit 8 MiB stack;
  `decern-serve` handles requests on its async runtime's threads, which musl measures
  correctly. The release workflow runs each built binary once, a `decern decide` and one
  `decern-serve` evaluation, before anything is published. Authored by @anivar.
- **Two claims narrowed to what the code checks.** `decern prove` states `money-gate` as
  "MoveMoney is never allowed unless the context carries human_approved = true" and
  `consent-gate` as "… unless the context carries consent = true", where they said "explicit
  human approval" and "explicit consent". The solver checks a context flag. The server sets
  `human_approved` only from a Mission covering `MoveMoney`, and `approve` does not check that
  the approver is human or someone other than the agent; the enforcement point sets
  `consent`. The proofs are unchanged. Bearer validation is described as RFC 9068's checks for
  `EdDSA` tokens: RFC 9068 §2.1 requires a conforming resource server to support RS256, which
  this does not, and the standards registry now says so. Authored by @anivar.
- **A bearer token with `"crit": null` is refused.** A bearer token whose header carries
  `"crit": null` is refused like any other `crit`, where `null` read as absent. `decern prove
  --timeout` is described as a bound on the whole run: cvc5 stops itself 60 seconds after it
  starts, so a higher value adds no solver time. Authored by @anivar.
- **The documentation says what the code does.** Claims that overstated or named what is not
  there are corrected across the repository:
  - The README, `ARCHITECTURE.md`, the CLI reference, both diagrams and the website name all five
    caller postures, AAuth included, and say the AAuth posture does not yet meet
    draft-hardt-oauth-aauth-protocol-11.
  - `SECURITY.md` says the proofs cover the Cedar model's symbolic input space, not the entire
    input space.
  - `docs/CLI.md` gains *Pairing with an identity provider* (bearer validation verifies `EdDSA`
    tokens only, so a provider that signs `RS256` belongs in front), *What a record keeps*, and
    *What a deployment supplies* (plain HTTP, keys read once at startup, no logging after
    startup, one unbounded ledger file, a Mission registry per replica, and no check that the
    served model is the proven one). The Missions section says a Mission binds only `Read`,
    `MoveMoney` and `AccessPII`.
  - The gateway adapter's Traefik example no longer says Traefik strips a client's
    `X-Forwarded-Subject` (an earlier middleware must), and its Envoy example, which also let a
    client choose its method and URI, is replaced by what a configuration must do. The adapter
    README says each gateway example forwards the HTTP method as the action name, which the
    builtin model does not declare.
  - The MCP example says its server approves a Mission in `corp`'s name; the client READMEs say
    `context` reaches the policies where the schema declares it and that `reasons` names
    deciding forbid policies too; the Postgres store README drops a money-budget gate that does
    not exist and says the Mission registry stays a per-host file.
  - `RELEASES.md` says which version fields each publish workflow checks and that the SBOMs are
    not signed; `DEPENDENCIES.md` gives the exact `cedar-policy` and `cedar-policy-symcc` pins;
    the README no longer calls the file head store Unix-only; `decern-proof` no longer names a
    flag that does not exist; the JCS module states that `-0` and `0` digest alike; and the
    0.4.0 known limits, which said the AAuth posture followed draft `-10`, name its replay limit.
    `scripts/changelog.sh --preview` exits 0 when the last fragment ends in a newline.
    Authored by @anivar.

### Security

- **A Mission's approval stays inside one tenant.** `POST /mission/v1/approve` refuses a Mission
  whose agent is not a principal in the approver's tenant (`422`, nothing recorded): an agent
  in another tenant, and an agent the model does not name, are refused in the same words. At
  decision time a Mission backs a decision only about a subject the model names, approved by a
  principal the model names, in the same tenant, so a cross-tenant Mission a registry already
  holds no longer counts. Before this, a principal in one tenant holding `move_money` could
  supply the approval behind a money movement in another (GHSA-rm33-3hf3-g366, affecting 0.2.0
  through 0.4.0). The approver is still not checked to differ from the agent; that is a
  separate decision. Authored by @anivar.
- **Standing tokens refuse `crit` and honour `nbf`.** A standing token whose header names a
  critical extension is refused, where it was ignored and the token verified — RFC 7515 §4.1.11
  requires the refusal of a recipient that implements no extension. An `nbf` in the future
  refuses the token, and `exp` and `nbf` are read as RFC 7519 NumericDates: a fractional `exp`
  is checked rather than read as missing, an `exp` too large for an unsigned 64-bit integer
  reads as a far expiry where it was refused as missing, and a non-numeric `exp` is refused as
  `standing_token exp is not a number` in place of `standing_token has no exp`. No standing token
  ever changed a decision — a challenge is taken out of the context before the kernel runs — but
  a validly signed one naming a critical extension, or not yet valid, could put a challenge
  answer on the record. Still open: a standing token needs no `typ` (only an access-token `typ`
  is refused), and header parameters that are not critical are ignored, as RFC 7515 §4 requires.
  Authored by @anivar.

### Known limits in this release

Unchanged from 0.4.0 — consent, log pinning, `--trust-proxy`, replay, standing tokens, the
SPIFFE posture's two ECDSA encodings, AAuth replay, and what the proofs cover — with these
stated now:

- **The AAuth posture does not meet draft-hardt-oauth-aauth-protocol-11.** It requires the
  agent token's `alg` to be `EdDSA`, which -11 replaces with `Ed25519`, and it takes the token
  from the `Signature-Key` member labelled `sig` while verifying the signature labelled `sig1`;
  the drafts pair the two by label, so no conformant agent passes. The standards registry lists
  each gap.
- **Bearer validation verifies `EdDSA` tokens only**, so it is not a conforming RFC 9068
  resource server, which §2.1 requires to support RS256. An identity provider that signs
  `RS256` belongs in front ([#226](https://github.com/anivar/decern/issues/226)).
- **A Mission's approver is not checked to differ from its agent**, so an agent holding
  `move_money` can approve its own money movement
  ([#229](https://github.com/anivar/decern/issues/229)).
- **The single-file ledger takes no lock.** Two processes on one ledger file both serve
  decisions and fork the chain; run one process per file
  ([#243](https://github.com/anivar/decern/issues/243)).
- **Keys, trust bundles and provider key sets load only at startup**
  ([#227](https://github.com/anivar/decern/issues/227)), and after a ledger write error the
  server records nothing until it is restarted.
- **Under `--sharded postgres://…` each replica keeps its own Mission registry**
  ([#228](https://github.com/anivar/decern/issues/228)).

## [0.4.0] - 2026-10-09

### Added

- **`decern-serve` can establish its caller from an AAuth agent token.** `--aauth-provider
  ISS=PATH` (repeatable) and `--aauth-audience` make the deciding and mission-lifecycle routes
  require an `aa-agent+jwt` presented per `draft-hardt-oauth-aauth-protocol` in
  `Signature-Key: sig=jwt; jwt="…"`, with the request signed under RFC 9421 by the key the
  token's RFC 7800 `cnf` confirms. This serves the draft's **identity-based access** mode,
  where the resource applies its own policy to a verified agent identity; the PS-asserted and
  federated modes need a Person Server, which decern does not implement. Two profile decisions
  are stated rather than implied. Providers are **pinned, never discovered** — the draft says
  to fetch the issuer's JWKS, and this deployment instead checks that `dwk` names that document
  and selects from a key set configured at startup, which the draft contemplates where it notes
  a resource pre-caching provider keys does not need the fetch; an agent from a provider this
  deployment was never told about is refused. And **`content-digest` is required on a bodied
  request**, which the draft's example component list does not carry: every AuthZEN evaluation
  is a POST, and RFC 9421 §1.4 assigns component requirements to the profile, so an agent that
  does not sign the digest is refused rather than allowing one captured signature to authorize
  any body at that path. `EdDSA` only. Unlike the signed-request posture, the agent token's own
  signature is verified against its provider's key, because here the token is the provider's
  assertion about which key the agent holds. A verified agent is a **workload** and may name
  only itself unless listed in `--pep`. `jti` is required and shape-checked but not used for
  replay detection — there is no nonce cache — and `parent_agent` is shape-checked and never
  reaches the kernel. `examples/aauth/` runs the whole posture with no agent
  provider and no network, and asserts both profile refusals. Authored by @anivar.

### Changed

- **The kernel and the proof harness move to cedar-policy 4.13.0 and cedar-policy-symcc 0.7.0.**
  The nine invariants and the negative controls prove unchanged on the built-in model. The
  `rustls` the optional `decern-store-postgres` crate pulls in moves to 0.23.45, which closes
  RUSTSEC-2026-0285; the default build carries no TLS stack and was never affected. Authored by
  @anivar.
- **The changelog check covers the example components, not just the crates and SDKs.** It asked
  for a fragment on `crates/` and `sdks/` only, so a behaviour change in `examples/ext_authz_adapter`
  — the forwarded-header refusal in this same release — passed with nothing in the release notes.
  The adapter is a binary people deploy and the MCP example is a server people run, so both now
  need an entry or the `no-changelog` label. Walkthrough scripts, tests, model fixtures, READMEs
  and lockfiles still do not, because none of them changes what a deployment does. Authored by
  @anivar.
- **The RustCrypto line moves together: ed25519-dalek 3.0, p256 0.14, sha2 0.11, getrandom 0.4
  and, through them, signature 3.0.** Nothing a caller sees changes: key, signature and digest
  formats are the same bytes, the test suite (which signs with fixed keys) passes unchanged, and
  the proofs are unaffected. ed25519-dalek, p256, sha2 and signature now resolve to one version
  each where the tree carried two; getrandom still has the older versions `ring` and
  `rand_core` pin beside it. Authored by @anivar.

- **Release assets are signed as Sigstore bundles.** Each binary and `SHA256SUMS` now ships
  with a `<file>.sigstore.json` carrying the signature, the signing certificate and the
  transparency-log entry, written by cosign 3, in place of the `.sig` and `.pem` pair earlier
  releases carried. `SECURITY.md` shows the `cosign verify-blob --bundle` command and the
  identity to check against; older releases verify as before. Authored by @anivar.

- **The AAuth posture follows draft `-11`.** A request that presents no agent token is
  answered `401` with `AAuth-Requirement: requirement=agent-token`, the draft's own challenge,
  and never through `WWW-Authenticate`. An `iat` ahead of this server's clock is tolerated up to
  the signature window (five seconds, the same tolerance a signature's `created` gets) and
  refused beyond it with `Signature-Error: error=clock_skew`, where it was refused at zero
  tolerance and without a signal. A token claiming a lifetime above 24 hours is refused — the
  draft says an agent token SHOULD NOT exceed that, and leaves the bound to the verifier.
  Everything the posture already implemented is unchanged in `-11`. Authored by @anivar.

### Fixed

- **The ext_authz adapter refuses a duplicated forwarded header instead of choosing one.**
  `HeaderMap::get` returns the first copy and ignores the rest, so a gateway that appended
  its own header rather than replacing a client-supplied one had the adapter authorize
  whichever copy arrived first — a client's `x-forwarded-method: Read` ahead of the gateway's
  `Write` is exactly the fail-open the adapter exists to prevent. Subject, method and URI are
  all checked now, and a duplicate is refused `403` before the PDP is consulted, so nothing is
  evaluated and nothing is recorded. Identical copies are refused too: the adapter cannot tell
  which copy the gateway set, so agreement between them is not evidence that the client did
  not supply one. A deployment whose gateway appends rather than replaces these headers will
  start seeing refusals, which is the misconfiguration becoming visible rather than a new
  restriction. Authored by @shaurya703, reported by @anivar.

### Known limits in this release

Unchanged from 0.3.0 — consent, log pinning, `--trust-proxy`, replay, standing tokens, and
what the proofs cover — with two additions:

- **The SPIFFE posture accepts both ECDSA encodings of a valid signature.** ES256 signers do
  not normalize `s` and RFC 7518 does not require it, so refusing the high-S form would refuse
  honest issuers. Nothing here keys on a token's bytes, so the twin is one more replay form,
  which the replay limit already covers.
- **The AAuth posture does not detect replay.** `jti` is required and shape-checked but
  nothing keys on it, so a captured request verifies again until 60 seconds after its
  `created`, and a replayed allow records again.

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
  Verified end to end with a shipping client: allow, tenant-deny as a tool error the
  model reads, approved money movement, and the insufficient-scope 403 —
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
