// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! decern-serve — a thin PDP: every decision is proven-model-evaluated AND recorded before it is served.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path as UrlPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use decern_identity::{IdentityError, mission, mission::Mission};
use decern_kernel::{Directory, EntityRef, Kernel, Model};
use decern_ledger::{Entry, Ledger, LedgerError, Party, ShardedLedger, UNATTRIBUTED_SHARD};
use decern_store::{FileLedgerHeadStore, FileMissionRegistry, MissionRegistry, StoreError};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Parser)]
#[command(
    name = "decern-serve",
    version,
    about = "Thin proven-decision PDP with a tamper-evident ledger"
)]
struct Args {
    /// Model directory; omit for the built-in model.
    #[arg(long)]
    model: Option<PathBuf>,
    /// Single-file ledger path (default backend). Mutually exclusive with `--sharded`.
    #[arg(long, conflicts_with = "sharded")]
    ledger: Option<PathBuf>,
    /// Hosted mode. Target is either a directory (per-shard `flock` head store —
    /// several `decern-serve` processes on ONE host share one tamper-evident
    /// ledger) or a `postgres://` URL (multi-HOST head store, requires building
    /// with `--features postgres`). Mutually exclusive with `--ledger`.
    #[arg(long, value_name = "DIR_OR_POSTGRES_URL")]
    sharded: Option<String>,
    /// 32-byte hex signing seed file; created if absent. Omit for an ephemeral key.
    #[arg(long)]
    key: Option<PathBuf>,
    /// Mission registry file — the durable record of approved Missions the mint path
    /// checks (`decern-identity`). Default: `decern-missions.json` alongside the ledger.
    #[arg(long, value_name = "PATH")]
    missions: Option<PathBuf>,
    /// Require every decision to name a live Mission in `context.mission`.
    /// When set, client-supplied `human_approved` / `consent` are ignored; those
    /// flags are derived server-side from the verified Mission (or the decision
    /// is Denied). Start opt-in; operators harden MoveMoney behind this flag.
    #[arg(long)]
    require_mission: bool,
    #[arg(long, default_value = "127.0.0.1:8080")]
    addr: String,
}

/// The default single-file ledger path when neither `--ledger` nor `--sharded`
/// is given. Applied at the use site (not as a clap `default_value`) so that a
/// present-but-default `--ledger` cannot slip past the `--sharded` conflict.
const DEFAULT_LEDGER: &str = "decern-ledger.jsonl";

/// The mission-registry filename used when `--missions` is not given.
const DEFAULT_MISSIONS_FILE: &str = "decern-missions.json";

/// The default mission-registry path: alongside the ledger it accompanies.
///
/// The rule is explicit so a `postgres://` sharded target is never `Path::join`ed as
/// if it were a directory (a URL is not a path):
///   - `--ledger <file>` given → sibling of that file.
///   - `--sharded <dir>` (a directory target) → `<dir>/decern-missions.json`.
///   - default single-file ledger, or a `--sharded postgres://…` target → the
///     filename in the current directory (alongside the default ledger).
fn default_missions_path(ledger: Option<&PathBuf>, sharded: Option<&String>) -> PathBuf {
    if let Some(l) = ledger {
        return l
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.join(DEFAULT_MISSIONS_FILE))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_MISSIONS_FILE));
    }
    if let Some(target) = sharded {
        let is_pg = target.starts_with("postgres://") || target.starts_with("postgresql://");
        if !is_pg {
            return Path::new(target).join(DEFAULT_MISSIONS_FILE);
        }
    }
    PathBuf::from(DEFAULT_MISSIONS_FILE)
}

/// The recording backend. Both arms are fail-closed by construction: an
/// `append` that cannot durably commit returns `Err`, never a silent `Ok`, so
/// `record_and_respond` turns either failure into a 503 — a decision is never
/// served unrecorded regardless of backend.
enum LedgerBackend {
    /// Sovereign single-file ledger (default), serialized in-process.
    Single(Mutex<Ledger>),
    /// Hosted per-shard ledger over a `flock` head store, safe for several
    /// processes on one host to extend concurrently.
    Sharded(ShardedLedger),
}

#[derive(Clone)]
struct AppState {
    kernel: Arc<Kernel>,
    /// The boot-pinned model. `mission::approve` reads the approver's authority from
    /// this SAME base model (not the live directory), so a Mission approval is bounded
    /// by exactly what a token minted under it would later be bounded by.
    model: Arc<Model>,
    backend: Arc<LedgerBackend>,
    /// The durable record of approved Missions. Held so a mission's termination
    /// outlives any single in-memory handle and is seen across processes.
    missions: Arc<FileMissionRegistry>,
    pubkey: VerifyingKey,
    /// When true, every decide must name a live `context.mission`.
    require_mission: bool,
}

/// Resolve the ledger shard for a decision: the subject's directory tenant.
///
/// Security-sensitive — the shard is the tenant-isolation boundary of the
/// tamper-evident log, so it is derived server-side from `dir`, never from the
/// request. Rules:
///   - subject is a known principal with a non-empty tenant → that tenant.
///   - subject unknown, or known with an empty tenant → [`UNATTRIBUTED_SHARD`].
///   - subject's tenant literally equals the reserved [`UNATTRIBUTED_SHARD`]
///     name → `Err`. The kernel does NOT reject such a tenant at load (see
///     report), so a REAL tenant named `__system__` reaching here would silently
///     co-mingle with the unattributed shard. We fail closed instead: the caller
///     turns this into a 503, never a quietly-misfiled Allow. (`serve` also
///     refuses to boot a `--sharded` deployment whose directory contains such a
///     tenant — this per-decision guard is defense in depth.)
fn resolve_shard(dir: &Directory, subject_id: &str) -> Result<String, String> {
    match dir.principals.get(subject_id) {
        Some(p) if !p.tenant.is_empty() => {
            if p.tenant == UNATTRIBUTED_SHARD {
                return Err(format!(
                    "subject {subject_id}'s tenant collides with the reserved shard {UNATTRIBUTED_SHARD:?}"
                ));
            }
            Ok(p.tenant.clone())
        }
        _ => Ok(UNATTRIBUTED_SHARD.to_owned()),
    }
}

/// Reject booting a `--sharded` deployment whose directory contains any tenant
/// (on a principal, resource, or org) literally equal to the reserved
/// [`UNATTRIBUTED_SHARD`] name. Defense in depth: the kernel already refuses
/// this at `Directory::validate` / `Kernel::new`, so a normal boot never
/// reaches here with a colliding model — this catches a hand-built / bypassed
/// directory and turns "some requests 503" into "this deployment never starts".
fn reserved_tenant_collision(dir: &Directory) -> Option<String> {
    let from_principals = dir
        .principals
        .values()
        .find(|p| p.tenant == UNATTRIBUTED_SHARD)
        .map(|p| format!("principal {}", p.id));
    let from_resources = || {
        dir.resources
            .values()
            .find(|r| r.tenant == UNATTRIBUTED_SHARD)
            .map(|r| format!("resource {}", r.id))
    };
    let from_orgs = || {
        dir.orgs
            .values()
            .find(|o| o.tenant == UNATTRIBUTED_SHARD)
            .map(|o| format!("org {}", o.id))
    };
    from_principals.or_else(from_resources).or_else(from_orgs)
}

#[derive(Deserialize)]
struct Ref {
    #[serde(rename = "type")]
    ty: String,
    id: String,
}

/// AuthZEN action: an object with a `name` (optional `properties` are accepted and ignored).
#[derive(Deserialize)]
struct Action {
    name: String,
}

#[derive(Deserialize)]
struct DecideReq {
    subject: Ref,
    action: Action,
    resource: Ref,
    #[serde(default)]
    context: Value,
    /// Optional party the decision affects (≠ acting subject, ≠ sponsor).
    #[serde(default)]
    decision_subject: Option<Ref>,
}

fn load_signing_key(path: Option<&PathBuf>) -> Result<SigningKey> {
    let mut seed = [0u8; 32];
    match path {
        Some(p) if p.exists() => {
            let hex = std::fs::read_to_string(p)
                .with_context(|| format!("reading key {}", p.display()))?;
            seed = hex::decode(hex.trim())
                .context("decoding key hex")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
        }
        other => {
            getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("generating key: {e}"))?;
            if let Some(p) = other {
                std::fs::write(p, hex::encode(seed))
                    .with_context(|| format!("writing key {}", p.display()))?;
            }
        }
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// AuthZEN Access Evaluation response: a boolean `decision`, with any reasons (on allow)
/// or errors (on deny) under `context`.
fn evaluation_body(decision: bool, reasons: &[String], errors: &[String]) -> Value {
    let mut body = json!({ "decision": decision });
    let mut ctx = serde_json::Map::new();
    if !reasons.is_empty() {
        ctx.insert("reasons".into(), json!(reasons));
    }
    if !errors.is_empty() {
        ctx.insert("errors".into(), json!(errors));
    }
    if !ctx.is_empty() {
        body["context"] = Value::Object(ctx);
    }
    body
}

/// The server's own wall clock in epoch seconds — the single time authority for every
/// decision. Never read from a request body (see `decide`).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether every socket address `addr` resolves to is loopback. The decision PDP and the
/// mission-mutation endpoints are unauthenticated by design (they trust an authenticating
/// proxy or a trusted network), so a non-loopback bind is flagged at startup. An address
/// that does not resolve here is treated as loopback: the `bind` below will fail and
/// report it, so there is no second warning to emit.
fn addr_is_loopback(addr: &str) -> bool {
    use std::net::ToSocketAddrs;
    match addr.to_socket_addrs() {
        Ok(mut it) => it.all(|s| s.ip().is_loopback()),
        Err(_) => true,
    }
}

/// Write the audit record, or hand back the fail-closed 503 the whole service rests on.
/// `None` = the record is durable, so the caller builds its own success response;
/// `Some(resp)` = it could not be written, so this 503 must be returned instead. No
/// transition — a decision OR a Mission lifecycle event — is ever reported as succeeded
/// unless its record landed.
fn record_or_503(append: impl FnOnce() -> Result<(), LedgerError>) -> Option<Response> {
    match append() {
        Ok(()) => None,
        Err(e) => Some(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(
                    json!({ "error": "not recorded; refusing to serve", "detail": e.to_string() }),
                ),
            )
                .into_response(),
        ),
    }
}

/// Serve a decision ONLY if its audit record was written. An append failure returns 503 —
/// a decision that cannot be recorded is never served. This is the whole contract.
fn record_and_respond(
    decision: bool,
    reasons: Vec<String>,
    errors: Vec<String>,
    append: impl FnOnce() -> Result<(), LedgerError>,
) -> Response {
    match record_or_503(append) {
        Some(unavailable) => unavailable,
        None => (
            StatusCode::OK,
            Json(evaluation_body(decision, &reasons, &errors)),
        )
            .into_response(),
    }
}

/// Append `entry` to whichever backend is configured, fail-closed. `shard` is the
/// server-derived ledger shard: `Some(Ok(shard))` for the sharded backend, `None` for
/// the single-file backend; a shard-resolver error (or the impossible `None` on the
/// sharded arm) becomes a ledger error → 503, never a panic or a misfiled record.
fn append_to_backend(
    backend: &LedgerBackend,
    shard: Option<Result<String, String>>,
    entry: Entry,
) -> Result<(), LedgerError> {
    match backend {
        // A poisoned mutex (a prior append panicked mid-write) fails CLOSED as a 503.
        LedgerBackend::Single(m) => match m.lock() {
            Ok(mut g) => g.append(entry).map(|_| ()),
            Err(_) => Err(LedgerError::Io {
                path: "ledger".into(),
                err: "ledger mutex poisoned; refusing to serve".into(),
            }),
        },
        LedgerBackend::Sharded(s) => {
            let resolver_err = |err: String| LedgerError::Io {
                path: "<sharded ledger, shard resolver>".into(),
                err,
            };
            let shard = match shard {
                Some(Ok(shard)) => shard,
                Some(Err(err)) => return Err(resolver_err(err)),
                None => return Err(resolver_err("shard unresolved for sharded backend".into())),
            };
            s.append(&shard, entry).map(|_| ())
        }
    }
}

/// The ledger shard for a subject: `Some(resolve_shard(...))` on the sharded backend
/// (derived server-side from the directory), `None` on the single-file backend.
fn shard_for(
    backend: &LedgerBackend,
    dir: &Directory,
    subject_id: &str,
) -> Option<Result<String, String>> {
    match backend {
        LedgerBackend::Sharded(_) => Some(resolve_shard(dir, subject_id)),
        LedgerBackend::Single(_) => None,
    }
}

/// Derive the accountable-owner ("sponsor") for a decision: the pure ROOT of
/// `subject_id`'s delegation chain, resolved server-side from the directory —
/// never a decision input, never read from the request body.
///
/// Three cases, discriminated in this exact order (the membership check FIRST,
/// because `ancestors_of` returns an empty vec for BOTH a self-root and an
/// unknown id — the empty vec alone cannot tell them apart):
///   - `subject_id` is NOT a known principal → `None` (a global/static-token
///     caller the directory doesn't recognize; nothing to stand behind).
///   - known, with ancestors → the LAST ancestor (the root of the chain), not
///     the nearest delegator.
///   - known, no ancestors → a self-sponsored root: the subject stands behind
///     itself, so `sponsor.id == subject_id`.
///
/// The caller leaves `sponsor_source` at its `Derived` default; this function
/// only ever computes, never asserts.
fn resolve_sponsor(dir: &Directory, subject_id: &str) -> Option<Party> {
    if !dir.contains(subject_id) {
        return None;
    }
    // Chain is nearest-first, root LAST; a self-root's chain is empty → itself.
    // `validate()` gates kernel load and rejects cycles, so on a served kernel
    // this last element is always the true root, never a cycle member.
    let root = dir
        .ancestors_of(subject_id)
        .pop()
        .unwrap_or_else(|| subject_id.to_owned());
    Some(Party {
        kind: "Principal".to_owned(),
        id: root,
    })
}

async fn decide(State(st): State<AppState>, Json(req): Json<DecideReq>) -> Response {
    let now_s = now_secs();
    let mut ctx = if req.context.is_object() {
        req.context
    } else {
        json!({})
    };
    // `now` is a server-derived fact, like `sponsor` and `shard` below — the PEP
    // is the clock authority. Set it UNCONDITIONALLY from the server clock,
    // overriding any body-supplied value: the kernel uses `context.now` as its
    // sole time source for the decay/expiry gate, so honoring a caller's `now`
    // would let `{"now":0}` win an Allow for an expired principal.
    ctx["now"] = json!(now_s);
    let subject = EntityRef {
        ty: req.subject.ty,
        id: req.subject.id,
    };
    let resource = EntityRef {
        ty: req.resource.ty,
        id: req.resource.id,
    };
    let action = req.action.name;

    // Decision-under-mission: bind (and optionally require) a live Mission.
    // Client-supplied human_approved/consent are stripped whenever a mission is
    // in play; the server re-derives them from the verified grant.
    let mission_bind = bind_mission(
        st.missions.as_ref(),
        st.require_mission,
        &subject.id,
        &action,
        &ctx,
        now_s,
    );
    let (mission_ref, mission_errors) = match mission_bind {
        // No Mission named and none required: `context` is left as the caller sent
        // it, including any approval flags. That is this server's standing trust
        // boundary — the endpoints are unauthenticated by design and the PEP in
        // front supplies the context — not something Missions relax. It does mean
        // approval is server-derived only under a Mission, so an operator who wants
        // that guarantee for money must run `--require-mission`.
        MissionBind::None => (None, Vec::new()),
        MissionBind::Ok(mref) => {
            apply_mission_context(&mut ctx, &action);
            (Some(mref), Vec::new())
        }
        MissionBind::Deny(errs) => {
            // Strip forged approval flags; force a Deny path (kernel will Deny
            // MoveMoney without human_approved, etc.) and surface the mission errors.
            strip_client_approval_flags(&mut ctx);
            (None, errs)
        }
    };
    // `mission` is not in the Cedar context schema — strip before check, re-attach
    // on the ledger Entry (Entry.mission + context.mission for auditors).
    let mission_for_context = ctx.get("mission").cloned();
    if let Some(obj) = ctx.as_object_mut() {
        obj.remove("mission");
    }

    let mut r = st.kernel.check(&subject, &action, &resource, &ctx);
    if !mission_errors.is_empty() {
        r.decision = false;
        r.errors.extend(mission_errors);
        r.reasons.clear();
    }

    // Accountable-owner, derived server-side from the delegation chain BEFORE
    // `subject.id` is moved into the entry. Never read from the request body.
    let sponsor = resolve_sponsor(st.kernel.directory(), &subject.id);

    // Shard (sharded backend only), likewise derived server-side from the
    // directory BEFORE `subject.id` is moved. `None` for the single-file
    // backend, which has no shards. Resolution errors (reserved-name collision)
    // are carried into the append closure so they fail closed as a 503.
    let shard = shard_for(&st.backend, st.kernel.directory(), &subject.id);

    // The party a decision is ABOUT. Only the caller knows whose data a request
    // concerns, so this one is caller-named — but a name the directory cannot
    // vouch for is refused rather than recorded. An accountability column that
    // accepts any string is decoration, and this one is bound into
    // `parameter_digest` below. Caller-named, server-validated; `sponsor` above
    // stays strictly server-derived.
    let decision_subject = match req.decision_subject {
        None => None,
        Some(r) => {
            if !st.kernel.directory().contains(&r.id) {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({
                        "error": "unknown decision_subject",
                        "detail": format!(
                            "decision_subject {} is not a principal this directory knows",
                            r.id
                        ),
                    })),
                )
                    .into_response();
            }
            Some(Party {
                kind: r.ty,
                id: r.id,
            })
        }
    };

    if let Some(m) = &mission_for_context {
        ctx["mission"] = m.clone();
    }

    // Bind the exact parameters evaluated: subject/action/resource + post-mission ctx.
    let parameter_digest = Some(decern_ledger::parameter_digest(&json!({
        "subject": {"type": subject.ty, "id": subject.id},
        "action": action,
        "resource": {"type": resource.ty, "id": resource.id},
        "context": ctx,
        "mission": mission_ref.as_ref().map(|m| json!({"approver": m.approver, "s256": m.s256})),
        "decision_subject": decision_subject.as_ref().map(|p| json!({"kind": p.kind, "id": p.id})),
    })));

    let entry = Entry {
        ts_ms: now_s.saturating_mul(1000),
        subject_type: subject.ty,
        subject_id: subject.id,
        action,
        resource_type: resource.ty,
        resource_id: resource.id,
        context: ctx,
        decision: r.decision,
        reasons: r.reasons.clone(),
        sponsor,
        parameter_digest,
        mission: mission_ref,
        decision_subject,
        ..Default::default()
    };

    let backend = st.backend.clone();
    record_and_respond(r.decision, r.reasons, r.errors, move || {
        append_to_backend(&backend, shard, entry)
    })
}

/// Outcome of resolving `context.mission` against the registry.
enum MissionBind {
    /// No mission named and `--require-mission` is off.
    None,
    /// Live Mission bound; caller should inject server-side approval flags.
    Ok(decern_ledger::MissionRef),
    /// Mission required or named but invalid — force Deny with these errors.
    Deny(Vec<String>),
}

fn strip_client_approval_flags(ctx: &mut Value) {
    if let Some(obj) = ctx.as_object_mut() {
        obj.remove("human_approved");
        obj.remove("consent");
    }
}

/// Map action → required scope name (mirrors the scope-gate convention).
///
/// `None` means "this action has no scope mapping", which under a Mission is a
/// refusal, not a pass — see `bind_mission`. An action added to the model without
/// a mapping here must not inherit every Mission's approval by omission.
fn scope_for_action(action: &str) -> Option<&'static str> {
    match action {
        "Read" => Some("read"),
        "MoveMoney" => Some("move_money"),
        "AccessPII" => Some("pii:read"),
        _ => None,
    }
}

/// After a Mission is verified, set approval flags from the grant — never from the body.
///
/// The flags say only what the grant establishes: an approver, holding the scope,
/// approved this action for this agent. `bind_mission` has already refused any
/// action the grant does not cover, so each flag set here is backed by that check.
fn apply_mission_context(ctx: &mut Value, action: &str) {
    strip_client_approval_flags(ctx);
    // A verified Mission that covers the action is the human/consent approval.
    if action == "MoveMoney" {
        ctx["human_approved"] = json!(true);
    }
    // Consent is asserted only where the action is itself the consent-bearing one.
    // `Read` is not: a Mission approving reads is not a data subject's consent, and
    // recording it as one would put a claim in the ledger the grant never made.
    if action == "AccessPII" {
        ctx["consent"] = json!(true);
    }
}

fn bind_mission(
    registry: &dyn MissionRegistry,
    require: bool,
    subject_id: &str,
    action: &str,
    ctx: &Value,
    now: u64,
) -> MissionBind {
    let mission_val = ctx.get("mission");
    let named = mission_val.is_some() && !mission_val.map(|v| v.is_null()).unwrap_or(true);
    if !named {
        return if require {
            MissionBind::Deny(vec![
                "context.mission is required (--require-mission)".into(),
            ])
        } else {
            MissionBind::None
        };
    }
    let Some(obj) = mission_val.and_then(|v| v.as_object()) else {
        return MissionBind::Deny(vec![
            "context.mission must be an object {approver,s256}".into(),
        ]);
    };
    let approver = obj.get("approver").and_then(|v| v.as_str()).unwrap_or("");
    let s256 = obj.get("s256").and_then(|v| v.as_str()).unwrap_or("");
    if approver.is_empty() || s256.is_empty() {
        return MissionBind::Deny(vec![
            "context.mission requires non-empty approver and s256".into(),
        ]);
    }

    let entry = match registry.status(s256) {
        Ok(Some(e)) => e,
        Ok(None) => {
            return MissionBind::Deny(vec![format!("mission {s256} names no registered approval")]);
        }
        Err(e) => {
            return MissionBind::Deny(vec![format!("mission registry unavailable: {e}")]);
        }
    };
    if entry.terminated {
        return MissionBind::Deny(vec![format!("mission {s256} is terminated")]);
    }
    if entry.expiry <= now {
        return MissionBind::Deny(vec![format!("mission {s256} is expired")]);
    }
    if entry.approver != approver {
        return MissionBind::Deny(vec![format!(
            "mission {s256} approver mismatch (registry {}, request {approver})",
            entry.approver
        )]);
    }
    if entry.agent.is_empty() {
        return MissionBind::Deny(vec![format!(
            "mission {s256} has no agent on file (re-approve to enable decision-under-mission)"
        )]);
    }
    if entry.agent != subject_id {
        return MissionBind::Deny(vec![format!(
            "mission {s256} authorizes agent {}, not subject {subject_id}",
            entry.agent
        )]);
    }
    match scope_for_action(action) {
        Some(scope) if !entry.approved_tools.iter().any(|t| t == scope) => {
            return MissionBind::Deny(vec![format!(
                "mission {s256} does not approve tool/scope `{scope}` for action {action}"
            )]);
        }
        // An action with no scope mapping cannot be shown to be covered by this
        // grant, so it is refused. Silently skipping the check would let any new
        // action ride on every Mission until someone remembered to map it.
        None => {
            return MissionBind::Deny(vec![format!(
                "action {action} has no scope mapping, so mission {s256} cannot be shown to approve it"
            )]);
        }
        _ => {}
    }

    MissionBind::Ok(decern_ledger::MissionRef {
        approver: approver.to_owned(),
        s256: s256.to_owned(),
    })
}

async fn pubkey(State(st): State<AppState>) -> Json<Value> {
    Json(json!({ "kid": hex::encode(st.pubkey.to_bytes()) }))
}

// ============================== Mission lifecycle ==============================
//
// An approver grants an agent a scoped, provably-attenuated Mission (`decern-identity`).
// Each accepted transition — approve, terminate — is recorded to the tamper-evident
// ledger before it is reported as succeeded (fail-closed), exactly as a decision is.

/// `POST /mission/v1/approve` body.
#[derive(Deserialize)]
struct MissionApproveReq {
    approver: String,
    agent: String,
    description: String,
    approved_tools: Vec<String>,
    #[serde(default)]
    capabilities: Vec<String>,
    expiry: u64,
}

/// The ledger `Entry` recording a Mission lifecycle transition.
///
/// For a `Mission.*` action `decision` is set `true` to mean "the transition was
/// accepted" — NOT an allow/deny verdict. A reader aggregating records by `decision`
/// must exclude `Mission.*` actions, or it would miscount an accepted approval or
/// termination as an allowed access decision.
fn mission_entry(
    dir: &Directory,
    now_s: u64,
    approver: &str,
    action: &str,
    s256: &str,
    context: Value,
) -> Entry {
    // For a Mission event the accountable-owner is the APPROVER's own delegation root
    // (subject = approver), not the agent the mission authorizes: the approver is who
    // stands behind the grant. Resolved server-side, never read from the request.
    let sponsor = resolve_sponsor(dir, approver);
    let parameter_digest = Some(decern_ledger::parameter_digest(&json!({
        "action": action,
        "approver": approver,
        "s256": s256,
        "context": context,
    })));
    Entry {
        ts_ms: now_s.saturating_mul(1000),
        subject_type: "Principal".into(),
        subject_id: approver.into(),
        action: action.into(),
        resource_type: "Mission".into(),
        resource_id: s256.into(),
        context,
        decision: true,
        sponsor,
        parameter_digest,
        mission: Some(decern_ledger::MissionRef {
            approver: approver.to_owned(),
            s256: s256.to_owned(),
        }),
        ..Default::default()
    }
}

/// Map a Mission-approval failure to its status. A registry conflict — a terminated
/// mission refusing re-registration (no revival) — is a 409; a registry I/O/serde
/// failure is infrastructure, so 503; every other approval failure (attenuation, an
/// unknown approver, a malformed grant) is the request's own fault, 422.
fn approve_error(e: &IdentityError) -> Response {
    let status = match e {
        IdentityError::Registry(StoreError::Invalid(_)) => StatusCode::CONFLICT,
        IdentityError::Registry(_) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (
        status,
        Json(json!({ "error": "mission not approved", "detail": e.to_string() })),
    )
        .into_response()
}

/// A registry read/write that could not complete is infrastructure failure → 503,
/// fail-closed: a caller must not read or change a mission's state from a store it
/// could not consult.
fn registry_unavailable(e: &StoreError) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "mission registry unavailable", "detail": e.to_string() })),
    )
        .into_response()
}

/// The mission reference `(approver, s256)` as a JSON object.
fn mission_reference(approver: &str, s256: &str) -> Value {
    json!({ "approver": approver, "s256": s256 })
}

/// `POST /mission/v1/approve` — attenuate a scoped Mission, record it, then register it.
async fn mission_approve(
    State(st): State<AppState>,
    Json(req): Json<MissionApproveReq>,
) -> Response {
    let now_s = now_secs();
    let mission = Mission {
        approver: req.approver,
        agent: req.agent,
        approved_at: now_s,
        description: req.description,
        approved_tools: req.approved_tools,
        capabilities: req.capabilities,
        expiry: req.expiry,
    };
    // Fail-closed attenuation happens INSIDE approve: an approved tool the approver does
    // not hold, or an expiry beyond the approver's, is refused here and NOTHING is
    // registered or recorded. The reference `s256` is DETERMINISTIC — a pure function of
    // the authority, not of `approved_at`/`now` — so a retry of the same request yields
    // the SAME reference. Compute it WITHOUT registering; the registration happens only
    // after the record lands (fail-closed, below).
    let approved = match mission::approve(st.model.as_ref(), mission, now_s, None) {
        Ok(a) => a,
        Err(e) => return approve_error(&e),
    };
    let (approver, s256) = approved.reference();
    let (approver, s256) = (approver.to_owned(), s256.to_owned());

    // Monotone no-revival fast-path: if this reference is already terminated, refuse
    // BEFORE recording so re-approving a killed mission does not write a spurious
    // "approved" audit line. Race-safe because termination is one-way — a `terminated`
    // reading can never become active, and a stale `active`/unknown reading simply falls
    // through to the record-then-register path below (where `register` is the authority).
    match st.missions.status(&s256) {
        Ok(Some(entry)) if entry.terminated => {
            return approve_error(&IdentityError::Registry(StoreError::Invalid(format!(
                "mission {s256} is terminated and cannot be re-registered"
            ))));
        }
        Err(e) => return registry_unavailable(&e),
        _ => {}
    }

    let dir = st.kernel.directory();
    let shard = shard_for(&st.backend, dir, &approver);
    let context = json!({
        "agent": approved.mission.agent,
        "description": approved.mission.description,
        "approved_tools": approved.mission.approved_tools,
        "capabilities": approved.mission.capabilities,
        "expiry": approved.mission.expiry,
        // A recorded FACT (not part of `s256`): when this approval was accepted.
        "approved_at": approved.mission.approved_at,
        "s256": s256,
    });
    let entry = mission_entry(dir, now_s, &approver, "Mission.Approve", &s256, context);

    // Record-then-register, fail-closed on AUTHORITY: append the ledger entry FIRST and
    // register the mission ONLY if that write landed. A record failure → 503 and NOTHING
    // registered, so a live mission never exists without a record. The reference is
    // deterministic, so a retry is idempotent — `register` is a no-op on an already-active
    // reference (the record may append a duplicate `Mission.Approve` line, which is
    // harmless). The reverse failure (record lands, register then 503s) is the SAFE
    // direction: an audit line exists and no authority went live, and a retry heals it.
    let backend = st.backend.clone();
    if let Some(unavailable) = record_or_503(move || append_to_backend(&backend, shard, entry)) {
        return unavailable;
    }
    if let Err(e) = st.missions.register(
        &s256,
        decern_store::MissionEntry {
            approver: approver.clone(),
            expiry: approved.mission.expiry,
            terminated: false,
            agent: approved.mission.agent.clone(),
            approved_tools: approved.mission.approved_tools.clone(),
        },
        now_s,
    ) {
        return approve_error(&IdentityError::Registry(e));
    }
    (
        StatusCode::OK,
        Json(json!({
            "approver": approver,
            "s256": s256,
            "reference": mission_reference(&approver, &s256),
        })),
    )
        .into_response()
}

/// `GET /mission/v1/{s256}` — the mission reference + state, or 404 if unknown.
async fn mission_get(State(st): State<AppState>, UrlPath(s256): UrlPath<String>) -> Response {
    match st.missions.status(&s256) {
        Ok(Some(entry)) => {
            let state = if entry.terminated {
                "terminated"
            } else {
                "active"
            };
            (
                StatusCode::OK,
                Json(json!({
                    "reference": mission_reference(&entry.approver, &s256),
                    "state": state,
                    "expiry": entry.expiry,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "unknown mission", "s256": s256 })),
        )
            .into_response(),
        Err(e) => registry_unavailable(&e),
    }
}

/// `POST /mission/v1/{s256}/terminate` — terminate (no revival), then record it.
async fn mission_terminate(State(st): State<AppState>, UrlPath(s256): UrlPath<String>) -> Response {
    let now_s = now_secs();
    // Resolve the mission first: its approver is the subject/accountable-owner of the
    // termination record, and an unknown reference has nothing to terminate.
    let entry = match st.missions.status(&s256) {
        Ok(Some(e)) => e,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unknown mission", "s256": s256 })),
            )
                .into_response();
        }
        Err(e) => return registry_unavailable(&e),
    };
    // Persist the termination (monotone, no revival; an idempotent no-op if already
    // terminated) BEFORE recording. The order is deliberate and OPPOSITE to approve's:
    // approve's dangerous state is a LIVE mission, so it records first (never live without
    // a record); terminate's dangerous state is a mission that still mints, and
    // terminating makes it SAFE (mints nothing), so persisting first is the fail-closed
    // choice. A 503 on the record therefore leaves the safe state, and the record runs on
    // every call — including a repeat of an already-terminated mission — so a 503'd
    // termination's audit entry is guaranteed to land on retry.
    if let Err(e) = st.missions.terminate(&s256, now_s) {
        return registry_unavailable(&e);
    }
    let dir = st.kernel.directory();
    let shard = shard_for(&st.backend, dir, &entry.approver);
    let context = json!({ "s256": s256, "expiry": entry.expiry });
    let ledger_entry = mission_entry(
        dir,
        now_s,
        &entry.approver,
        "Mission.Terminate",
        &s256,
        context,
    );

    let backend = st.backend.clone();
    if let Some(unavailable) =
        record_or_503(move || append_to_backend(&backend, shard, ledger_entry))
    {
        return unavailable;
    }
    (
        StatusCode::OK,
        Json(json!({
            "reference": mission_reference(&entry.approver, &s256),
            "state": "terminated",
        })),
    )
        .into_response()
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/pubkey", get(pubkey))
        // AuthZEN Authorization API 1.0 Access Evaluation endpoint; /decide is a friendly alias.
        .route("/access/v1/evaluation", post(decide))
        .route("/decide", post(decide))
        // Mission lifecycle: approve a scoped Mission, read its state, terminate it.
        // Like the decision PDP above, the MUTATION endpoints (approve, terminate) are
        // UNAUTHENTICATED by design and trust their caller — `approver` is a request-body
        // field, not authenticated here. Deploy behind an authenticating proxy that
        // derives/validates `approver`, and keep the bind loopback (`--addr`, default
        // 127.0.0.1) unless such a proxy fronts them (see README "Trust boundary"; a
        // non-loopback `--addr` logs a startup WARN).
        .route("/mission/v1/approve", post(mission_approve))
        .route("/mission/v1/{s256}", get(mission_get))
        .route("/mission/v1/{s256}/terminate", post(mission_terminate))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let model = match &args.model {
        Some(d) => {
            Model::from_dir(d).with_context(|| format!("loading model from {}", d.display()))?
        }
        None => Model::builtin(),
    };
    let kernel = Kernel::new(&model)?;
    let key = load_signing_key(args.key.as_ref())?;
    let pubkey = key.verifying_key();

    // Resolve the mission-registry path while `args.ledger`/`args.sharded` are still
    // borrowable (the backend match below consumes `args.ledger`). The registry is
    // OPENED after the backend so a boot that bails does not create its file.
    let missions_path = args
        .missions
        .clone()
        .unwrap_or_else(|| default_missions_path(args.ledger.as_ref(), args.sharded.as_ref()));

    let (backend, backend_desc) = match &args.sharded {
        Some(target) => {
            // Fail closed at boot: a directory tenant equal to the reserved
            // unattributed-shard name would silently co-mingle with it.
            if let Some(who) = reserved_tenant_collision(kernel.directory()) {
                anyhow::bail!(
                    "refusing to serve sharded: {who} uses the reserved shard name {UNATTRIBUTED_SHARD:?}"
                );
            }
            let is_pg = target.starts_with("postgres://") || target.starts_with("postgresql://");
            // A postgres URL can carry a password — never echo it in the log line.
            let desc = if is_pg {
                "sharded (postgres head store)".to_string()
            } else {
                format!("sharded {target}")
            };
            let store: Arc<dyn decern_store::LedgerHeadStore> = if is_pg {
                #[cfg(feature = "postgres")]
                {
                    Arc::new(
                        decern_store_postgres::PostgresLedgerHeadStore::new(target)
                            .with_context(|| "connecting sharded postgres head store")?,
                    )
                }
                #[cfg(not(feature = "postgres"))]
                {
                    anyhow::bail!(
                        "a postgres:// sharded head store requires a build with `--features postgres`"
                    );
                }
            } else {
                Arc::new(
                    FileLedgerHeadStore::new(target)
                        .with_context(|| format!("opening sharded head store at {target}"))?,
                )
            };
            let sharded = ShardedLedger::new(store, key, vec![]);
            (LedgerBackend::Sharded(sharded), desc)
        }
        None => {
            let path = args.ledger.unwrap_or_else(|| PathBuf::from(DEFAULT_LEDGER));
            let mut ledger = Ledger::open(&path, key)?;
            // Durable by default in the server: an append the PEP acks (and acts
            // on) must survive a crash — `sync_data` before `append` returns.
            ledger.set_sync(true);
            let desc = format!("ledger {}", path.display());
            (LedgerBackend::Single(Mutex::new(ledger)), desc)
        }
    };

    let missions = Arc::new(
        FileMissionRegistry::open(&missions_path)
            .with_context(|| format!("opening mission registry at {}", missions_path.display()))?,
    );

    let state = AppState {
        kernel: Arc::new(kernel),
        model: Arc::new(model),
        backend: Arc::new(backend),
        missions,
        pubkey,
        require_mission: args.require_mission,
    };
    if !addr_is_loopback(&args.addr) {
        eprintln!(
            "WARN: binding {} exposes the UNAUTHENTICATED decision and mission-mutation \
             endpoints on the network; front them with an authenticating proxy that \
             derives/validates the caller (see README \"Trust boundary\") or bind a \
             loopback --addr",
            args.addr
        );
    }
    let listener = tokio::net::TcpListener::bind(&args.addr)
        .await
        .with_context(|| format!("binding {}", args.addr))?;
    println!(
        "decern-serve on {} — {}, missions {}, kid {}",
        args.addr,
        backend_desc,
        missions_path.display(),
        hex::encode(pubkey.to_bytes())
    );
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Resolve when the process is asked to stop — SIGINT (Ctrl-C) or, on Unix, SIGTERM.
/// `axum::serve` then stops accepting, drains in-flight requests, and returns, so
/// `AppState` (and any head-store connection it holds) drops on a normal control-flow
/// path — destructors run — instead of being skipped by a default signal termination.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            // If the handler cannot be installed, fall back to Ctrl-C alone rather
            // than resolving immediately (which would shut the server down at once).
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn unrecordable_decision_returns_503_never_the_allow() {
        // The thesis: a proven Allow whose audit record fails to write must NOT be served.
        let resp = record_and_respond(true, vec!["policy0".into()], vec![], || {
            Err(LedgerError::Serde("disk wedged".into()))
        });
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn recorded_decision_is_served_200() {
        let resp = record_and_respond(true, vec![], vec![], || Ok(()));
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn non_loopback_bind_is_flagged_for_the_startup_warn() {
        // The startup WARN keys off this predicate: loopback binds are silent, a bind
        // reachable off-host is flagged (the endpoints are unauthenticated by design).
        // Literal addresses only — no DNS, so the test is hermetic.
        assert!(
            addr_is_loopback("127.0.0.1:8080"),
            "IPv4 loopback is silent"
        );
        assert!(addr_is_loopback("[::1]:8080"), "IPv6 loopback is silent");
        assert!(
            !addr_is_loopback("0.0.0.0:8080"),
            "all-interfaces is flagged"
        );
        assert!(
            !addr_is_loopback("[::]:8080"),
            "IPv6 unspecified is flagged"
        );
    }

    #[test]
    fn accepts_authzen_request_shape() {
        // AuthZEN 1.0: action is an object with a `name`; optional `properties` are ignored.
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"corp"},
                "action":{"name":"Read","properties":{}},
                "resource":{"type":"Resource","id":"claim1"}}"#,
        )
        .unwrap();
        assert_eq!(req.action.name, "Read");
        assert_eq!(req.subject.id, "corp");
    }

    #[test]
    fn response_is_authzen_shaped() {
        // Minimal: just the boolean decision.
        assert_eq!(evaluation_body(true, &[], &[]), json!({ "decision": true }));
        // Reasons go under `context`, not at the top level.
        assert_eq!(
            evaluation_body(false, &["policy3".into()], &[]),
            json!({ "decision": false, "context": { "reasons": ["policy3"] } })
        );
        // A deny surfaces the kernel's errors under `context` too.
        assert_eq!(
            evaluation_body(false, &[], &["unknown principal".into()]),
            json!({ "decision": false, "context": { "errors": ["unknown principal"] } })
        );
    }

    /// A small directory with a real 3-hop chain a <- b <- c, a standalone
    /// self-root `solo`, and (implicitly) ids absent from it entirely.
    fn test_dir() -> Directory {
        let principal = |id: &str, delegator: Option<&str>| {
            let mut attrs = json!({
                "kind": "Agent", "tenant": "A", "expiry": 1000, "scopes": ["read"],
            });
            if let Some(d) = delegator {
                attrs["delegator"] = json!({"__entity": {"type": "Principal", "id": d}});
            }
            json!({"uid": {"type": "Principal", "id": id}, "attrs": attrs, "parents": []})
        };
        let ents = json!([
            principal("a", None),
            principal("b", Some("a")),
            principal("c", Some("b")),
            principal("solo", None),
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(dir.validate().is_empty(), "fixture must be well-formed");
        dir
    }

    #[test]
    fn sponsor_of_multi_hop_delegate_is_the_root_not_the_delegator() {
        // c's nearest delegator is b, but accountability rolls all the way to a.
        let s = resolve_sponsor(&test_dir(), "c").expect("known principal has a sponsor");
        assert_eq!(
            s,
            Party {
                kind: "Principal".into(),
                id: "a".into()
            }
        );
    }

    #[test]
    fn self_root_sponsors_itself() {
        let s = resolve_sponsor(&test_dir(), "solo").expect("known root has a sponsor");
        assert_eq!(
            s,
            Party {
                kind: "Principal".into(),
                id: "solo".into()
            }
        );
        // The root `a` is likewise its own sponsor.
        let a = resolve_sponsor(&test_dir(), "a").unwrap();
        assert_eq!(a.id, "a");
    }

    #[test]
    fn unknown_subject_has_no_sponsor() {
        // A global/static-token caller the directory doesn't recognize — distinct
        // from a self-root, even though both yield an empty ancestor chain.
        assert!(resolve_sponsor(&test_dir(), "ghost").is_none());
    }

    #[test]
    fn shard_of_known_subject_is_its_tenant() {
        // The fixture puts every principal in tenant "A".
        assert_eq!(resolve_shard(&test_dir(), "c").unwrap(), "A");
    }

    #[test]
    fn shard_of_unknown_subject_is_the_unattributed_shard() {
        assert_eq!(
            resolve_shard(&test_dir(), "ghost").unwrap(),
            UNATTRIBUTED_SHARD
        );
    }

    /// A directory with one principal whose tenant literally IS the reserved
    /// unattributed-shard name. `parse` alone does not validate; `Kernel::new`
    /// / `validate` refuse it. Used to exercise `resolve_shard`'s Err path.
    fn dir_with_reserved_tenant() -> Directory {
        let ents = json!([{
            "uid": {"type": "Principal", "id": "sneaky"},
            "attrs": {"kind": "Agent", "tenant": UNATTRIBUTED_SHARD, "expiry": 1000, "scopes": []},
            "parents": []
        }]);
        Directory::parse(&ents).unwrap()
    }

    #[test]
    fn shard_of_empty_tenant_subject_is_the_unattributed_shard() {
        // `Directory::parse` rejects a missing tenant, so an empty tenant cannot
        // arise from a loaded model — this branch is pure defense in depth. Build
        // the degenerate record directly and confirm it lands unattributed, never
        // panics or errors.
        use decern_kernel::graph::PrincipalRec;
        let mut dir = Directory::default();
        dir.principals.insert(
            "notenant".into(),
            PrincipalRec {
                id: "notenant".into(),
                kind: "Agent".into(),
                tenant: String::new(),
                expiry: 1000,
                scopes: Default::default(),
                delegator: None,
                org: None,
                roles: Default::default(),
                jurisdictions: Default::default(),
                revoked: false,
            },
        );
        assert_eq!(resolve_shard(&dir, "notenant").unwrap(), UNATTRIBUTED_SHARD);
    }

    #[test]
    fn kernel_refuses_reserved_tenant_at_load() {
        // Kernel-level guard: a model whose principal tenant is `__system__`
        // must not load — so a colliding graph never reaches decide/shard.
        let mut model = Model::builtin();
        if let Value::Array(ents) = &mut model.entities {
            ents.push(json!({
                "uid": {"type": "Principal", "id": "sysguy"},
                "attrs": {"kind": "Agent", "tenant": UNATTRIBUTED_SHARD, "expiry": 1000, "scopes": []},
                "parents": []
            }));
        }
        match Kernel::new(&model) {
            Ok(_) => panic!("reserved tenant must refuse load"),
            Err(err) => assert!(
                err.to_string().contains("reserved"),
                "expected reserved-tenant Graph error, got {err}"
            ),
        }
    }

    #[test]
    fn reserved_name_tenant_fails_closed_not_comingled() {
        // A real tenant named like the reserved shard must ERROR, never quietly
        // land in the unattributed shard alongside genuinely unattributed entries.
        assert!(resolve_shard(&dir_with_reserved_tenant(), "sneaky").is_err());
        // And the boot-time guard catches the same directory before serving.
        assert!(reserved_tenant_collision(&dir_with_reserved_tenant()).is_some());
        // A clean directory passes the boot guard.
        assert!(reserved_tenant_collision(&test_dir()).is_none());
    }

    #[tokio::test]
    async fn sharded_decision_records_to_the_subjects_tenant_shard() {
        use decern_store::{FileLedgerHeadStore, LedgerHeadStore};

        // Isolated temp head-store root.
        let root = std::env::temp_dir().join(format!(
            "decern-serve-sharded-test-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();

        let store: Arc<dyn LedgerHeadStore> = Arc::new(FileLedgerHeadStore::new(&root).unwrap());
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let pubkey = key.verifying_key();
        let sharded = ShardedLedger::new(store.clone(), key, vec![]);

        let kernel = Kernel::new(&Model::builtin()).unwrap();
        let st = AppState {
            kernel: Arc::new(kernel),
            model: Arc::new(Model::builtin()),
            backend: Arc::new(LedgerBackend::Sharded(sharded)),
            missions: test_missions(),
            pubkey,
            require_mission: false,
        };

        // corpB is a builtin principal in tenant "B".
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"corpB"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claimB"}}"#,
        )
        .unwrap();
        let resp = decide(State(st), Json(req)).await;
        assert_eq!(resp.status(), StatusCode::OK, "recorded decision is served");

        // Read the log back via an independent reader over the same store.
        let reader = ShardedLedger::new(store.clone(), SigningKey::from_bytes(&[1u8; 32]), vec![]);
        let in_b = reader.read_records("B", 0, 100).unwrap();
        assert_eq!(in_b.len(), 1, "the decision landed in shard B");
        assert_eq!(
            in_b[0]["entry"]["subject_id"], "corpB",
            "and it is corpB's decision"
        );
        // Nothing spilled into the reserved unattributed shard.
        let in_system = reader.read_records(UNATTRIBUTED_SHARD, 0, 100).unwrap();
        assert!(in_system.is_empty(), "unattributed shard stays empty");

        let _ = std::fs::remove_dir_all(&root);
    }

    fn now_nanos() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    #[test]
    fn derivation_is_never_sourced_from_the_request() {
        // The derived sponsor is carried on an Entry whose sponsor_source stays
        // at the Derived default (this helper only ever computes, never asserts).
        use decern_ledger::SponsorSource;
        let entry = Entry {
            sponsor: resolve_sponsor(&test_dir(), "c"),
            ..Default::default()
        };
        assert_eq!(entry.sponsor_source, SponsorSource::Derived);
        assert_eq!(entry.sponsor.unwrap().id, "a");
    }

    // ============================ Mission service ============================

    /// A throwaway durable mission registry for a test that needs an `AppState` but
    /// does not exercise missions (its own temp file, cleaned by the OS).
    fn test_missions() -> Arc<FileMissionRegistry> {
        let path = std::env::temp_dir().join(format!(
            "decern-serve-missions-{}-{}.json",
            std::process::id(),
            now_nanos()
        ));
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(path.with_extension("lock")).ok();
        Arc::new(FileMissionRegistry::open(&path).unwrap())
    }

    /// A fresh temp directory to hold a test's ledger + mission registry together.
    fn mission_base() -> PathBuf {
        // A per-call atomic sequence guarantees a UNIQUE directory even when two parallel
        // mission tests hit the same wall-clock nanosecond — a shared dir would mean a
        // shared ledger file, whose interleaved appends would break the hash chain and
        // fail an unrelated test's `Ledger::open`.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "decern-serve-mission-{}-{}-{}",
            std::process::id(),
            now_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    /// A single-file-ledger `AppState` whose ledger and mission registry both live under
    /// `base`. Reopening the same `base` yields FRESH durable handles (nothing carried in
    /// memory), which is exactly what the durability test needs. The signing seed is fixed
    /// so a reopened ledger's existing records still verify under the returned key.
    fn mission_state_at(base: &Path) -> (AppState, VerifyingKey) {
        let ledger_path = base.join("decern-ledger.jsonl");
        let missions_path = base.join("decern-missions.json");
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = key.verifying_key();
        let mut ledger = Ledger::open(&ledger_path, key).unwrap();
        ledger.set_sync(true);
        let st = AppState {
            kernel: Arc::new(Kernel::new(&Model::builtin()).unwrap()),
            model: Arc::new(Model::builtin()),
            backend: Arc::new(LedgerBackend::Single(Mutex::new(ledger))),
            missions: Arc::new(FileMissionRegistry::open(&missions_path).unwrap()),
            pubkey,
            require_mission: false,
        };
        (st, pubkey)
    }

    async fn body_json(resp: Response) -> (StatusCode, Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, v)
    }

    /// `corp`'s authority expiry — the attenuation ceiling for a mission it approves.
    /// Read from the model (32503680000, far past wall clock) rather than hardcoded, so
    /// an approved mission is never GC'd out from under a test by the registry's
    /// evict-past-`now` sweep.
    fn corp_expiry() -> u64 {
        decern_identity::exchange::delegator_attrs(&Model::builtin(), "corp")
            .unwrap()
            .1
    }

    fn approve_req(tools: &[&str], expiry: u64) -> MissionApproveReq {
        MissionApproveReq {
            approver: "corp".into(),
            agent: "agent-mission".into(),
            description: "reconcile invoices".into(),
            approved_tools: tools.iter().map(|s| s.to_string()).collect(),
            capabilities: vec![],
            expiry,
        }
    }

    #[tokio::test]
    async fn approved_mission_survives_a_registry_reopen() {
        // Durability: approve, then drop the state and open FRESH durable handles on the
        // same files — GET must still report the mission active.
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "approve recorded and served");
        let s256 = body["s256"].as_str().unwrap().to_owned();
        drop(st);

        let (st2, _pk2) = mission_state_at(&base);
        let (status, body) = body_json(mission_get(State(st2), UrlPath(s256)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"], "active", "durably active across a reopen");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn terminated_mission_is_never_revived_and_reads_terminated() {
        // No-revival: terminate, then a re-POST of the same grant is refused as a 409
        // through the endpoint, nothing new is recorded, and GET reports it terminated.
        let base = mission_base();
        let (st, pk) = mission_state_at(&base);
        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let (status, _b) =
            body_json(mission_terminate(State(st.clone()), UrlPath(s256.clone())).await).await;
        assert_eq!(status, StatusCode::OK);

        // Because `s256` is now deterministic, a handler re-POST of the SAME grant carries
        // the SAME reference and hits the no-revival guard directly through the endpoint: a
        // 409, and (thanks to the monotone terminated fast-path) nothing new is recorded.
        let before = decern_ledger::verify(&base.join("decern-ledger.jsonl"), Some(&pk))
            .unwrap()
            .entries;
        let (status, _b) = body_json(
            mission_approve(
                State(st.clone()),
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "re-approving a terminated mission is a 409 (no revival)"
        );
        let after = decern_ledger::verify(&base.join("decern-ledger.jsonl"), Some(&pk))
            .unwrap()
            .entries;
        assert_eq!(
            before, after,
            "a refused re-approval must not write a spurious audit line"
        );

        let (status, body) = body_json(mission_get(State(st), UrlPath(s256)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"], "terminated");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_failed_approve_record_leaves_no_registered_mission() {
        // B2 property (b), record-then-register fail-closed: if the ledger append fails,
        // the mission is NEVER registered — no live authority without a record.
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);

        // The deterministic reference this exact grant produces (independent of the
        // registry and of approval time — fields mirror `approve_req(&["read"], ...)`).
        let expected = mission::approve(
            st.model.as_ref(),
            Mission {
                approver: "corp".into(),
                agent: "agent-mission".into(),
                approved_at: 0,
                description: "reconcile invoices".into(),
                approved_tools: vec!["read".into()],
                capabilities: vec![],
                expiry: corp_expiry(),
            },
            0,
            None,
        )
        .unwrap();
        let s256 = expected.s256.clone();
        assert!(
            st.missions.status(&s256).unwrap().is_none(),
            "precondition: the reference is not registered yet"
        );

        // Simulate an unwritable ledger: poison the ledger mutex, so every append fails
        // CLOSED (see `append_to_backend`). The mission registry has its own lock and is
        // untouched, so the pre-record status read still succeeds and falls through.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let LedgerBackend::Single(m) = &*st.backend {
                let _guard = m.lock().unwrap();
                panic!("intentionally poison the ledger mutex to simulate an unwritable ledger");
            }
        }));

        let (status, _b) = body_json(
            mission_approve(
                State(st.clone()),
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "an unrecordable approval is a 503"
        );
        assert!(
            st.missions.status(&s256).unwrap().is_none(),
            "record-then-register: a failed record must leave NOTHING registered"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn approving_a_tool_the_approver_lacks_is_refused_and_the_ledger_does_not_grow() {
        // Attenuation fail-closed: one successful approve first (so we count from a real
        // baseline), then a refused one must be a 4xx AND leave the ledger unchanged.
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        let ledger_path = base.join("decern-ledger.jsonl");

        let (status, _b) = body_json(
            mission_approve(
                State(st.clone()),
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let before = decern_ledger::verify(&ledger_path, Some(&pubkey))
            .unwrap()
            .entries;

        // corp does NOT hold `root_everything` → approve refuses it, nothing recorded.
        let (status, _b) = body_json(
            mission_approve(
                State(st),
                Json(approve_req(&["read", "root_everything"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert!(
            status.is_client_error(),
            "an attenuation violation is a 4xx, got {status}"
        );
        let after = decern_ledger::verify(&ledger_path, Some(&pubkey))
            .unwrap()
            .entries;
        assert_eq!(before, after, "a refused approval must not grow the ledger");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn every_mission_transition_is_a_verifiable_ledger_entry() {
        // approve + terminate, then `decern verify` (chain + every signature) passes over
        // the resulting ledger, and each entry is the mission transition it claims to be.
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        let ledger_path = base.join("decern-ledger.jsonl");

        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                Json(approve_req(&["read", "move_money"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let (status, _b) =
            body_json(mission_terminate(State(st), UrlPath(s256.clone())).await).await;
        assert_eq!(status, StatusCode::OK);

        let report = decern_ledger::verify(&ledger_path, Some(&pubkey)).unwrap();
        assert_eq!(report.entries, 2, "one Approve + one Terminate recorded");
        assert!(report.signatures_checked, "every signature verified");

        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 10).unwrap();
        let actions: Vec<&str> = records
            .iter()
            .map(|r| r["entry"]["action"].as_str().unwrap())
            .collect();
        assert_eq!(actions, vec!["Mission.Approve", "Mission.Terminate"]);
        for r in &records {
            assert_eq!(r["entry"]["subject_id"], "corp", "subject is the approver");
            assert_eq!(r["entry"]["resource_type"], "Mission");
            assert_eq!(r["entry"]["resource_id"], s256);
            assert_eq!(
                r["entry"]["decision"], true,
                "Mission.* decision is the transition-accepted marker"
            );
            assert_eq!(
                r["entry"]["sponsor"]["id"], "corp",
                "accountable-owner is the approver's own root"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn server_ignores_body_now_and_decays_by_its_own_clock() {
        // Regression guard: the server must use its OWN wall clock, never the request
        // body's `now`. `agent1` is a builtin principal with `expiry: 200`, far in the
        // past relative to the wall clock the server uses.
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);

        // Non-vacuous: at now=100 (< agent1's expiry 200) agent1 MAY read claim1 — so the
        // ONLY reason the server denies below is that it ignored the body `now`.
        let allow_at_100 = st.kernel.check(
            &EntityRef {
                ty: "Principal".into(),
                id: "agent1".into(),
            },
            "Read",
            &EntityRef {
                ty: "Resource".into(),
                id: "claim1".into(),
            },
            &json!({ "now": 100 }),
        );
        assert!(
            allow_at_100.decision,
            "fixture guard: agent1 reads claim1 at now=100 (before its expiry)"
        );

        // The request carries {"now":100}; honoring it would wrongly ALLOW. The server
        // must instead use its own clock (>> 200) → agent1 is decayed → DENY.
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"agent1"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claim1"},
                "context":{"now":100}}"#,
        )
        .unwrap();
        let (status, body) = body_json(decide(State(st), Json(req)).await).await;
        assert_eq!(status, StatusCode::OK, "a recorded decision is served");
        assert_eq!(
            body["decision"], false,
            "server ignored body now=100 and decayed agent1 by its own wall clock"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn mission_routes_are_reachable_through_the_router() {
        // The handler tests call the functions directly; this drives real requests
        // through `app()`, exercising the axum path layer: that the router BUILDS (a
        // route conflict would panic here), that `POST /mission/v1/approve` resolves to
        // the literal route rather than being captured as `{s256}="approve"`, and that
        // the `{s256}` (base64url) segment routes to get/terminate.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let router = app(st);

        let approve_body = serde_json::to_vec(&json!({
            "approver": "corp",
            "agent": "agent-mission",
            "description": "reconcile invoices",
            "approved_tools": ["read"],
            "expiry": corp_expiry(),
        }))
        .unwrap();
        let (status, body) = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mission/v1/approve")
                        .header("content-type", "application/json")
                        .body(Body::from(approve_body))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "approve routed to the literal path");
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let (status, body) = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/mission/v1/{s256}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"], "active", "{s256} routed to get");

        let (status, body) = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/mission/v1/{s256}/terminate"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"], "terminated", "{s256}/terminate routed");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn require_mission_denies_without_a_mission() {
        let base = mission_base();
        let (mut st, _pk) = mission_state_at(&base);
        st.require_mission = true;
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"agent1"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claim1"},
                "context":{"human_approved":true}}"#,
        )
        .unwrap();
        let (status, body) = body_json(decide(State(st), Json(req)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], false, "missing mission must Deny: {body}");
        assert!(
            body["context"]["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e.as_str().unwrap_or("").contains("require-mission")),
            "{body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn decide_under_live_mission_allows_and_records_mission_ref() {
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        // Approve a Mission for corp (non-expired builtin principal) with move_money.
        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                Json(MissionApproveReq {
                    approver: "corp".into(),
                    agent: "corp".into(),
                    description: "under-mission decide".into(),
                    approved_tools: vec!["read".into(), "move_money".into()],
                    capabilities: vec![],
                    expiry: corp_expiry(),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let mut st = st;
        st.require_mission = true;
        let req: DecideReq = serde_json::from_str(&format!(
            r#"{{"subject":{{"type":"Principal","id":"corp"}},
                "action":{{"name":"MoveMoney"}},
                "resource":{{"type":"Resource","id":"claim1"}},
                "context":{{"mission":{{"approver":"corp","s256":"{s256}"}}}},
                "decision_subject":{{"type":"Principal","id":"corp"}}}}"#
        ))
        .unwrap();
        let (status, body) = body_json(decide(State(st.clone()), Json(req)).await).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["decision"], true,
            "mission-gated MoveMoney allows: {body}"
        );

        let ledger_path = base.join("decern-ledger.jsonl");
        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 100).unwrap();
        let last = records.last().expect("decision recorded");
        assert_eq!(last["entry"]["action"], "MoveMoney");
        assert_eq!(last["entry"]["decision"], true);
        assert_eq!(last["entry"]["mission"]["s256"], s256);
        assert!(
            last["entry"]["parameter_digest"].as_str().is_some(),
            "parameter_digest must be written: {last}"
        );
        assert_eq!(last["entry"]["decision_subject"]["id"], "corp");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A decision-subject the directory cannot vouch for is refused, not recorded.
    /// The column names the party a decision is about; accepting an arbitrary
    /// string would make it decoration and would bind a phantom into the digest.
    #[tokio::test]
    async fn decide_refuses_an_unknown_decision_subject() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"corp"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claim1"},
                "decision_subject":{"type":"Principal","id":"ghost-not-in-directory"}}"#,
        )
        .unwrap();
        let (status, body) = body_json(decide(State(st.clone()), Json(req)).await).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown decision_subject must be refused: {body}"
        );
        assert_eq!(body["error"], "unknown decision_subject");

        let ledger_path = base.join("decern-ledger.jsonl");
        let recorded = std::fs::read_to_string(&ledger_path).unwrap_or_default();
        assert!(
            !recorded.contains("ghost-not-in-directory"),
            "a refused decision_subject must never reach the ledger: {recorded}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An action with no scope mapping cannot be shown to be covered by a grant,
    /// so under `--require-mission` it is refused. Skipping the check would let
    /// every future action ride on every Mission until someone mapped it.
    #[tokio::test]
    async fn mission_refuses_an_action_with_no_scope_mapping() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                Json(approve_req(&["read", "move_money"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let mut st = st;
        st.require_mission = true;
        let req: DecideReq = serde_json::from_str(&format!(
            r#"{{"subject":{{"type":"Principal","id":"corp"}},
                "action":{{"name":"SomeUnmappedFutureAction"}},
                "resource":{{"type":"Resource","id":"claim1"}},
                "context":{{"mission":{{"approver":"corp","s256":"{s256}"}}}}}}"#
        ))
        .unwrap();
        let (status, body) = body_json(decide(State(st.clone()), Json(req)).await).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["decision"], false,
            "an unmapped action must not inherit the grant: {body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn terminated_mission_cannot_justify_a_decision() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256 = body["s256"].as_str().unwrap().to_owned();
        // approve_req uses agent-mission; terminate then try decide as that agent.
        let _ = mission_terminate(State(st.clone()), UrlPath(s256.clone())).await;

        let mut st = st;
        st.require_mission = true;
        let req: DecideReq = serde_json::from_str(&format!(
            r#"{{"subject":{{"type":"Principal","id":"agent-mission"}},
                "action":{{"name":"Read"}},
                "resource":{{"type":"Resource","id":"claim1"}},
                "context":{{"mission":{{"approver":"corp","s256":"{s256}"}}}}}}"#
        ))
        .unwrap();
        let (status, body) = body_json(decide(State(st), Json(req)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], false, "{body}");
        assert!(
            body["context"]["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e.as_str().unwrap_or("").contains("terminated")),
            "{body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn mission_tool_mismatch_denies() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let mut st = st;
        st.require_mission = true;
        // Mission only has read; MoveMoney needs move_money.
        let req: DecideReq = serde_json::from_str(&format!(
            r#"{{"subject":{{"type":"Principal","id":"agent-mission"}},
                "action":{{"name":"MoveMoney"}},
                "resource":{{"type":"Resource","id":"claim1"}},
                "context":{{"mission":{{"approver":"corp","s256":"{s256}"}}}}}}"#
        ))
        .unwrap();
        let (status, body) = body_json(decide(State(st), Json(req)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], false, "{body}");
        assert!(
            body["context"]["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e.as_str().unwrap_or("").contains("move_money")),
            "{body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
