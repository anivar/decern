// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The recording layer: a decision or transition is durably appended to the
//! configured ledger backend before it is served, and a failed append is a 503.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use decern_kernel::Directory;
use decern_ledger::{Entry, LedgerError, UNATTRIBUTED_SHARD};
use serde_json::{Value, json};

use crate::LedgerBackend;

/// Where a record goes on the sharded backend: `Some(Ok(shard))` for the subject's tenant,
/// `Some(Err(why))` when it could not be resolved (fails closed as a 503 at append), `None`
/// on the single-file backend, which has no shards.
pub(crate) type Shard = Option<Result<String, String>>;

/// Resolve the ledger shard for a decision: the subject's directory tenant.
///
/// Security-sensitive — the shard is the tenant-isolation boundary of the
/// tamper-evident log, so it is derived server-side from `dir`, never from the
/// request. Rules:
///   - subject is a known principal with a non-empty tenant → that tenant.
///   - subject unknown, or known with an empty tenant → [`UNATTRIBUTED_SHARD`].
///   - subject's tenant literally equals the reserved [`UNATTRIBUTED_SHARD`]
///     name → `Err`. The kernel already refuses such a tenant at load
///     (`Directory::validate`, covered by `reserved_tenant_rejected_at_load`),
///     and `serve` refuses to boot a `--sharded` deployment whose directory
///     contains one. This per-decision guard is defense in depth behind both:
///     were a tenant named `__system__` ever to reach here, it would otherwise
///     co-mingle with the unattributed shard, so we fail closed and the caller
///     turns it into a 503 rather than a quietly-misfiled Allow.
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
pub(crate) fn reserved_tenant_collision(dir: &Directory) -> Option<String> {
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

/// AuthZEN Access Evaluation response: a boolean `decision`, with its `reasons` and `errors`,
/// the kernel's and any from binding a Mission, under `context` when there are any.
pub(crate) fn evaluation_body(decision: bool, reasons: &[String], errors: &[String]) -> Value {
    let mut body = json!({ "decision": decision });
    let mut ctx = serde_json::Map::new();
    if !reasons.is_empty() {
        ctx.insert("reasons".into(), json!(reasons));
    }
    if !errors.is_empty() {
        // A kernel error can quote the request back, an unknown action's name among
        // others; bounded as a refusal's detail is.
        let errors: Vec<String> = errors
            .iter()
            .map(|e| crate::decide::bounded(e, 512))
            .collect();
        ctx.insert("errors".into(), json!(errors));
    }
    if !ctx.is_empty() {
        body["context"] = Value::Object(ctx);
    }
    body
}

/// `GET /healthz`: `ok`, or `503` once the single-file ledger has stopped after a write
/// error or its lock is poisoned, or once a sharded ledger's store has failed: a Postgres
/// store whose connection closed or whose worker thread stopped. None recovers without a
/// restart, so a liveness probe on this route restarts the process, and the restart reopens
/// the ledger. A lock held by an append in progress counts as alive: the probe never waits
/// behind a write.
pub(crate) async fn healthz(
    axum::extract::State(st): axum::extract::State<crate::AppState>,
) -> Response {
    let stopped = match &*st.backend {
        LedgerBackend::Single(ledger) => match ledger.try_lock() {
            Ok(ledger) => ledger.has_failed(),
            Err(std::sync::TryLockError::Poisoned(_)) => true,
            Err(std::sync::TryLockError::WouldBlock) => false,
        }
        .then_some("ledger stopped after a write error; restart to recover"),
        LedgerBackend::Sharded(s) => s
            .has_failed()
            .then_some("ledger store can no longer record; restart to recover"),
    };
    match stopped {
        Some(why) => (StatusCode::SERVICE_UNAVAILABLE, why).into_response(),
        None => "ok".into_response(),
    }
}

/// Run a handler's work on a blocking thread and answer with what it returns. Evaluation, the
/// append and its fsync are synchronous; on an executor worker they would hold it, and every
/// request queued behind it, for their whole length, and the request deadline could not fire
/// while they ran. A panic in the work is answered `503` under `error`; whatever it had already
/// recorded stays recorded, and nothing unrecorded is served.
pub(crate) async fn off_the_executor(
    error: &'static str,
    work: impl FnOnce() -> Response + Send + 'static,
) -> Response {
    match tokio::task::spawn_blocking(work).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": error, "detail": "the request did not complete" })),
        )
            .into_response(),
    }
}

/// Write the audit record, or hand back the fail-closed 503 the whole service rests on.
/// `None` = the record is durable, so the caller builds its own success response;
/// `Some(resp)` = it could not be written, so this 503 must be returned instead. No
/// transition — a decision OR a Mission lifecycle event — is ever reported as succeeded
/// unless its record landed.
pub(crate) fn record_or_503(append: impl FnOnce() -> Result<(), LedgerError>) -> Option<Response> {
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
/// a decision that cannot be recorded is never served.
pub(crate) fn record_and_respond(
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

/// The ledger's mutex is poisoned: an append panicked mid-write, and nothing that needs the
/// ledger is served after it.
pub(crate) fn poisoned() -> LedgerError {
    LedgerError::Io {
        path: "ledger".into(),
        err: "ledger mutex poisoned; refusing to serve".into(),
    }
}

/// Append `entry` to whichever backend is configured, fail-closed. `shard` is the
/// server-derived ledger shard: `Some(Ok(shard))` for the sharded backend, `None` for
/// the single-file backend; a shard-resolver error (or the impossible `None` on the
/// sharded arm) becomes a ledger error → 503, never a panic or a misfiled record.
pub(crate) fn append_to_backend(
    backend: &LedgerBackend,
    shard: Shard,
    entry: Entry,
) -> Result<(), LedgerError> {
    match backend {
        // A poisoned mutex (a prior append panicked mid-write) fails CLOSED as a 503.
        LedgerBackend::Single(m) => match m.lock() {
            Ok(mut g) => g.append(entry).map(|_| ()),
            Err(_) => Err(poisoned()),
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

/// Append every entry of a batch, fail-closed. On the single-file backend the batch is
/// one durable step under one lock — one sync for the exchange, not one per decision —
/// so a thousand decisions cannot hold the ledger for a thousand fsyncs. On the sharded
/// backend each entry is its own append under its shard's lock, since entries may span
/// shards. Either way nothing is served until every entry has landed.
pub(crate) fn append_all_to_backend(
    backend: &LedgerBackend,
    entries: Vec<(Shard, Entry)>,
) -> Result<(), LedgerError> {
    match backend {
        LedgerBackend::Single(m) => match m.lock() {
            Ok(mut g) => g
                .append_all(entries.into_iter().map(|(_, entry)| entry).collect())
                .map(|_| ()),
            Err(_) => Err(poisoned()),
        },
        LedgerBackend::Sharded(_) => entries
            .into_iter()
            .try_for_each(|(shard, entry)| append_to_backend(backend, shard, entry)),
    }
}

/// The ledger shard for a record about a tenant's resource rather than a principal's act —
/// a subject search, which names no subject: the resource's tenant, or the unattributed
/// shard when the resource is unknown. The reserved name fails closed, as on a decision.
pub(crate) fn shard_for_tenant(backend: &LedgerBackend, tenant: Option<&str>) -> Shard {
    match backend {
        LedgerBackend::Sharded(_) => Some(match tenant.filter(|t| !t.is_empty()) {
            Some(t) if t == UNATTRIBUTED_SHARD => Err(format!(
                "the resource's tenant collides with the reserved shard {UNATTRIBUTED_SHARD:?}"
            )),
            Some(t) => Ok(t.to_owned()),
            None => Ok(UNATTRIBUTED_SHARD.to_owned()),
        }),
        LedgerBackend::Single(_) => None,
    }
}

/// The ledger shard for a subject: `Some(resolve_shard(...))` on the sharded backend
/// (derived server-side from the directory), `None` on the single-file backend.
pub(crate) fn shard_for(backend: &LedgerBackend, dir: &Directory, subject_id: &str) -> Shard {
    match backend {
        LedgerBackend::Sharded(_) => Some(resolve_shard(dir, subject_id)),
        LedgerBackend::Single(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Work that panics on its blocking thread is answered 503, never a dropped connection.
    #[tokio::test]
    async fn work_that_panics_off_the_executor_is_answered_503() {
        let response = off_the_executor("decision_unavailable", || panic!("work failed")).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    use decern_kernel::{Kernel, Model};

    use crate::testutil::test_dir;

    #[test]
    fn unrecordable_decision_returns_503_never_the_allow() {
        // A proven Allow whose audit record fails to write is not served.
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
}
