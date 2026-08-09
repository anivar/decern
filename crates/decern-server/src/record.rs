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
/// a decision that cannot be recorded is never served. This is the whole contract.
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

/// Append `entry` to whichever backend is configured, fail-closed. `shard` is the
/// server-derived ledger shard: `Some(Ok(shard))` for the sharded backend, `None` for
/// the single-file backend; a shard-resolver error (or the impossible `None` on the
/// sharded arm) becomes a ledger error → 503, never a panic or a misfiled record.
pub(crate) fn append_to_backend(
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
pub(crate) fn shard_for(
    backend: &LedgerBackend,
    dir: &Directory,
    subject_id: &str,
) -> Option<Result<String, String>> {
    match backend {
        LedgerBackend::Sharded(_) => Some(resolve_shard(dir, subject_id)),
        LedgerBackend::Single(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decern_kernel::{Kernel, Model};

    use crate::testutil::test_dir;

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
