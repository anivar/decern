// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The Mission lifecycle layer: approve, read and terminate scoped Missions,
//! each accepted transition recorded before it is reported.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use decern_identity::{IdentityError, mission, mission::Mission};
use decern_kernel::Directory;
use decern_ledger::Entry;
use decern_store::{MissionRegistry, StoreError};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::decide::resolve_sponsor;
use crate::record::{append_to_backend, record_or_503, shard_for};
use crate::{AppState, now_secs};

// ============================== Mission lifecycle ==============================
//
// An approver grants an agent a scoped, provably-attenuated Mission (`decern-identity`).
// Each accepted transition — approve, terminate — is recorded to the tamper-evident
// ledger before it is reported as succeeded (fail-closed), exactly as a decision is.

/// `POST /mission/v1/approve` body.
#[derive(Deserialize)]
pub(crate) struct MissionApproveReq {
    pub(crate) approver: String,
    pub(crate) agent: String,
    pub(crate) description: String,
    pub(crate) approved_tools: Vec<String>,
    #[serde(default)]
    pub(crate) capabilities: Vec<String>,
    pub(crate) expiry: u64,
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
    mut context: Value,
    asserted_by: Option<decern_ledger::AssertedBy>,
) -> Entry {
    // Defense-in-depth: remove any asserted_by key that somehow reached the context,
    // so it cannot shadow the server-derived top-level column on the permanent record.
    if let Some(obj) = context.as_object_mut() {
        obj.remove("asserted_by");
    }
    // For a Mission event the accountable-owner is the APPROVER's own delegation root
    // (subject = approver), not the agent the mission authorizes: the approver is who
    // stands behind the grant. Resolved server-side, never read from the request.
    let sponsor = resolve_sponsor(dir, approver);
    let parameters_digest = decern_ledger::digest(&json!({
        "action": action,
        "approver": approver,
        "s256": s256,
        "context": context,
    }));
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
        mission: Some(decern_ledger::MissionRef {
            approver: approver.to_owned(),
            s256: s256.to_owned(),
        }),
        asserted_by,
        digests: BTreeMap::from([(
            decern_ledger::DIGEST_PARAMETERS.to_owned(),
            parameters_digest,
        )]),
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
pub(crate) async fn mission_approve(
    State(st): State<AppState>,
    caller: Option<axum::Extension<crate::caller::Authenticated>>,
    Json(req): Json<MissionApproveReq>,
) -> Response {
    if let Some(refusal) = crate::caller::refuse_unless_admits(&caller, &req.approver) {
        return refusal;
    }
    let asserted_by = caller
        .as_ref()
        .map(|axum::Extension(who)| decern_ledger::AssertedBy {
            sub: who.subject.clone(),
            client_id: who.client_id.clone(),
            iss: who.issuer.clone(),
        });
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
    let entry = mission_entry(
        dir,
        now_s,
        &approver,
        "Mission.Approve",
        &s256,
        context,
        asserted_by,
    );

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
pub(crate) async fn mission_get(
    State(st): State<AppState>,
    UrlPath(s256): UrlPath<String>,
) -> Response {
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
pub(crate) async fn mission_terminate(
    State(st): State<AppState>,
    caller: Option<axum::Extension<crate::caller::Authenticated>>,
    UrlPath(s256): UrlPath<String>,
) -> Response {
    let asserted_by = caller
        .as_ref()
        .map(|axum::Extension(who)| decern_ledger::AssertedBy {
            sub: who.subject.clone(),
            client_id: who.client_id.clone(),
            iss: who.issuer.clone(),
        });
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
    if let Some(refusal) = crate::caller::refuse_unless_admits(&caller, &entry.approver) {
        return refusal;
    }
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
        asserted_by,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LedgerBackend;
    use crate::testutil::{approve_req, body_json, corp_expiry, mission_base, mission_state_at};

    #[tokio::test]
    async fn approved_mission_survives_a_registry_reopen() {
        // Durability: approve, then drop the state and open FRESH durable handles on the
        // same files — GET must still report the mission active.
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                None,
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
                None,
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let (status, _b) =
            body_json(mission_terminate(State(st.clone()), None, UrlPath(s256.clone())).await)
                .await;
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
                None,
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
                None,
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
                None,
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
                None,
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
                None,
                Json(approve_req(&["read", "move_money"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let (status, _b) =
            body_json(mission_terminate(State(st), None, UrlPath(s256.clone())).await).await;
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
    async fn mission_approve_records_asserted_by_under_bearer_mode() {
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        let ledger_path = base.join("decern-ledger.jsonl");

        let auth = crate::caller::Authenticated::new(
            "operator-1",
            "admin-cli",
            "https://auth.example.com",
        );

        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                Some(axum::Extension(auth)),
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 10).unwrap();
        assert_eq!(records.len(), 1);
        let entry = &records[0]["entry"];
        assert_eq!(entry["action"], "Mission.Approve");
        assert_eq!(entry["resource_id"], s256);
        assert_eq!(entry["asserted_by"]["sub"], "operator-1");
        assert_eq!(entry["asserted_by"]["client_id"], "admin-cli");
        assert_eq!(entry["asserted_by"]["iss"], "https://auth.example.com");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn mission_approve_omits_asserted_by_under_proxy_mode() {
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        let ledger_path = base.join("decern-ledger.jsonl");

        let (status, _body) = body_json(
            mission_approve(
                State(st.clone()),
                None,
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 10).unwrap();
        assert_eq!(records.len(), 1);
        let entry = &records[0]["entry"];
        assert!(entry.get("asserted_by").is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn mission_terminate_records_asserted_by_under_bearer_mode() {
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        let ledger_path = base.join("decern-ledger.jsonl");

        let auth_approve = crate::caller::Authenticated::new(
            "operator-1",
            "admin-cli",
            "https://auth.example.com",
        );

        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                Some(axum::Extension(auth_approve)),
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let auth_term =
            crate::caller::Authenticated::new("operator-2", "ops-tool", "https://auth.example.com");

        let (status, _b) = body_json(
            mission_terminate(
                State(st.clone()),
                Some(axum::Extension(auth_term)),
                UrlPath(s256.clone()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 10).unwrap();
        assert_eq!(records.len(), 2);
        let term_entry = &records[1]["entry"];
        assert_eq!(term_entry["action"], "Mission.Terminate");
        assert_eq!(term_entry["asserted_by"]["sub"], "operator-2");
        assert_eq!(term_entry["asserted_by"]["client_id"], "ops-tool");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn mission_terminate_omits_asserted_by_under_proxy_mode() {
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        let ledger_path = base.join("decern-ledger.jsonl");

        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                None,
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let (status, _b) =
            body_json(mission_terminate(State(st), None, UrlPath(s256.clone())).await).await;
        assert_eq!(status, StatusCode::OK);

        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 10).unwrap();
        assert_eq!(records.len(), 2);
        let term_entry = &records[1]["entry"];
        assert_eq!(term_entry["action"], "Mission.Terminate");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// No caller reaches this today — `mission_approve`/`mission_terminate` build
    /// `context` entirely from `approved.mission.*`, never from the request body — so
    /// the strip in `mission_entry` has no live exploit path. This calls the function
    /// directly to prove the defense-in-depth fires anyway, in case a future change
    /// ever makes the path reachable.
    #[test]
    fn mission_entry_strips_a_context_supplied_asserted_by() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let dir = st.kernel.directory();
        let entry = mission_entry(
            dir,
            1,
            "corp",
            "Mission.Approve",
            "deadbeef",
            json!({
                "approved_tools": ["read"],
                "asserted_by": {"sub": "forged", "client_id": "x", "iss": "y"},
            }),
            None,
        );
        assert!(
            entry.context.get("asserted_by").is_none(),
            "a context-supplied asserted_by must not survive into the record: {:?}",
            entry.context
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn asserted_by_does_not_influence_the_mission_reference() {
        // The s256 reference is a pure function of the grant's authority, not of who called
        // the endpoint. Two approvals with different bearer identities for the same grant must
        // produce the same reference — asserted_by is strictly descriptive, never an input.
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        let ledger_path = base.join("decern-ledger.jsonl");

        let (status, body_a) = body_json(
            mission_approve(
                State(st.clone()),
                Some(axum::Extension(crate::caller::Authenticated::new(
                    "caller-a",
                    "client-a",
                    "https://auth.example.com",
                ))),
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256_a = body_a["s256"].as_str().unwrap().to_owned();

        // Second approve: same grant, different bearer — hits the idempotent registered path.
        let (status, body_b) = body_json(
            mission_approve(
                State(st.clone()),
                Some(axum::Extension(crate::caller::Authenticated::new(
                    "caller-b",
                    "client-b",
                    "https://auth.example.com",
                ))),
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256_b = body_b["s256"].as_str().unwrap().to_owned();

        assert_eq!(
            s256_a, s256_b,
            "reference must be invariant to the bearer identity"
        );

        // Verify both ledger entries are signed and chained cleanly.
        let report = decern_ledger::verify(&ledger_path, Some(&pubkey)).unwrap();
        assert!(report.signatures_checked);

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The theft: an authenticated agent minting a Mission as `corp`. Attenuation
    /// would succeed; admission is what stops it.
    #[tokio::test]
    async fn a_self_only_caller_cannot_approve_as_another_principal() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let thief = crate::caller::Authenticated::new("agent-1", "agent-1", "https://iss.example/")
            .self_only();
        let (status, body) = body_json(
            mission_approve(
                State(st),
                Some(axum::Extension(thief)),
                Json(approve_req(&["move_money"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "caller_mismatch");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_self_only_caller_cannot_terminate_anothers_mission() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                None,
                Json(approve_req(&["read"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let thief = crate::caller::Authenticated::new("agent-1", "agent-1", "https://iss.example/")
            .self_only();
        let (status, body) = body_json(
            mission_terminate(
                State(st.clone()),
                Some(axum::Extension(thief)),
                UrlPath(s256.clone()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "caller_mismatch");

        let (status, body) = body_json(mission_get(State(st), UrlPath(s256)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["state"], "active",
            "a refused terminate must not kill the grant"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
