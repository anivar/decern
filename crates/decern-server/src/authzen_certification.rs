// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The OpenID AuthZEN *Authorization API 1.0* certification scenario
//! (`openid/authzen`, `certification/authorization-api-1_0-scenario.md`), Basic Core, Basic
//! Properties and Discovery sub-levels, run in-process against the certification model in
//! `examples/authzen-certification/model`. Each test names the scenario test it is; the
//! requests are the scenario's own, byte for byte where it gives them.
//!
//! Batch and Search are not here, and the README says so.

use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use decern_kernel::{Kernel, Model};
use decern_ledger::Ledger;
use decern_store::FileMissionRegistry;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::decide::{DecideReq, decide};
use crate::routes::app;
use crate::testutil::{body_json, mission_base, open};
use crate::{AppState, LedgerBackend, caller_disclosure};

const PUBLIC_URL: &str = "https://pdp.example";

/// A test's ledger and mission registry live here, and go when the test ends.
struct TempBase(std::path::PathBuf);

impl Drop for TempBase {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The certification model, with the scenario's request types aliased onto the model's
/// and a public URL for the metadata document.
fn fixture_state() -> (AppState, TempBase) {
    let dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/authzen-certification/model");
    let model = Model::from_dir(&dir).expect("certification model loads");
    let base = mission_base();
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let pubkey = key.verifying_key();
    let mut ledger = Ledger::open(&base.join("ledger.jsonl"), key).unwrap();
    ledger.set_sync(true);
    let mut aliases = std::collections::BTreeMap::new();
    aliases.insert("user".to_owned(), "Principal".to_owned());
    aliases.insert("record".to_owned(), "Resource".to_owned());
    let st = AppState {
        kernel: Arc::new(Kernel::new(&model).unwrap()),
        model: Arc::new(model),
        backend: Arc::new(LedgerBackend::Single(Mutex::new(ledger))),
        type_aliases: Arc::new(aliases),
        public_url: Some(Arc::from(PUBLIC_URL)),
        missions: Arc::new(FileMissionRegistry::open(base.join("missions.json")).unwrap()),
        pubkey,
        require_mission: false,
        standing_issuers: Arc::new(Vec::new()),
        authority_digest: Arc::from("certification"),
        caller_disclosure: Arc::new(caller_disclosure(&crate::caller::Caller::TrustedProxy)),
    };
    (st, TempBase(base))
}

/// `POST /access/v1/evaluation` with a body and a content type, under `--trust-proxy`.
async fn evaluate(
    st: &AppState,
    body: impl Into<Body>,
    content_type: Option<&str>,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method("POST")
        .uri("/access/v1/evaluation");
    if let Some(ct) = content_type {
        req = req.header("content-type", ct);
    }
    app(st.clone(), open())
        .oneshot(req.body(body.into()).unwrap())
        .await
        .unwrap()
}

async fn decision(st: &AppState, body: &str) -> (StatusCode, Value) {
    let resp = evaluate(st, body.to_owned(), Some("application/json")).await;
    body_json(resp).await
}

fn fixture(subject: &str, action: &str, resource: &str) -> String {
    json!({
        "subject": { "type": "user", "id": subject },
        "action": { "name": action },
        "resource": { "type": "record", "id": resource },
    })
    .to_string()
}

/// C-1-4 rules 1–4 through C-2-2-1 and C-2-2-2: the decisions the harness validates.
#[tokio::test]
async fn the_fixture_decides_rules_one_to_four_as_the_scenario_requires() {
    let (st, _base) = fixture_state();
    for (subject, action, expect) in [
        ("alice", "read", true),
        ("alice", "write", true),
        ("bob", "read", true),
        ("bob", "write", false),
    ] {
        let (status, body) = decision(&st, &fixture(subject, action, "record-1")).await;
        assert_eq!(status, StatusCode::OK, "{subject} {action}: {body}");
        assert!(body["decision"].is_boolean(), "{body}");
        assert_eq!(
            body["decision"], expect,
            "{subject} {action} record-1: {body}"
        );
    }
}

/// C-2-2-3: a context the model does not declare is accepted, and the decision stands.
#[tokio::test]
async fn an_undeclared_optional_context_leaves_the_decision_unchanged() {
    let (st, _base) = fixture_state();
    let body = json!({
        "subject": { "type": "user", "id": "alice" },
        "action": { "name": "read" },
        "resource": { "type": "record", "id": "record-1" },
        "context": { "time": "2025-06-27T18:03-07:00", "ip": "192.168.1.1" },
    })
    .to_string();
    let (status, resp) = decision(&st, &body).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["decision"], true, "{resp}");
}

/// C-2-2-8 and C-2-2-9: additional `properties` on every entity and unknown top-level
/// fields are ignored, as the specification's forward-compatibility rule requires.
#[tokio::test]
async fn additional_properties_and_unknown_fields_are_ignored() {
    let (st, _base) = fixture_state();
    let with_properties = json!({
        "subject": { "type": "user", "id": "alice",
                     "properties": { "department": "Sales", "role": "manager" } },
        "action": { "name": "read", "properties": { "method": "GET" } },
        "resource": { "type": "record", "id": "record-1",
                      "properties": { "status": "active", "owner": "bob" } },
    })
    .to_string();
    let (status, body) = decision(&st, &with_properties).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], true, "{body}");

    let with_unknown = json!({
        "subject": { "type": "user", "id": "alice" },
        "action": { "name": "read" },
        "resource": { "type": "record", "id": "record-1" },
        "foo": "bar",
        "futureField": { "nested": true },
    })
    .to_string();
    let (status, body) = decision(&st, &with_unknown).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], true, "{body}");
}

/// C-2-4: every malformed shape the scenario lists is 400 — missing fields and
/// sub-fields, wrong types, a content type that is not JSON, a body that is not JSON,
/// an empty body.
#[tokio::test]
async fn a_malformed_request_is_400_in_every_shape_the_scenario_lists() {
    let (st, _base) = fixture_state();
    let cases: Vec<(&str, String)> = vec![
        ("missing subject", json!({"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}).to_string()),
        ("missing action", json!({"subject":{"type":"user","id":"alice"},"resource":{"type":"record","id":"record-1"}}).to_string()),
        ("missing resource", json!({"subject":{"type":"user","id":"alice"},"action":{"name":"read"}}).to_string()),
        ("subject without type", json!({"subject":{"id":"alice"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}).to_string()),
        ("subject without id", json!({"subject":{"type":"user"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}).to_string()),
        ("action without name", json!({"subject":{"type":"user","id":"alice"},"action":{},"resource":{"type":"record","id":"record-1"}}).to_string()),
        ("resource without type", json!({"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"id":"record-1"}}).to_string()),
        ("resource without id", json!({"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"record"}}).to_string()),
        ("subject is a string", json!({"subject":"alice","action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}).to_string()),
        ("action.name is a number", json!({"subject":{"type":"user","id":"alice"},"action":{"name":123},"resource":{"type":"record","id":"record-1"}}).to_string()),
        ("properties is a string", json!({"subject":{"type":"user","id":"alice","properties":"x"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"}}).to_string()),
        ("malformed JSON", "{\"subject\": ".to_owned()),
        ("empty body", String::new()),
    ];
    for (what, body) in cases {
        let (status, resp) = decision(&st, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {resp}");
    }
    // C-2-4-3: a content type other than application/json.
    let resp = evaluate(
        &st,
        fixture("alice", "read", "record-1"),
        Some("text/plain"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "text/plain content type"
    );
    let resp = evaluate(&st, fixture("alice", "read", "record-1"), None).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "no content type");
}

/// C-2-5: an `X-Request-ID` comes back unchanged; its absence changes nothing.
#[tokio::test]
async fn x_request_id_is_echoed_and_its_absence_is_harmless() {
    let (st, _base) = fixture_state();
    let resp = app(st.clone(), open())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .header("x-request-id", "req-7f3a")
                .body(Body::from(fixture("alice", "read", "record-1")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok()),
        Some("req-7f3a")
    );
    let (status, _) = decision(&st, &fixture("alice", "read", "record-1")).await;
    assert_eq!(status, StatusCode::OK);
}

/// C-2-6: the same request decides the same way each time.
#[tokio::test]
async fn the_same_request_decides_the_same_way_each_time() {
    let (st, _base) = fixture_state();
    for _ in 0..3 {
        let (status, body) = decision(&st, &fixture("bob", "write", "record-1")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["decision"], false, "{body}");
    }
}

/// C-6: the metadata document names the decision point and its evaluation endpoint,
/// as `application/json`, and nothing this deployment does not serve.
#[tokio::test]
async fn the_metadata_document_names_the_decision_point_and_only_what_is_served() {
    let (st, _base) = fixture_state();
    let resp = app(st, open())
        .oneshot(
            Request::builder()
                .uri("/.well-known/authzen-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/json")),
        "{:?}",
        resp.headers().get("content-type")
    );
    let (_, doc) = body_json(resp).await;
    assert_eq!(doc["policy_decision_point"], PUBLIC_URL);
    assert_eq!(
        doc["access_evaluation_endpoint"],
        format!("{PUBLIC_URL}/access/v1/evaluation")
    );
    for absent in ["access_evaluations_endpoint", "search_subject_endpoint"] {
        assert!(
            doc.get(absent).is_none(),
            "{absent} is not served and must not be advertised"
        );
    }
}

/// C-2-2-4 to C-2-2-7, rules 5–8: the decision turns on what the PEP says about the
/// resource (archived), the subject (admin) and the action (soft).
#[tokio::test]
async fn properties_decide_rules_five_to_eight_as_the_scenario_requires() {
    let (st, _base) = fixture_state();
    for (what, body, expect) in [
        (
            "rule 5: alice writes an archived record",
            json!({
                "subject": { "type": "user", "id": "alice" },
                "action": { "name": "write" },
                "resource": { "type": "record", "id": "record-2",
                              "properties": { "status": "archived" } },
            }),
            false,
        ),
        (
            "rule 6: an admin writes an archived record",
            json!({
                "subject": { "type": "user", "id": "bob", "properties": { "role": "admin" } },
                "action": { "name": "write" },
                "resource": { "type": "record", "id": "record-2",
                              "properties": { "status": "archived" } },
            }),
            true,
        ),
        (
            "rule 7: a soft delete",
            json!({
                "subject": { "type": "user", "id": "alice" },
                "action": { "name": "delete", "properties": { "soft": true } },
                "resource": { "type": "record", "id": "record-1" },
            }),
            true,
        ),
        (
            "rule 8: a hard delete",
            json!({
                "subject": { "type": "user", "id": "alice" },
                "action": { "name": "delete", "properties": { "soft": false } },
                "resource": { "type": "record", "id": "record-1" },
            }),
            false,
        ),
    ] {
        let (status, resp) = decision(&st, &body.to_string()).await;
        assert_eq!(status, StatusCode::OK, "{what}: {resp}");
        assert_eq!(resp["decision"], expect, "{what}: {resp}");
    }
}

/// A description of a party is admitted from a PEP, a bearer caller or a trusted front, and
/// refused from a caller bound to itself, which may not say what it is.
#[tokio::test]
async fn a_caller_bound_to_itself_may_not_describe_a_party() {
    let (st, _base) = fixture_state();
    let body = json!({
        "subject": { "type": "user", "id": "bob", "properties": { "role": "admin" } },
        "action": { "name": "write" },
        "resource": { "type": "record", "id": "record-2", "properties": { "status": "archived" } },
    });
    let req: DecideReq = serde_json::from_value(body.clone()).unwrap();
    let workload =
        crate::caller::Authenticated::new("bob", "bob", "https://iss.example/").self_only();
    let (status, resp) = body_json(
        decide(
            State(st.clone()),
            Some(axum::Extension(workload)),
            Ok(Json(req)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(resp["error"], "caller_mismatch");

    let req: DecideReq = serde_json::from_value(body).unwrap();
    let pep = crate::caller::Authenticated::new("gateway", "gateway", "https://iss.example/");
    let (status, resp) =
        body_json(decide(State(st.clone()), Some(axum::Extension(pep)), Ok(Json(req))).await).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["decision"], true, "{resp}");

    // An empty `properties` describes nothing: a client that always sends the key is not
    // refused for it, and the workload gets its decision.
    let empty: DecideReq = serde_json::from_value(json!({
        "subject": { "type": "user", "id": "bob", "properties": {} },
        "action": { "name": "read", "properties": {} },
        "resource": { "type": "record", "id": "record-1", "properties": {} },
    }))
    .unwrap();
    let workload =
        crate::caller::Authenticated::new("bob", "bob", "https://iss.example/").self_only();
    let (status, resp) =
        body_json(decide(State(st), Some(axum::Extension(workload)), Ok(Json(empty))).await).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["decision"], true, "{resp}");
}

/// `context.subject`, `context.resource` and `context.action` are reserved for the
/// request's `properties`: writing there directly describes nothing.
#[tokio::test]
async fn a_description_cannot_be_smuggled_through_the_free_form_context() {
    let (st, _base) = fixture_state();
    let body = json!({
        "subject": { "type": "user", "id": "bob" },
        "action": { "name": "write" },
        "resource": { "type": "record", "id": "record-2" },
        "context": { "subject": { "role": "admin" }, "resource": { "status": "archived" } },
    });
    let (status, resp) = decision(&st, &body.to_string()).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["decision"], false, "rule 4 stands: {resp}");
}

/// What the PEP said and a policy could read is on the record; what it said and no policy
/// could read is not.
#[tokio::test]
async fn the_record_carries_declared_properties_and_nothing_else() {
    let (st, base) = fixture_state();
    let body = json!({
        "subject": { "type": "user", "id": "bob",
                     "properties": { "role": "admin", "department": "Sales" } },
        "action": { "name": "write", "properties": { "method": "PUT" } },
        "resource": { "type": "record", "id": "record-2",
                      "properties": { "status": "archived", "owner": "alice" } },
    });
    let (status, resp) = decision(&st, &body.to_string()).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["decision"], true, "{resp}");
    let ledger = base.0.join("ledger.jsonl");
    let (_r, records) = decern_ledger::read_verified(&ledger, Some(&st.pubkey), 0, 10).unwrap();
    let ctx = &records.last().expect("recorded")["entry"]["context"];
    assert_eq!(ctx["subject"], json!({ "role": "admin" }), "{ctx}");
    assert_eq!(ctx["resource"], json!({ "status": "archived" }), "{ctx}");
    assert!(
        ctx.get("action").is_none(),
        "write declares no action properties: {ctx}"
    );
}
