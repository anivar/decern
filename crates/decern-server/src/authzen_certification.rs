// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The OpenID AuthZEN *Authorization API 1.0* certification scenario
//! (`openid/authzen`, `certification/authorization-api-1_0-scenario.md`): the Basic and
//! Batch levels, Core and Properties, and Discovery, run in-process against the certification model in
//! `examples/authzen-certification/model`. Each test names the scenario test it is; the
//! requests are the scenario's own, byte for byte where it gives them.
//!
//! Search is not here, and the README says so.

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
        ("context is a string", json!({"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"record","id":"record-1"},"context":"x"}).to_string()),
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
    assert_eq!(
        doc["access_evaluations_endpoint"],
        format!("{PUBLIC_URL}/access/v1/evaluations")
    );
    for absent in [
        "search_subject_endpoint",
        "search_resource_endpoint",
        "search_action_endpoint",
    ] {
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

/// `POST /access/v1/evaluations` with a JSON body, under `--trust-proxy`.
async fn evaluations(st: &AppState, body: &Value) -> (StatusCode, Value) {
    let resp = app(st.clone(), open())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluations")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(resp).await
}

fn decisions(resp: &Value) -> Vec<Value> {
    resp["evaluations"]
        .as_array()
        .unwrap_or_else(|| panic!("evaluations array: {resp}"))
        .iter()
        .map(|e| e["decision"].clone())
        .collect()
}

fn records_in(base: &TempBase, st: &AppState) -> Vec<Value> {
    let ledger = base.0.join("ledger.jsonl");
    decern_ledger::read_verified(&ledger, Some(&st.pubkey), 0, 10_000)
        .map(|(_, records)| records)
        .unwrap_or_default()
}

/// C-3-2-1, C-3-2-2, C-3-2-5, C-3-2-6, C-3-3-x: the Batch Core requests, answered in
/// request order with the defaults filled in and no top-level decision.
#[tokio::test]
async fn batch_core_decides_in_request_order_with_defaults_filled_in() {
    let (st, _base) = fixture_state();
    // C-3-2-1: structure.
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "evaluations": [
                { "resource": { "type": "record", "id": "record-1" } },
                { "resource": { "type": "record", "id": "record-2" } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(decisions(&resp).iter().all(Value::is_boolean), "{resp}");
    assert_eq!(decisions(&resp).len(), 2, "{resp}");
    assert!(
        resp.get("decision").is_none(),
        "no top-level decision: {resp}"
    );
    // C-3-2-2: rules 3 and 4, in order.
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "bob" },
            "resource": { "type": "record", "id": "record-1" },
            "evaluations": [{ "action": { "name": "read" } }, { "action": { "name": "write" } }],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(true), json!(false)], "{resp}");
    // C-3-2-5: fully specified items, no defaults.
    let (status, resp) = evaluations(
        &st,
        &json!({
            "evaluations": [
                { "subject": { "type": "user", "id": "alice" }, "action": { "name": "read" },
                  "resource": { "type": "record", "id": "record-1" } },
                { "subject": { "type": "user", "id": "bob" }, "action": { "name": "write" },
                  "resource": { "type": "record", "id": "record-1" } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(true), json!(false)], "{resp}");
    // C-3-2-6: a top-level context, overridden whole by the second item.
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "context": { "time": "2025-06-27T18:03-07:00" },
            "evaluations": [
                { "resource": { "type": "record", "id": "record-1" } },
                { "resource": { "type": "record", "id": "record-2" },
                  "context": { "time": "2025-06-27T19:00-07:00", "source": "batch-override" } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(true), json!(true)], "{resp}");
}

/// C-3-2-3, C-3-2-4, C-3-2-7: properties are evaluated per item, and a key an item carries
/// replaces the top-level default whole.
#[tokio::test]
async fn batch_properties_are_evaluated_per_item() {
    let (st, _base) = fixture_state();
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "write" },
            "evaluations": [
                { "resource": { "type": "record", "id": "record-1", "properties": { "status": "active" } } },
                { "resource": { "type": "record", "id": "record-2", "properties": { "status": "archived" } } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        decisions(&resp),
        [json!(true), json!(false)],
        "C-3-2-3: {resp}"
    );
    let (status, resp) = evaluations(
        &st,
        &json!({
            "action": { "name": "write" },
            "resource": { "type": "record", "id": "record-2", "properties": { "status": "archived" } },
            "evaluations": [
                { "subject": { "type": "user", "id": "alice" } },
                { "subject": { "type": "user", "id": "bob", "properties": { "role": "admin" } } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        decisions(&resp),
        [json!(false), json!(true)],
        "C-3-2-4: {resp}"
    );
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "write" },
            "resource": { "type": "record", "id": "record-1", "properties": { "status": "active" } },
            "evaluations": [
                {},
                { "resource": { "type": "record", "id": "record-2", "properties": { "status": "archived" } } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        decisions(&resp),
        [json!(true), json!(false)],
        "C-3-2-7: {resp}"
    );
}

/// C-3-4-1: under `execute_all`, an item that is not an evaluation is answered
/// `decision: false` with the reason in its context (§7.2.1's shape: `context.error`
/// with the status the single endpoint would have answered), in its place, and nothing is
/// recorded for it — it decided nothing.
#[tokio::test]
async fn a_batch_item_that_is_not_an_evaluation_is_denied_in_place_and_not_recorded() {
    let (st, base) = fixture_state();
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "options": { "evaluations_semantic": "execute_all" },
            "evaluations": [{ "resource": { "type": "record", "id": "record-1" } }, {}],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(true), json!(false)], "{resp}");
    let error = &resp["evaluations"][1]["context"]["error"];
    assert_eq!(error["status"], 400, "{resp}");
    assert_eq!(error["code"], "invalid_request", "{resp}");
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|m| m.contains("resource")),
        "the reason names what is missing: {resp}"
    );
    let records = records_in(&base, &st);
    assert_eq!(
        records.len(),
        1,
        "only the evaluated item is recorded: {records:?}"
    );
    assert_eq!(records[0]["entry"]["resource_id"], "record-1");
}

/// C-3-4-2, C-3-4-3: no items, or an empty array, is the single evaluation — in request
/// and in answer.
#[tokio::test]
async fn a_batch_without_items_is_the_single_evaluation() {
    let (st, _base) = fixture_state();
    for body in [
        json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
        }),
        json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "evaluations": [],
        }),
    ] {
        let (status, resp) = evaluations(&st, &body).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        assert_eq!(resp["decision"], true, "{resp}");
        assert!(resp.get("evaluations").is_none(), "{resp}");
    }
    // And a single evaluation that is not one is 400, as on the single endpoint.
    let (status, resp) = evaluations(
        &st,
        &json!({ "subject": { "type": "user", "id": "alice" }, "action": { "name": "read" } }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert!(
        resp["detail"]
            .as_str()
            .is_some_and(|d| d.contains("resource") && !d.contains("evaluations[")),
        "a batch without items names no item: {resp}"
    );
}

/// §7.1.2.1: `deny_on_first_deny` stops at the first deny, `permit_on_first_permit` at
/// the first permit, `execute_all` at the end; a semantic this server does not know is
/// refused rather than executed as another.
#[tokio::test]
async fn batch_semantics_stop_where_the_specification_says() {
    let (st, base) = fixture_state();
    let items = json!([
        { "subject": { "type": "user", "id": "alice" }, "action": { "name": "read" } },
        { "subject": { "type": "user", "id": "bob" }, "action": { "name": "write" } },
        { "subject": { "type": "user", "id": "alice" }, "action": { "name": "write" } },
    ]);
    for (semantic, expect) in [
        ("execute_all", vec![true, false, true]),
        ("deny_on_first_deny", vec![true, false]),
        ("permit_on_first_permit", vec![true]),
    ] {
        let (status, resp) = evaluations(
            &st,
            &json!({
                "resource": { "type": "record", "id": "record-1" },
                "options": { "evaluations_semantic": semantic },
                "evaluations": items,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{semantic}: {resp}");
        assert_eq!(
            decisions(&resp),
            expect.iter().map(|d| json!(d)).collect::<Vec<_>>(),
            "{semantic}: {resp}"
        );
    }
    // Every evaluated item, and only those, is on the record: 3 + 2 + 1.
    assert_eq!(records_in(&base, &st).len(), 6);
    let (status, resp) = evaluations(
        &st,
        &json!({
            "resource": { "type": "record", "id": "record-1" },
            "options": { "evaluations_semantic": "first_come_first_served" },
            "evaluations": items,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert_eq!(resp["error"], "invalid_request");
}

/// Admission is for the whole exchange and comes first: a caller bound to itself that
/// names another principal in any item is refused before anything is evaluated or
/// recorded.
#[tokio::test]
async fn a_batch_is_refused_whole_when_one_item_is_not_the_callers_to_ask() {
    let (st, base) = fixture_state();
    let req: crate::batch::BatchReq = serde_json::from_value(json!({
        "action": { "name": "read" },
        "resource": { "type": "record", "id": "record-1" },
        "evaluations": [
            { "subject": { "type": "user", "id": "bob" } },
            { "subject": { "type": "user", "id": "alice" } },
        ],
    }))
    .unwrap();
    let workload =
        crate::caller::Authenticated::new("bob", "bob", "https://iss.example/").self_only();
    let (status, resp) = body_json(
        crate::batch::evaluations(
            State(st.clone()),
            Some(axum::Extension(workload)),
            Ok(Json(req)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(resp["error"], "caller_mismatch");
    assert!(records_in(&base, &st).is_empty(), "nothing was recorded");

    // An item that is not an evaluation still names whom it names: the refusal does not
    // hide behind a malformed item's per-item deny.
    let req: crate::batch::BatchReq = serde_json::from_value(json!({
        "action": { "name": "read" },
        "evaluations": [
            { "subject": { "type": "user", "id": "bob" },
              "resource": { "type": "record", "id": "record-1" } },
            { "subject": { "type": "user", "id": "alice" } },
        ],
    }))
    .unwrap();
    let workload =
        crate::caller::Authenticated::new("bob", "bob", "https://iss.example/").self_only();
    let (status, resp) = body_json(
        crate::batch::evaluations(
            State(st.clone()),
            Some(axum::Extension(workload)),
            Ok(Json(req)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(records_in(&base, &st).is_empty(), "nothing was recorded");
}

/// A bounded exchange: one over the cap is refused with the cap named.
#[tokio::test]
async fn a_batch_over_the_cap_is_refused() {
    let (st, _base) = fixture_state();
    let items: Vec<Value> = (0..=crate::batch::MAX_EVALUATIONS)
        .map(|_| json!({ "resource": { "type": "record", "id": "record-1" } }))
        .collect();
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "evaluations": items,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert!(
        resp["detail"]
            .as_str()
            .is_some_and(|d| d.contains(&crate::batch::MAX_EVALUATIONS.to_string())),
        "{resp}"
    );
}

/// A refusal this server would answer 422 on the single endpoint — here, a decision
/// subject that identifies a person — is carried inside the item that earned it, as that
/// item's deny with `context.error` carrying the status and code, and the item is not
/// recorded; the rest of the exchange is unaffected, and `deny_on_first_deny` treats it as
/// the deny it is.
#[tokio::test]
async fn a_refusal_inside_a_batch_item_is_that_items_deny_and_records_nothing_for_it() {
    let (st, base) = fixture_state();
    let body = json!({
        "subject": { "type": "user", "id": "alice" },
        "action": { "name": "read" },
        "resource": { "type": "record", "id": "record-1" },
        "evaluations": [
            {},
            { "context": { "decision_subject": "carol@example.com" } },
            {},
        ],
    });
    let (status, resp) = evaluations(&st, &body).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        decisions(&resp),
        [json!(true), json!(false), json!(true)],
        "{resp}"
    );
    let error = &resp["evaluations"][1]["context"]["error"];
    assert_eq!(error["status"], 422, "{resp}");
    assert_eq!(error["code"], "decision_subject", "{resp}");
    let records = records_in(&base, &st);
    assert_eq!(
        records.len(),
        2,
        "the refused item decided nothing: {records:?}"
    );
    assert!(
        !records
            .iter()
            .any(|r| r.to_string().contains("carol@example.com")),
        "a refused handle never reaches the ledger"
    );

    let mut short = body.clone();
    short["options"] = json!({ "evaluations_semantic": "deny_on_first_deny" });
    let (status, resp) = evaluations(&st, &short).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(true), json!(false)], "{resp}");
}

/// A context larger than one evaluation may carry is refused before it is evaluated or
/// recorded — 413 on the single endpoint, that item's answer in a batch — and a batch
/// whose default context is too large does not copy it into every item to find out; an
/// item that brings its own context is judged on that.
#[tokio::test]
async fn an_oversize_context_is_refused_before_it_is_evaluated_or_recorded() {
    let (st, base) = fixture_state();
    let pad = "x".repeat(crate::decide::MAX_CONTEXT_BYTES + 1);
    let (status, resp) = decision(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "context": { "pad": pad },
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{resp}");
    assert_eq!(resp["error"], "context_too_large");
    assert!(records_in(&base, &st).is_empty(), "nothing recorded");

    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "context": { "pad": pad },
            "evaluations": [{}, { "context": { "small": true } }],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(false), json!(true)], "{resp}");
    assert_eq!(
        resp["evaluations"][0]["context"]["error"]["status"], 413,
        "{resp}"
    );
    assert_eq!(
        records_in(&base, &st).len(),
        1,
        "only the decided item is recorded"
    );

    // The same for a party whose default `properties` are that large: the item that
    // inherits it is answered without the copy, the item that brings its own is decided.
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1", "properties": { "pad": pad } },
            "evaluations": [
                {},
                { "resource": { "type": "record", "id": "record-1", "properties": {} } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(false), json!(true)], "{resp}");
    assert_eq!(
        resp["evaluations"][0]["context"]["error"]["status"], 413,
        "{resp}"
    );
    assert_eq!(
        records_in(&base, &st).len(),
        2,
        "one more decided item is recorded"
    );
}

/// What the record keeps of a `context.mission` is the pair that was looked up — never
/// the object as sent, which is caller-chosen and would be permanent.
#[tokio::test]
async fn the_record_carries_the_mission_pair_not_the_object_sent() {
    let (st, base) = fixture_state();
    let (status, resp) = decision(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "context": { "mission": { "approver": "alice", "s256": "nope", "pad": "y".repeat(10_000) } },
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        resp["decision"], false,
        "an unregistered mission denies: {resp}"
    );
    let records = records_in(&base, &st);
    let mission = &records.last().expect("recorded")["entry"]["context"]["mission"];
    assert_eq!(
        mission,
        &json!({ "approver": "alice", "s256": "nope" }),
        "{mission}"
    );
}
