// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The OpenID AuthZEN *Authorization API 1.0* certification scenario
//! (`openid/authzen`, `certification/authorization-api-1_0-scenario.md`): every level,
//! Core and Properties, and Discovery, run in-process against the certification model in
//! `examples/authzen-certification/model`. Each test names the scenario test it is; the
//! requests are the scenario's own, byte for byte where it gives them.

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

mod basic;
mod batch;
mod search;

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
    for (field, path) in [
        ("search_subject_endpoint", "/access/v1/search/subject"),
        ("search_resource_endpoint", "/access/v1/search/resource"),
        ("search_action_endpoint", "/access/v1/search/action"),
    ] {
        assert_eq!(doc[field], format!("{PUBLIC_URL}{path}"), "{doc}");
    }
}
