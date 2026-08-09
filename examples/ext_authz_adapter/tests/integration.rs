// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Integration test suite for ext_authz_adapter against a mock PDP server.

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderName, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt;

use ext_authz_adapter::{AppState, PdpClient, create_router};

#[derive(Clone)]
struct MockPdpState {
    mode: Arc<AtomicUsize>,
    last_auth_header: Arc<tokio::sync::Mutex<Option<String>>>,
}

async fn mock_pdp_handler(
    State(st): State<MockPdpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let mut guard = st.last_auth_header.lock().await;
        *guard = Some(auth.to_string());
    }

    assert_eq!(body["subject"]["type"], "Principal");
    assert!(body["subject"]["id"].is_string());
    assert!(body["action"]["name"].is_string());
    assert_eq!(body["resource"]["type"], "Resource");

    match st.mode.load(Ordering::SeqCst) {
        0 => (StatusCode::OK, Json(json!({ "decision": true }))).into_response(),
        1 => (StatusCode::OK, Json(json!({ "decision": false }))).into_response(),
        2 => (StatusCode::OK, Json(json!({ "unrelated": true }))).into_response(),
        4 => {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            (StatusCode::OK, Json(json!({ "decision": true }))).into_response()
        }
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "ledger record failed" })),
        )
            .into_response(),
    }
}

async fn spawn_mock_pdp() -> (
    String,
    Arc<AtomicUsize>,
    Arc<tokio::sync::Mutex<Option<String>>>,
) {
    let mode = Arc::new(AtomicUsize::new(0));
    let last_auth_header = Arc::new(tokio::sync::Mutex::new(None));
    let state = MockPdpState {
        mode: mode.clone(),
        last_auth_header: last_auth_header.clone(),
    };

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/access/v1/evaluation", post(mock_pdp_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (
        format!("http://127.0.0.1:{}", addr.port()),
        mode,
        last_auth_header,
    )
}

fn build_adapter_router(pdp_url: &str) -> Router {
    build_adapter_router_full(pdp_url, "x-forwarded-subject", None)
}

fn build_adapter_router_with_subject_header(pdp_url: &str, subject_header_name: &str) -> Router {
    build_adapter_router_full(pdp_url, subject_header_name, None)
}

fn build_adapter_router_full(
    pdp_url: &str,
    subject_header_name: &str,
    bearer_token: Option<&str>,
) -> Router {
    let pdp_client = Arc::new(PdpClient::new(pdp_url, 5, bearer_token.map(String::from)).unwrap());
    let state = AppState {
        pdp_client,
        subject_header: HeaderName::from_str(subject_header_name).unwrap(),
        method_header: HeaderName::from_str("x-forwarded-method").unwrap(),
        uri_header: HeaderName::from_str("x-forwarded-uri").unwrap(),
        subject_type: "Principal".to_string(),
        resource_type: "Resource".to_string(),
    };
    create_router(state)
}

#[tokio::test]
async fn test_adapter_healthz() {
    let app = build_adapter_router("http://127.0.0.1:9999");
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn test_allow_decision_nginx_style() {
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(0, Ordering::SeqCst);

    let app = build_adapter_router(&pdp_url);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "/claims/claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "allow"
    );
}

#[tokio::test]
async fn test_allow_decision_traefik_style_headers() {
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(0, Ordering::SeqCst);

    let app = build_adapter_router_with_subject_header(&pdp_url, "X-Forwarded-User");
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("X-Forwarded-User", "corp")
        .header("X-Forwarded-Method", "Read")
        .header("X-Forwarded-Uri", "/claims/claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "allow"
    );
}

#[tokio::test]
async fn test_allow_decision_envoy_http_filter_style() {
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(0, Ordering::SeqCst);

    // Envoy's envoy.extensions.filters.http.ext_authz.v3.ExtAuthz filter sends HTTP POST requests
    let app = build_adapter_router(&pdp_url);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "DELETE")
        .header("x-forwarded-uri", "/api/v1/resources/100")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "allow"
    );
}

#[tokio::test]
async fn test_deny_decision() {
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(1, Ordering::SeqCst);

    let app = build_adapter_router(&pdp_url);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "nobody")
        .header("x-forwarded-method", "Write")
        .header("x-forwarded-uri", "/claims/claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "deny"
    );
}

#[tokio::test]
async fn test_missing_subject_header_refused() {
    let (pdp_url, _, _) = spawn_mock_pdp().await;
    let app = build_adapter_router(&pdp_url);

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "/claims/claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "deny"
    );
}

#[tokio::test]
async fn test_whitespace_only_subject_header_refused() {
    let (pdp_url, _, _) = spawn_mock_pdp().await;
    let app = build_adapter_router(&pdp_url);

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "   ")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "/claims/claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "deny"
    );
}

#[tokio::test]
async fn test_missing_method_header_refused() {
    // A gateway that forwards who is calling but not what they asked for gets a
    // refusal, not a request evaluated under a defaulted action.
    let (pdp_url, _mode, _) = spawn_mock_pdp().await;
    let app = build_adapter_router(&pdp_url);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-uri", "claim1")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "deny"
    );
}

#[tokio::test]
async fn test_missing_uri_header_refused() {
    let (pdp_url, _mode, _) = spawn_mock_pdp().await;
    let app = build_adapter_router(&pdp_url);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "deny"
    );
}

#[tokio::test]
async fn test_bearer_token_forwarded_to_pdp() {
    let (pdp_url, mode, last_auth) = spawn_mock_pdp().await;
    mode.store(0, Ordering::SeqCst);

    let app = build_adapter_router_full(
        &pdp_url,
        "x-forwarded-subject",
        Some("secret_access_token_123"),
    );
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "/claims/claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let auth_header = last_auth.lock().await;
    assert_eq!(
        auth_header.as_deref(),
        Some("Bearer secret_access_token_123")
    );
}

#[tokio::test]
async fn test_malformed_pdp_body_fails_closed_503() {
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(2, Ordering::SeqCst);

    let app = build_adapter_router(&pdp_url);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "unavailable"
    );
}

#[tokio::test]
async fn test_pdp_503_fails_closed() {
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(3, Ordering::SeqCst);

    let app = build_adapter_router(&pdp_url);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "unavailable"
    );
}

#[tokio::test]
async fn test_unreachable_pdp_fails_closed_503() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let unmapped_url = format!("http://127.0.0.1:{port}");
    let app = build_adapter_router(&unmapped_url);

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "unavailable"
    );
}

#[tokio::test]
async fn test_empty_subject_header_refused() {
    let (pdp_url, _, _) = spawn_mock_pdp().await;
    let app = build_adapter_router(&pdp_url);

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "/claims/claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "deny"
    );
}

#[tokio::test]
async fn test_pdp_timeout_fails_closed_503() {
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(4, Ordering::SeqCst);

    let pdp_client = Arc::new(PdpClient::new(&pdp_url, 1, None).unwrap());
    let state = AppState {
        pdp_client,
        subject_header: HeaderName::from_str("x-forwarded-subject").unwrap(),
        method_header: HeaderName::from_str("x-forwarded-method").unwrap(),
        uri_header: HeaderName::from_str("x-forwarded-uri").unwrap(),
        subject_type: "Principal".to_string(),
        resource_type: "Resource".to_string(),
    };
    let app = create_router(state);

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        resp.headers()
            .get("x-decern-decision")
            .unwrap()
            .to_str()
            .unwrap(),
        "unavailable"
    );
}
