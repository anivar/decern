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
        // Headers at once, then a body that never ends.
        5 => axum::http::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(axum::body::Body::new(Stall))
            .unwrap(),
        // A well-formed decision inside a body far past what one needs.
        6 => (
            StatusCode::OK,
            Json(json!({ "decision": true, "pad": "x".repeat(1 << 20) })),
        )
            .into_response(),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "ledger record failed" })),
        )
            .into_response(),
    }
}

/// A body that sends nothing and never ends: a PDP that answered its headers and then stalled.
struct Stall;

impl http_body::Body for Stall {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Pending
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
    build_adapter_router_full(pdp_url, "x-forwarded-subject", None, 5)
}

fn build_adapter_router_with_subject_header(pdp_url: &str, subject_header_name: &str) -> Router {
    build_adapter_router_full(pdp_url, subject_header_name, None, 5)
}

/// The one way every test builds the adapter; `timeout_secs` is the PDP deadline.
fn build_adapter_router_full(
    pdp_url: &str,
    subject_header_name: &str,
    bearer_token: Option<&str>,
    timeout_secs: u64,
) -> Router {
    let pdp_client =
        Arc::new(PdpClient::new(pdp_url, timeout_secs, bearer_token.map(String::from)).unwrap());
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
        5,
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

    let app = adapter_with_timeout(&pdp_url, 1);

    let resp = app.oneshot(forwarded_check()).await.unwrap();
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

fn adapter_with_timeout(pdp_url: &str, timeout_secs: u64) -> Router {
    build_adapter_router_full(pdp_url, "x-forwarded-subject", None, timeout_secs)
}

fn forwarded_check() -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "claim1")
        .body(axum::body::Body::empty())
        .unwrap()
}

/// The deadline covers the whole exchange: a PDP that answers its headers at once and then
/// stalls on the body holds the adapter until `--pdp-timeout-secs`, not forever.
#[tokio::test]
async fn test_pdp_body_stall_fails_closed_503_at_the_deadline() {
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(5, Ordering::SeqCst);
    let app = adapter_with_timeout(&pdp_url, 1);

    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        app.oneshot(forwarded_check()),
    )
    .await
    .expect("the adapter answers by its deadline, it does not hang on the body")
    .unwrap();
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

/// A body past the bound is refused, not read into memory whole, however well formed the
/// decision inside it.
#[tokio::test]
async fn test_pdp_oversized_body_fails_closed_503() {
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(6, Ordering::SeqCst);
    let app = adapter_with_timeout(&pdp_url, 5);

    let resp = app.oneshot(forwarded_check()).await.unwrap();
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
async fn test_duplicated_subject_header_refused() {
    // Two copies is the signature of a gateway that set its own header without stripping
    // the client's. Either copy could be the client's, so neither can be trusted and the
    // adapter must not pick one — the values differ here to make that concrete.
    let (pdp_url, mode, last_auth) = spawn_mock_pdp().await;
    mode.store(0, Ordering::SeqCst); // PDP would ALLOW, so a pass-through would return 200

    let app = build_adapter_router_full(
        &pdp_url,
        "x-forwarded-subject",
        Some("secret_access_token_123"),
        5,
    );
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-subject", "attacker")
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

    // Refused locally, before evaluation: nothing reached the PDP, so nothing is recorded.
    // The bearer token is what makes this observable — the mock only records a call that
    // carried an authorization header.
    assert!(
        last_auth.lock().await.is_none(),
        "a duplicated subject header must be refused before the PDP is consulted"
    );
}

#[tokio::test]
async fn test_duplicated_subject_header_refused_even_when_copies_agree() {
    // Identical copies are refused too. The adapter cannot tell which copy the gateway
    // set, so "they agree" is not evidence that the client did not supply one.
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(0, Ordering::SeqCst);

    let app = build_adapter_router(&pdp_url);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "/claims/claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_duplicated_subject_header_honours_custom_header_name() {
    // The check follows --subject-header, not the default name.
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(0, Ordering::SeqCst);

    let app = build_adapter_router_with_subject_header(&pdp_url, "X-Forwarded-User");
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("X-Forwarded-User", "corp")
        .header("X-Forwarded-User", "attacker")
        .header("X-Forwarded-Method", "Read")
        .header("X-Forwarded-Uri", "/claims/claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_single_subject_header_still_allowed() {
    // Guards the guard: the duplicate check must not refuse the ordinary one-copy request.
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
}

#[tokio::test]
async fn test_duplicated_method_header_refused() {
    // The sharper of the two the subject check missed. If a client copy of the method
    // header arrives ahead of the gateway's, `get()` returns `Read` while the real
    // request is a `Write`: the PDP authorizes the Read, the adapter answers 200, and
    // the gateway forwards the Write. That is the fail-open the comment above these
    // reads already warns about, reached by a different route.
    let (pdp_url, mode, last_auth) = spawn_mock_pdp().await;
    mode.store(0, Ordering::SeqCst); // PDP would ALLOW, so a pass-through would return 200

    let app = build_adapter_router_full(
        &pdp_url,
        "x-forwarded-subject",
        Some("secret_access_token_123"),
        5,
    );
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
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
    assert!(
        last_auth.lock().await.is_none(),
        "a duplicated method header must be refused before the PDP is consulted"
    );
}

#[tokio::test]
async fn test_duplicated_uri_header_refused() {
    // Same shape on the resource: the decision would be evaluated against a path the
    // client supplied while the request goes somewhere else.
    let (pdp_url, mode, last_auth) = spawn_mock_pdp().await;
    mode.store(0, Ordering::SeqCst);

    let app = build_adapter_router_full(
        &pdp_url,
        "x-forwarded-subject",
        Some("secret_access_token_123"),
        5,
    );
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "/claims/claim1")
        .header("x-forwarded-uri", "/admin")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        last_auth.lock().await.is_none(),
        "a duplicated uri header must be refused before the PDP is consulted"
    );
}

#[tokio::test]
async fn test_duplicated_method_header_refused_even_when_copies_agree() {
    // Same reasoning as the subject: the adapter cannot tell which copy the gateway
    // set, so agreement between them is not evidence the client did not supply one.
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(0, Ordering::SeqCst);

    let app = build_adapter_router(&pdp_url);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("x-forwarded-subject", "corp")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-method", "Read")
        .header("x-forwarded-uri", "/claims/claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_duplicated_method_header_honours_custom_subject_header_name() {
    // The three headers are read through one helper, so a custom --subject-header must
    // not change how the other two are checked.
    let (pdp_url, mode, _) = spawn_mock_pdp().await;
    mode.store(0, Ordering::SeqCst);

    let app = build_adapter_router_with_subject_header(&pdp_url, "X-Forwarded-User");
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/check")
        .header("X-Forwarded-User", "corp")
        .header("X-Forwarded-Method", "Read")
        .header("X-Forwarded-Method", "Write")
        .header("X-Forwarded-Uri", "/claims/claim1")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
