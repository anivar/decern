// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! decern ext_authz adapter — generic HTTP external authorization shim for decern-serve.
//!
//! Translates HTTP gateway requests (e.g. NGINX auth_request, Traefik forwardAuth, Envoy ext_authz)
//! carrying forwarded metadata into AuthZEN JSON evaluations against decern-serve.
//!
//! Fail-closed contract:
//!   - PDP decision == true   => 200 OK
//!   - PDP decision == false  => 403 Forbidden
//!   - Missing subject header => 403 Forbidden (refuse unauthenticated callers by default)
//!   - PDP error / timeout / unreachable / malformed response => 503 Service Unavailable

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use serde_json::json;
use tokio::time::timeout;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "ext-authz-adapter",
    version,
    about = "Generic HTTP external authorization shim for decern-serve"
)]
pub struct Args {
    /// Address to bind and listen on.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:9090")]
    pub listen_addr: SocketAddr,

    /// Target decern-serve PDP URL.
    #[arg(long, value_name = "URL", default_value = "http://127.0.0.1:8080")]
    pub pdp_url: String,

    /// Header carrying the verified subject identity injected by the gateway.
    #[arg(long, value_name = "HEADER", default_value = "x-forwarded-subject")]
    pub subject_header: String,

    /// Header carrying the original request HTTP method.
    #[arg(long, value_name = "HEADER", default_value = "x-forwarded-method")]
    pub method_header: String,

    /// Header carrying the original request URI path.
    #[arg(long, value_name = "HEADER", default_value = "x-forwarded-uri")]
    pub uri_header: String,

    /// Subject entity type passed to AuthZEN evaluation.
    #[arg(long, value_name = "TYPE", default_value = "Principal")]
    pub subject_type: String,

    /// Resource entity type passed to AuthZEN evaluation.
    #[arg(long, value_name = "TYPE", default_value = "Resource")]
    pub resource_type: String,

    /// Timeout for upstream PDP evaluation requests in seconds.
    #[arg(long, value_name = "SECS", default_value = "5")]
    pub pdp_timeout_secs: u64,

    /// Optional Bearer token to present to decern-serve when bearer validation is enabled.
    #[arg(long, value_name = "TOKEN")]
    pub pdp_bearer_token: Option<String>,
}

/// Errors encountered when evaluating a decision against upstream decern-serve.
#[derive(Debug, thiserror::Error)]
pub enum PdpError {
    #[error("network error: {0}")]
    Network(String),

    #[error("PDP evaluation request timed out after {0:?}")]
    Timeout(Duration),

    #[error("PDP returned non-success HTTP status {0}")]
    HttpStatus(StatusCode),

    #[error("PDP returned malformed JSON body: {0}")]
    MalformedBody(String),
}

/// Upstream decern-serve client wrapping a pure-Rust HTTP connection pool.
pub struct PdpClient {
    eval_uri: Uri,
    health_uri: Uri,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    timeout_duration: Duration,
    bearer_token: Option<String>,
}

impl PdpClient {
    pub fn new(
        pdp_url: &str,
        timeout_secs: u64,
        bearer_token: Option<String>,
    ) -> Result<Self, String> {
        let trimmed = pdp_url.trim_end_matches('/');
        let eval_str = format!("{trimmed}/access/v1/evaluation");
        let health_str = format!("{trimmed}/healthz");

        let eval_uri = Uri::from_str(&eval_str)
            .map_err(|e| format!("invalid PDP evaluation URL '{eval_str}': {e}"))?;
        let health_uri = Uri::from_str(&health_str)
            .map_err(|e| format!("invalid PDP health URL '{health_str}': {e}"))?;

        let client = Client::builder(TokioExecutor::new()).build_http();

        Ok(Self {
            eval_uri,
            health_uri,
            client,
            timeout_duration: Duration::from_secs(timeout_secs),
            bearer_token,
        })
    }

    /// Best-effort ping to the PDP `/healthz` endpoint on boot.
    pub async fn healthcheck(&self) -> Result<(), PdpError> {
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(&self.health_uri)
            .body(Full::new(Bytes::new()))
            .map_err(|e| PdpError::Network(e.to_string()))?;

        let resp = timeout(Duration::from_secs(2), self.client.request(req))
            .await
            .map_err(|_| PdpError::Timeout(Duration::from_secs(2)))?
            .map_err(|e| PdpError::Network(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(PdpError::HttpStatus(resp.status()))
        }
    }

    /// Post an AuthZEN JSON request to decern-serve and parse the decision.
    pub async fn evaluate(
        &self,
        subject_type: &str,
        subject_id: &str,
        action_name: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<bool, PdpError> {
        let payload = json!({
            "subject": {
                "type": subject_type,
                "id": subject_id
            },
            "action": {
                "name": action_name
            },
            "resource": {
                "type": resource_type,
                "id": resource_id
            }
        });

        let body_bytes = serde_json::to_vec(&payload)
            .map_err(|e| PdpError::MalformedBody(format!("serializing AuthZEN request: {e}")))?;

        let mut req_builder = axum::http::Request::builder()
            .method("POST")
            .uri(&self.eval_uri)
            .header(axum::http::header::CONTENT_TYPE, "application/json");

        if let Some(token) = &self.bearer_token {
            let auth_val = format!("Bearer {token}");
            req_builder = req_builder.header(axum::http::header::AUTHORIZATION, auth_val);
        }

        let req = req_builder
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|e| PdpError::Network(e.to_string()))?;

        let fut = self.client.request(req);
        let resp = timeout(self.timeout_duration, fut)
            .await
            .map_err(|_| PdpError::Timeout(self.timeout_duration))?
            .map_err(|e| PdpError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(PdpError::HttpStatus(status));
        }

        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| PdpError::Network(format!("reading response body: {e}")))?
            .to_bytes();

        let parsed: AuthZenEvalResponse = serde_json::from_slice(&body).map_err(|e| {
            PdpError::MalformedBody(format!(
                "failed to parse AuthZEN evaluation response JSON: {e}"
            ))
        })?;

        Ok(parsed.decision)
    }
}

#[derive(Deserialize)]
struct AuthZenEvalResponse {
    decision: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub pdp_client: Arc<PdpClient>,
    pub subject_header: HeaderName,
    pub method_header: HeaderName,
    pub uri_header: HeaderName,
    pub subject_type: String,
    pub resource_type: String,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/check", post(check_handler).get(check_handler))
        .with_state(state)
}

pub async fn run_main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let subject_header = HeaderName::from_str(&args.subject_header).map_err(|e| {
        format!(
            "invalid --subject-header name '{}': {e}",
            args.subject_header
        )
    })?;
    let method_header = HeaderName::from_str(&args.method_header)
        .map_err(|e| format!("invalid --method-header name '{}': {e}", args.method_header))?;
    let uri_header = HeaderName::from_str(&args.uri_header)
        .map_err(|e| format!("invalid --uri-header name '{}': {e}", args.uri_header))?;

    let pdp_client = Arc::new(PdpClient::new(
        &args.pdp_url,
        args.pdp_timeout_secs,
        args.pdp_bearer_token,
    )?);

    // Best-effort PDP health check on boot (3.5)
    match pdp_client.healthcheck().await {
        Ok(()) => eprintln!(
            "ext-authz-adapter: successfully connected to PDP at {}",
            args.pdp_url
        ),
        Err(e) => eprintln!(
            "ext-authz-adapter: WARNING — PDP at {} is not reachable on boot ({e}). Will retry on requests.",
            args.pdp_url
        ),
    }

    let state = AppState {
        pdp_client,
        subject_header,
        method_header,
        uri_header,
        subject_type: args.subject_type,
        resource_type: args.resource_type,
    };

    let app = create_router(state);

    eprintln!("ext-authz-adapter: listening on {}", args.listen_addr);
    let listener = tokio::net::TcpListener::bind(args.listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Axum handler for `POST /check` (and `GET /check`).
pub async fn check_handler(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let start_time = Instant::now();

    // 1. Extract subject identity header
    let subject_id = match headers
        .get(&st.subject_header)
        .and_then(|v| v.to_str().ok())
    {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => {
            eprintln!(
                "check: status=403 decision=deny error=\"missing subject header '{}'\"",
                st.subject_header
            );
            let mut res_headers = HeaderMap::new();
            res_headers.insert("x-decern-decision", HeaderValue::from_static("deny"));
            return (StatusCode::FORBIDDEN, res_headers, "Missing subject header").into_response();
        }
    };

    // 2. Extract forwarded action (method) and resource (URI)
    let action_name = headers
        .get(&st.method_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("Read");

    let resource_id = headers
        .get(&st.uri_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("/");

    // 3. Evaluate decision against PDP
    match st
        .pdp_client
        .evaluate(
            &st.subject_type,
            subject_id,
            action_name,
            &st.resource_type,
            resource_id,
        )
        .await
    {
        Ok(true) => {
            let elapsed_ms = start_time.elapsed().as_millis();
            eprintln!(
                "check: subject={subject_id} action={action_name} resource={resource_id} decision=allow upstream_ms={elapsed_ms}"
            );
            let mut res_headers = HeaderMap::new();
            res_headers.insert("x-decern-decision", HeaderValue::from_static("allow"));
            (StatusCode::OK, res_headers, "Allowed").into_response()
        }
        Ok(false) => {
            let elapsed_ms = start_time.elapsed().as_millis();
            eprintln!(
                "check: subject={subject_id} action={action_name} resource={resource_id} decision=deny upstream_ms={elapsed_ms}"
            );
            let mut res_headers = HeaderMap::new();
            res_headers.insert("x-decern-decision", HeaderValue::from_static("deny"));
            (StatusCode::FORBIDDEN, res_headers, "Denied").into_response()
        }
        Err(err) => {
            let elapsed_ms = start_time.elapsed().as_millis();
            eprintln!(
                "check_error: subject={subject_id} action={action_name} resource={resource_id} error=\"{err}\" upstream_ms={elapsed_ms}"
            );
            let mut res_headers = HeaderMap::new();
            res_headers.insert("x-decern-decision", HeaderValue::from_static("unavailable"));
            (StatusCode::SERVICE_UNAVAILABLE, res_headers, "PDP Error").into_response()
        }
    }
}
