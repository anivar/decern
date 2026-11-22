// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! AuthZEN 1.0 PDP client.
//!
//! Posts a single AuthZEN evaluation to `POST <pdp>/access/v1/evaluation` and reads back
//! `{"decision": bool}`. The endpoint and request shape are AuthZEN-standard, so the same client
//! talks to `decern-serve` or any AuthZEN 1.0 PDP. Pure-Rust HTTP, no TLS: the PDP is
//! expected on loopback or a private in-cluster address, exactly as decern's `ext_authz_adapter`.
//!
//! Every non-decision outcome is an error the caller turns into a deny: the egress is fail-closed.

use std::str::FromStr;
use std::time::Duration;

use bytes::Bytes;
use http::{Uri, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use serde_json::json;
use tokio::time::timeout;

/// The most a PDP response body may carry. A decision is a few hundred bytes; a PDP that streams
/// more than this is refused at the bound rather than read into memory whole.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PdpError {
    #[error("network error: {0}")]
    Network(String),
    #[error("PDP evaluation request timed out after {0:?}")]
    Timeout(Duration),
    #[error("PDP returned non-success HTTP status {0}")]
    HttpStatus(u16),
    #[error("PDP returned malformed JSON body: {0}")]
    MalformedBody(String),
    #[error("PDP response body over {0} bytes")]
    ResponseTooLarge(usize),
}

#[derive(Deserialize)]
struct AuthZenEvalResponse {
    decision: bool,
}

/// Upstream AuthZEN PDP client over a pure-Rust HTTP connection pool.
pub struct PdpClient {
    eval_uri: Uri,
    health_uri: Uri,
    client: Client<HttpConnector, Full<Bytes>>,
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
        let req = http::Request::builder()
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
            Err(PdpError::HttpStatus(resp.status().as_u16()))
        }
    }

    /// Post an AuthZEN evaluation and parse the decision. Any outcome that is not a parsed
    /// decision is an `Err`, which the egress turns into a deny.
    pub async fn evaluate(
        &self,
        subject_type: &str,
        subject_id: &str,
        action_name: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<bool, PdpError> {
        let payload = json!({
            "subject": { "type": subject_type, "id": subject_id },
            "action": { "name": action_name },
            "resource": { "type": resource_type, "id": resource_id }
        });
        let body_bytes = serde_json::to_vec(&payload)
            .map_err(|e| PdpError::MalformedBody(format!("serializing AuthZEN request: {e}")))?;

        let mut req_builder = http::Request::builder()
            .method("POST")
            .uri(&self.eval_uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = &self.bearer_token {
            req_builder = req_builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let req = req_builder
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|e| PdpError::Network(e.to_string()))?;

        // One deadline over the whole exchange; the body is read through a bound.
        let exchange = async {
            let resp = self
                .client
                .request(req)
                .await
                .map_err(|e| PdpError::Network(e.to_string()))?;
            let status = resp.status();
            if !status.is_success() {
                return Err(PdpError::HttpStatus(status.as_u16()));
            }
            Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
                .collect()
                .await
                .map(|collected| collected.to_bytes())
                .map_err(|e| {
                    if e.is::<http_body_util::LengthLimitError>() {
                        PdpError::ResponseTooLarge(MAX_RESPONSE_BYTES)
                    } else {
                        PdpError::Network(format!("reading response body: {e}"))
                    }
                })
        };
        let body = timeout(self.timeout_duration, exchange)
            .await
            .map_err(|_| PdpError::Timeout(self.timeout_duration))??;

        let parsed: AuthZenEvalResponse = serde_json::from_slice(&body).map_err(|e| {
            PdpError::MalformedBody(format!(
                "failed to parse AuthZEN evaluation response JSON: {e}"
            ))
        })?;
        Ok(parsed.decision)
    }
}
