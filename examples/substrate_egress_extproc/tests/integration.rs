// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! End-to-end tests: a real Envoy ext_proc client drives the adapter against a stub AuthZEN PDP,
//! exercising `process` and the fail-closed paths the README promises.

use std::collections::HashMap;
use std::sync::Arc;

use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};
use envoy_types::pb::envoy::service::ext_proc::v3::{
    HttpHeaders, ProcessingRequest, ProcessingResponse,
    external_processor_client::ExternalProcessorClient,
    external_processor_server::ExternalProcessorServer, processing_request, processing_response,
};
use envoy_types::pb::google::protobuf::{Struct, Value, value::Kind};
use substrate_egress_extproc::pdp::PdpClient;
use substrate_egress_extproc::{Config, EgressAuthz, Mode};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

/// The CEL attribute key Substrate's atenet dispatch sets and reads the actor identity under.
const IDK: &str = "filter_state['dev.ate.actor.identity']";

/// Start the ext_proc adapter in `mode`, pointing at `pdp_url`; return its `http://addr`.
async fn start_adapter(mode: Mode, pdp_url: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pdp = Arc::new(PdpClient::new(&pdp_url, 2, None).unwrap());
    let svc = EgressAuthz::new(
        pdp,
        Config {
            identity_attr: IDK.to_string(),
            subject_type: "Actor".to_string(),
            resource_type: "Destination".to_string(),
            mode,
        },
    );
    tokio::spawn(async move {
        Server::builder()
            .add_service(ExternalProcessorServer::new(svc))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

/// Start a stub AuthZEN PDP that answers every evaluation with a fixed decision; return its URL.
async fn start_stub_pdp(decision: bool) -> String {
    use axum::{Json, Router, routing::post};
    let app = Router::new().route(
        "/access/v1/evaluation",
        post(move || async move { Json(serde_json::json!({ "decision": decision })) }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn hv(k: &str, v: &str) -> HeaderValue {
    HeaderValue {
        key: k.to_string(),
        raw_value: v.as_bytes().to_vec(),
        ..Default::default()
    }
}

/// A request_headers ProcessingRequest, optionally carrying the actor identity attribute.
fn request_headers_msg(identity: Option<&str>, method: &str, authority: &str) -> ProcessingRequest {
    let mut attributes = HashMap::new();
    if let Some(id) = identity {
        let mut fields = HashMap::new();
        fields.insert(
            IDK.to_string(),
            Value {
                kind: Some(Kind::StringValue(id.to_string())),
            },
        );
        attributes.insert("ext_proc".to_string(), Struct { fields });
    }
    ProcessingRequest {
        request: Some(processing_request::Request::RequestHeaders(HttpHeaders {
            headers: Some(HeaderMap {
                headers: vec![hv(":method", method), hv(":authority", authority)],
            }),
            ..Default::default()
        })),
        attributes,
        ..Default::default()
    }
}

/// Send one request_headers message and return the single ProcessingResponse.
async fn call(adapter_url: String, req: ProcessingRequest) -> ProcessingResponse {
    let mut client = ExternalProcessorClient::connect(adapter_url).await.unwrap();
    let mut resp = client
        .process(tokio_stream::iter(vec![req]))
        .await
        .unwrap()
        .into_inner();
    resp.message().await.unwrap().unwrap()
}

fn is_allow(r: &ProcessingResponse) -> bool {
    matches!(
        r.response,
        Some(processing_response::Response::RequestHeaders(_))
    )
}

fn deny_code(r: &ProcessingResponse) -> Option<i32> {
    match &r.response {
        Some(processing_response::Response::ImmediateResponse(ir)) => {
            ir.status.as_ref().map(|s| s.code)
        }
        _ => None,
    }
}

/// A request_headers message for the given actor identity (or none), POSTing to a fixed host.
fn req(identity: Option<&str>) -> ProcessingRequest {
    request_headers_msg(identity, "POST", "api.example.com")
}

const ACTOR: &str = "spiffe://cluster.local/ns/a/sa/x";

// --- enforce mode: a decern allow proceeds; a deny or any failure is blocked (403) ---

#[tokio::test]
async fn enforce_allows_when_pdp_permits() {
    let adapter = start_adapter(Mode::Enforce, start_stub_pdp(true).await).await;
    let r = call(adapter, req(Some(ACTOR))).await;
    assert!(is_allow(&r), "expected continue, got {:?}", r.response);
}

#[tokio::test]
async fn enforce_blocks_when_pdp_refuses() {
    let adapter = start_adapter(Mode::Enforce, start_stub_pdp(false).await).await;
    assert_eq!(deny_code(&call(adapter, req(Some(ACTOR))).await), Some(403));
}

#[tokio::test]
async fn enforce_blocks_when_no_identity() {
    // The PDP would allow, but there is no verified actor identity → blocked before the PDP.
    let adapter = start_adapter(Mode::Enforce, start_stub_pdp(true).await).await;
    assert_eq!(deny_code(&call(adapter, req(None)).await), Some(403));
}

#[tokio::test]
async fn enforce_blocks_when_pdp_unreachable() {
    // Nothing listening on the PDP port → unreachable → fail closed.
    let adapter = start_adapter(Mode::Enforce, "http://127.0.0.1:1".to_string()).await;
    assert_eq!(deny_code(&call(adapter, req(Some(ACTOR))).await), Some(403));
}

// --- record mode: never blocks; the request proceeds whatever decern says or does ---

#[tokio::test]
async fn record_never_blocks_on_deny() {
    let adapter = start_adapter(Mode::Record, start_stub_pdp(false).await).await;
    assert!(is_allow(&call(adapter, req(Some(ACTOR))).await));
}

#[tokio::test]
async fn record_never_blocks_when_pdp_unreachable() {
    let adapter = start_adapter(Mode::Record, "http://127.0.0.1:1".to_string()).await;
    assert!(is_allow(&call(adapter, req(Some(ACTOR))).await));
}
