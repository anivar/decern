// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Agent Substrate egress → AuthZEN adapter.
//!
//! An Envoy `ext_proc` ExternalProcessor that Agent Substrate's egress gateway calls on every
//! outbound actor request (the `--experimental-additional-egress-extproc-service` augment path).
//! For each request it maps the verified actor identity and the destination to an AuthZEN 1.0
//! evaluation against a PDP (`decern-serve`, or any AuthZEN 1.0 PDP), and allows or denies.
//!
//! Fail-closed: anything other than an explicit PDP allow is a deny (HTTP 403). Substrate's own
//! `failure_mode_allow: false` double-guards an unreachable adapter.
//!
//! This is decide-and-record only. The forward proxy, the actor mTLS CONNECT, credential injection
//! and the Network Egress Contract stay in Substrate's `atenet-egress`; this adapter never proxies.

pub mod pdp;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming, transport::Server};

use envoy_types::pb::envoy::config::core::v3::HeaderValue;
use envoy_types::pb::envoy::service::ext_proc::v3::{
    HeadersResponse, HttpHeaders, ImmediateResponse, ProcessingRequest, ProcessingResponse,
    external_processor_server::{ExternalProcessor, ExternalProcessorServer},
    processing_request, processing_response,
};
use envoy_types::pb::envoy::r#type::v3::HttpStatus;
use envoy_types::pb::google::protobuf::{Struct, value::Kind};

use pdp::PdpClient;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "substrate-egress-extproc",
    version,
    about = "Envoy ext_proc adapter: authorize Agent Substrate actor egress against an AuthZEN 1.0 PDP"
)]
pub struct Args {
    /// Address to bind the ext_proc gRPC server on (what Substrate's
    /// `--experimental-additional-egress-extproc-service` points at). Defaults to loopback;
    /// an in-cluster deployment binds `0.0.0.0` and must pair it with `--tls-cert`/`--tls-key`.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:50051")]
    pub listen_addr: SocketAddr,

    /// AuthZEN PDP base URL. `/access/v1/evaluation` is appended. e.g. decern-serve.
    #[arg(long, value_name = "URL", default_value = "http://127.0.0.1:8080")]
    pub pdp_url: String,

    /// ext_proc request-attribute key carrying the verified actor identity. This is the CEL
    /// expression Substrate's augment requests and reads back in its own atenet dispatch; the value
    /// is the actor's SPIFFE id as a plain string.
    #[arg(
        long,
        value_name = "KEY",
        default_value = "filter_state['dev.ate.actor.identity']"
    )]
    pub identity_attr: String,

    /// AuthZEN subject entity type for the actor.
    #[arg(long, value_name = "TYPE", default_value = "Actor")]
    pub subject_type: String,

    /// AuthZEN resource entity type for the egress destination.
    #[arg(long, value_name = "TYPE", default_value = "Destination")]
    pub resource_type: String,

    /// How a decision is applied. `enforce` (default): deny egress with a 403 on a decern deny or
    /// any failure — fail-closed, decern in the request path. `record`: never block; record every
    /// egress decision in decern for the subject to contest, and continue regardless — fail-open,
    /// decern off the critical path. Choose `record` when Substrate's own EgressPolicy already
    /// enforces and decern's value is the contestable log; pair it with `observability_mode` on the
    /// Substrate filter so Envoy does not wait on the callout.
    #[arg(long, value_enum, default_value_t = Mode::Enforce)]
    pub mode: Mode,

    /// Deadline, in seconds, for the whole PDP exchange. Keep it below Substrate's ext_proc
    /// `message_timeout` (2s by default) so a slow decision answers rather than being cut off and
    /// denied by `failure_mode_allow: false`.
    #[arg(long, value_name = "SECS", default_value = "1")]
    pub pdp_timeout_secs: u64,

    /// Optional bearer token presented to the PDP. Prefer the environment variable.
    #[arg(
        long,
        value_name = "TOKEN",
        env = "PDP_BEARER_TOKEN",
        hide_env_values = true
    )]
    pub pdp_bearer_token: Option<String>,

    /// Server TLS certificate chain (PEM). Set with --tls-key to serve mTLS, as the in-cluster
    /// augment requires. Without it the server is plaintext h2c, for local development only.
    #[arg(long, value_name = "FILE", requires = "tls_key")]
    pub tls_cert: Option<String>,

    /// Server TLS private key (PEM).
    #[arg(long, value_name = "FILE", requires = "tls_cert")]
    pub tls_key: Option<String>,

    /// CA bundle (PEM) to verify Substrate's client certificate (mutual TLS).
    #[arg(long, value_name = "FILE")]
    pub tls_client_ca: Option<String>,
}

/// How a decern decision is applied to the egress request.
#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Mode {
    /// Deny egress (403) on a decern deny or any failure. Fail-closed; decern in the request path.
    Enforce,
    /// Never block; record the decision in decern and continue. Fail-open; decern off the path.
    Record,
}

/// Immutable mapping configuration shared by every request.
#[derive(Clone)]
pub struct Config {
    pub identity_attr: String,
    pub subject_type: String,
    pub resource_type: String,
    pub mode: Mode,
}

/// The gRPC service.
pub struct EgressAuthz {
    pdp: Arc<PdpClient>,
    cfg: Config,
}

impl EgressAuthz {
    pub fn new(pdp: Arc<PdpClient>, cfg: Config) -> Self {
        Self { pdp, cfg }
    }
}

/// The decern decision for one request, or the inability to obtain one.
enum Outcome {
    Allow,
    Deny,
    /// No actor identity, no method/destination, or the PDP was unreachable — no usable decision.
    Cannot,
}

/// Whether the request is permitted. In `record` mode the request always proceeds; in `enforce`
/// mode only a decern allow proceeds, so a deny or any `Cannot` is blocked (fail-closed).
fn permits(mode: Mode, outcome: &Outcome) -> bool {
    matches!(mode, Mode::Record) || matches!(outcome, Outcome::Allow)
}

fn applied(mode: Mode, outcome: &Outcome) -> &'static str {
    if permits(mode, outcome) {
        "permit"
    } else {
        "block"
    }
}

fn decern_label(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Allow => "allow",
        Outcome::Deny => "deny",
        Outcome::Cannot => "unavailable",
    }
}

/// The value of an ext_proc header. Carried in `raw_value`; the deprecated `value` is a fallback.
fn header_value(hv: &HeaderValue) -> String {
    if hv.raw_value.is_empty() {
        hv.value.clone()
    } else {
        String::from_utf8_lossy(&hv.raw_value).into_owned()
    }
}

/// Pull `:method` and the egress destination out of the ext_proc header map. The destination is
/// `:authority` (HTTP/2, authoritative) and falls back to `host` (HTTP/1.1) only when it is absent.
fn read_pseudo_headers(h: &HttpHeaders) -> (Option<String>, Option<String>) {
    let mut method = None;
    let mut authority = None;
    let mut host = None;
    if let Some(map) = &h.headers {
        for hv in &map.headers {
            match hv.key.to_ascii_lowercase().as_str() {
                ":method" if method.is_none() => method = Some(header_value(hv)),
                ":authority" if authority.is_none() => authority = Some(header_value(hv)),
                "host" if host.is_none() => host = Some(header_value(hv)),
                _ => {}
            }
        }
    }
    (method, authority.or(host))
}

/// Read the actor identity from the ext_proc request attributes, exactly as Agent Substrate's own
/// atenet dispatch does: look the CEL attribute key up in each delivered attribute struct and take
/// its string value. The identity is the actor's SPIFFE id — a plain string the egress set from the
/// verified actor certificate. A request that carries no such value is denied.
fn extract_identity(attrs: &HashMap<String, Struct>, key: &str) -> Option<String> {
    for s in attrs.values() {
        if let Some(v) = s.fields.get(key)
            && let Some(Kind::StringValue(sv)) = &v.kind
            && !sv.is_empty()
        {
            return Some(sv.clone());
        }
    }
    None
}

/// Build the ext_proc response: continue when the mode permits the outcome, else a local 403.
fn response_for(outcome: &Outcome, mode: Mode) -> ProcessingResponse {
    let response = if permits(mode, outcome) {
        processing_response::Response::RequestHeaders(HeadersResponse::default())
    } else {
        processing_response::Response::ImmediateResponse(ImmediateResponse {
            status: Some(HttpStatus { code: 403 }),
            body: b"egress denied".to_vec(),
            details: "decern egress policy".to_string(),
            ..Default::default()
        })
    };
    ProcessingResponse {
        response: Some(response),
        ..Default::default()
    }
}

/// Evaluate one request_headers message against decern and return the decern outcome. The response
/// is shaped from it by `response_for` under the configured mode. Each request logs one line with
/// the decern result and the action the mode applied (`permit`/`block`).
async fn decide(
    pdp: &PdpClient,
    cfg: &Config,
    h: &HttpHeaders,
    attrs: &HashMap<String, Struct>,
) -> Outcome {
    let started = Instant::now();
    let Some(subject_id) = extract_identity(attrs, &cfg.identity_attr) else {
        let o = Outcome::Cannot;
        eprintln!(
            "egress: mode={:?} decern=unavailable reason=\"no actor identity\" applied={}",
            cfg.mode,
            applied(cfg.mode, &o)
        );
        return o;
    };
    let (method, authority) = read_pseudo_headers(h);
    let (Some(action), Some(resource)) = (method, authority) else {
        let o = Outcome::Cannot;
        eprintln!(
            "egress: mode={:?} subject={subject_id:?} decern=unavailable reason=\"missing method or destination\" applied={}",
            cfg.mode,
            applied(cfg.mode, &o)
        );
        return o;
    };

    let result = pdp
        .evaluate(
            &cfg.subject_type,
            &subject_id,
            &action,
            &cfg.resource_type,
            &resource,
        )
        .await;
    let ms = started.elapsed().as_millis();
    let (outcome, reason) = match result {
        Ok(true) => (Outcome::Allow, String::new()),
        Ok(false) => (Outcome::Deny, String::new()),
        Err(err) => (Outcome::Cannot, format!(" reason={:?}", err.to_string())),
    };
    eprintln!(
        "egress: mode={:?} subject={subject_id:?} action={action:?} resource={resource:?} decern={}{reason} applied={} upstream_ms={ms}",
        cfg.mode,
        decern_label(&outcome),
        applied(cfg.mode, &outcome)
    );
    outcome
}

#[tonic::async_trait]
impl ExternalProcessor for EgressAuthz {
    type ProcessStream = ReceiverStream<Result<ProcessingResponse, Status>>;

    async fn process(
        &self,
        request: Request<Streaming<ProcessingRequest>>,
    ) -> Result<Response<Self::ProcessStream>, Status> {
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(4);
        let pdp = Arc::clone(&self.pdp);
        let cfg = self.cfg.clone();

        tokio::spawn(async move {
            while let Ok(Some(msg)) = inbound.message().await {
                // request_header_mode: SEND is the only phase configured; react to request_headers
                // and acknowledge any other phase with a continue rather than stalling the stream.
                let out = match &msg.request {
                    Some(processing_request::Request::RequestHeaders(h)) => {
                        response_for(&decide(&pdp, &cfg, h, &msg.attributes).await, cfg.mode)
                    }
                    _ => response_for(&Outcome::Allow, cfg.mode),
                };
                if tx.send(Ok(out)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

pub async fn run_main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let pdp = Arc::new(PdpClient::new(
        &args.pdp_url,
        args.pdp_timeout_secs,
        args.pdp_bearer_token,
    )?);
    match pdp.healthcheck().await {
        Ok(()) => eprintln!(
            "substrate-egress-extproc: PDP reachable at {}",
            args.pdp_url
        ),
        Err(e) => eprintln!(
            "substrate-egress-extproc: WARNING — PDP at {} not reachable on boot ({e})",
            args.pdp_url
        ),
    }
    eprintln!(
        "substrate-egress-extproc: mode={:?} ({})",
        args.mode,
        match args.mode {
            Mode::Enforce => "fail-closed; a decern deny or failure blocks egress",
            Mode::Record => "fail-open; records decisions in decern, never blocks",
        }
    );

    let svc = EgressAuthz {
        pdp,
        cfg: Config {
            identity_attr: args.identity_attr,
            subject_type: args.subject_type,
            resource_type: args.resource_type,
            mode: args.mode,
        },
    };

    let mut server = Server::builder();
    if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
        use tonic::transport::{Identity, ServerTlsConfig};
        let identity = Identity::from_pem(std::fs::read(cert)?, std::fs::read(key)?);
        let mut tls = ServerTlsConfig::new().identity(identity);
        if let Some(ca) = &args.tls_client_ca {
            use tonic::transport::Certificate;
            tls = tls.client_ca_root(Certificate::from_pem(std::fs::read(ca)?));
        }
        server = server.tls_config(tls)?;
        eprintln!(
            "substrate-egress-extproc: serving ext_proc over TLS on {}",
            args.listen_addr
        );
    } else {
        eprintln!(
            "substrate-egress-extproc: serving ext_proc PLAINTEXT on {} (dev only; the in-cluster augment requires TLS — pass --tls-cert/--tls-key)",
            args.listen_addr
        );
    }

    server
        .add_service(ExternalProcessorServer::new(svc))
        .serve(args.listen_addr)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_types::pb::envoy::config::core::v3::{HeaderMap as EnvoyHeaderMap, HeaderValue};
    use envoy_types::pb::google::protobuf::Value;

    fn sval(s: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(s.to_string())),
        }
    }
    fn strukt(pairs: &[(&str, Value)]) -> Struct {
        Struct {
            fields: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        }
    }

    fn hv(key: &str, val: &str) -> HeaderValue {
        HeaderValue {
            key: key.to_string(),
            raw_value: val.as_bytes().to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn reads_method_and_authority() {
        let h = HttpHeaders {
            headers: Some(EnvoyHeaderMap {
                headers: vec![
                    hv(":method", "POST"),
                    hv(":authority", "api.example.com:443"),
                ],
            }),
            ..Default::default()
        };
        let (m, a) = read_pseudo_headers(&h);
        assert_eq!(m.as_deref(), Some("POST"));
        assert_eq!(a.as_deref(), Some("api.example.com:443"));
    }

    #[test]
    fn host_is_authority_fallback() {
        let h = HttpHeaders {
            headers: Some(EnvoyHeaderMap {
                headers: vec![hv("host", "svc.internal")],
            }),
            ..Default::default()
        };
        let (_, a) = read_pseudo_headers(&h);
        assert_eq!(a.as_deref(), Some("svc.internal"));
    }

    // The CEL attribute key Substrate's atenet dispatch sets and reads back.
    const IDK: &str = "filter_state['dev.ate.actor.identity']";

    #[test]
    fn identity_read_as_substrate_delivers_it() {
        // A plain SPIFFE-id string under the CEL key, in one of the delivered attribute structs.
        let mut attrs = HashMap::new();
        attrs.insert(
            "envoy.filters.http.ext_proc".to_string(),
            strukt(&[(IDK, sval("spiffe://cluster.local/ns/team-a/sa/agent-7"))]),
        );
        assert_eq!(
            extract_identity(&attrs, IDK).as_deref(),
            Some("spiffe://cluster.local/ns/team-a/sa/agent-7")
        );
    }

    #[test]
    fn identity_absent_or_wrong_key_is_none() {
        assert!(extract_identity(&HashMap::new(), IDK).is_none());
        let mut attrs = HashMap::new();
        attrs.insert("f".to_string(), strukt(&[("some.other.attr", sval("x"))]));
        assert!(extract_identity(&attrs, IDK).is_none());
    }

    #[test]
    fn identity_empty_string_is_none() {
        let mut attrs = HashMap::new();
        attrs.insert("f".to_string(), strukt(&[(IDK, sval(""))]));
        assert!(extract_identity(&attrs, IDK).is_none());
    }

    fn is_403(resp: &ProcessingResponse) -> bool {
        matches!(
            &resp.response,
            Some(processing_response::Response::ImmediateResponse(ir))
                if ir.status.as_ref().map(|s| s.code) == Some(403)
        )
    }
    fn is_continue(resp: &ProcessingResponse) -> bool {
        matches!(
            resp.response,
            Some(processing_response::Response::RequestHeaders(_))
        )
    }

    #[test]
    fn enforce_permits_allow_and_blocks_the_rest() {
        assert!(is_continue(&response_for(&Outcome::Allow, Mode::Enforce)));
        assert!(is_403(&response_for(&Outcome::Deny, Mode::Enforce)));
        assert!(is_403(&response_for(&Outcome::Cannot, Mode::Enforce)));
    }

    #[test]
    fn record_permits_every_outcome() {
        // record never blocks — it records the decision and lets the request through.
        assert!(is_continue(&response_for(&Outcome::Allow, Mode::Record)));
        assert!(is_continue(&response_for(&Outcome::Deny, Mode::Record)));
        assert!(is_continue(&response_for(&Outcome::Cannot, Mode::Record)));
    }

    #[test]
    fn permits_matches_the_mode_table() {
        assert!(permits(Mode::Enforce, &Outcome::Allow));
        assert!(!permits(Mode::Enforce, &Outcome::Deny));
        assert!(!permits(Mode::Enforce, &Outcome::Cannot));
        assert!(permits(Mode::Record, &Outcome::Allow));
        assert!(permits(Mode::Record, &Outcome::Deny));
        assert!(permits(Mode::Record, &Outcome::Cannot));
    }
}
