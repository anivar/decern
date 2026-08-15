// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The routing layer: one router, a guarded half for everything that decides
//! or mutates and an open-by-intent half for what third parties must reach.

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::audit::{descendants, pubkey, subject_audit, subject_side_disclosure, tree_head};
use crate::decide::decide;
use crate::mission::{mission_approve, mission_get, mission_terminate};
use crate::{AppState, caller};

pub(crate) fn app(state: AppState, caller: Arc<caller::Caller>) -> Router {
    // Everything that decides, or that changes what a later decision will be. Split into
    // its own router so the guard covers it by construction: a route added here is
    // guarded, and a route that should be guarded cannot become open by someone
    // forgetting to name it somewhere else.
    //
    // `approver` on the mission mutations is a request-body field. Bearer and
    // `--trust-proxy` authenticate a PEP, which may name any principal. A signed-request
    // agent is bound to itself unless named in `--pep`: it cannot approve or terminate
    // as someone else.
    //
    // A route added to either half must also be added to the matching list in the router
    // tests, which drive every path through this function and assert which side answered.
    let guarded = Router::new()
        // AuthZEN Authorization API 1.0 Access Evaluation endpoint; /decide is a friendly alias.
        .route("/access/v1/evaluation", post(decide))
        .route("/decide", post(decide))
        // Mission lifecycle. The read is guarded with the mutations: mission state is what a
        // PEP consults before honoring a grant, and the reference is a digest of fields an
        // outsider may be able to guess — it is not a subject-side surface.
        .route("/mission/v1/approve", post(mission_approve))
        .route("/mission/v1/{s256}", get(mission_get))
        .route("/mission/v1/{s256}/terminate", post(mission_terminate))
        // Read-only and unrecorded, but it reads the authority graph.
        .route(
            "/directory/v1/principals/{id}/descendants",
            get(descendants),
        )
        .route_layer(axum::middleware::from_fn_with_state(caller, caller::guard));

    // Open by intent, each for its own reason. `/healthz` and `/pubkey` are operational;
    // the tree head and the disclosure are what an operator publishes on purpose, so a
    // third party can check this deployment without holding a credential for it; and
    // `/audit/v1/subject` answers the party a decision was about — who will not hold a
    // credential for the deployment that decided about them, which is the point of the
    // subject-side surface. The pseudonymous handle is that route's whole access control.
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/pubkey", get(pubkey))
        .route("/anchor/v1/tree-head", get(tree_head))
        .route(
            "/.well-known/decern-subject-side-disclosure",
            get(subject_side_disclosure),
        )
        .route("/audit/v1/subject", get(subject_audit))
        .merge(guarded)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bearer;
    use axum::Json;
    use axum::extract::{Path as UrlPath, State};
    use axum::http::StatusCode;
    use decern_kernel::{Kernel, Model};
    use decern_ledger::{ShardedLedger, UNATTRIBUTED_SHARD};
    use ed25519_dalek::SigningKey;
    use serde_json::{Value, json};

    use crate::audit::MAX_PROJECTED_DECISIONS;
    use crate::decide::DecideReq;
    use crate::mission::MissionApproveReq;
    use crate::testutil::{
        approve_req, body_json, corp_expiry, mission_base, mission_state_at, now_nanos, open,
        test_missions,
    };
    use crate::{LedgerBackend, caller_disclosure, now_secs};

    #[tokio::test]
    async fn sharded_decision_records_to_the_subjects_tenant_shard() {
        use decern_store::{FileLedgerHeadStore, LedgerHeadStore};

        // Isolated temp head-store root.
        let root = std::env::temp_dir().join(format!(
            "decern-serve-sharded-test-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();

        let store: Arc<dyn LedgerHeadStore> = Arc::new(FileLedgerHeadStore::new(&root).unwrap());
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let pubkey = key.verifying_key();
        let sharded = ShardedLedger::new(store.clone(), key, vec![]);

        let kernel = Kernel::new(&Model::builtin()).unwrap();
        let st = AppState {
            kernel: Arc::new(kernel),
            model: Arc::new(Model::builtin()),
            backend: Arc::new(LedgerBackend::Sharded(sharded)),
            missions: test_missions(),
            pubkey,
            require_mission: false,
            standing_issuers: Arc::new(Vec::new()),
            authority_digest: Arc::from("test-authority"),
            caller_disclosure: Arc::new(caller_disclosure(&caller::Caller::TrustedProxy)),
        };

        // corpB is a builtin principal in tenant "B".
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"corpB"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claimB"}}"#,
        )
        .unwrap();
        let resp = decide(State(st), None, Json(req)).await;
        assert_eq!(resp.status(), StatusCode::OK, "recorded decision is served");

        // Read the log back via an independent reader over the same store.
        let reader = ShardedLedger::new(store.clone(), SigningKey::from_bytes(&[1u8; 32]), vec![]);
        let in_b = reader.read_records("B", 0, 100).unwrap();
        assert_eq!(in_b.len(), 1, "the decision landed in shard B");
        assert_eq!(
            in_b[0]["entry"]["subject_id"], "corpB",
            "and it is corpB's decision"
        );
        // Nothing spilled into the reserved unattributed shard.
        let in_system = reader.read_records(UNATTRIBUTED_SHARD, 0, 100).unwrap();
        assert!(in_system.is_empty(), "unattributed shard stays empty");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Which routes the guard covers, asserted through the router rather than read off the
    /// source. A route added to the open half by mistake is exactly the failure this catches,
    /// and it can only be caught from outside.
    /// The two credential postures refuse differently, and that difference is a design
    /// decision rather than an accident of which module grew first: a bearer refusal owes
    /// an RFC 6750 challenge naming the scheme to retry with, and a signed-request refusal
    /// has no such scheme to name — offering `Bearer` there would invite a retry with
    /// exactly the credential this posture does not accept. Pinned here because the
    /// `CallerAuth` trait now makes it easy to give a new posture the wrong one by default.
    #[tokio::test]
    async fn each_posture_refuses_in_its_own_scheme() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let mut agents = std::collections::BTreeMap::new();
        agents.insert(
            "agent-1".to_owned(),
            SigningKey::from_bytes(&[9u8; 32]).verifying_key(),
        );
        let router = app(
            st,
            Arc::new(caller::Caller::Signed(Box::new(
                crate::sig::SigConfig::new(agents, "https://pdp.example/"),
            ))),
        );
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluation")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            resp.headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .is_none(),
            "a signed-request refusal must not advertise a scheme it does not accept"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Through the router, not just the verifier: the guard must hash the body it
    /// restores onto the request. A unit test that passes a swapped body into
    /// `authenticate` cannot catch a middleware that never buffered it.
    #[tokio::test]
    async fn a_captured_signed_post_cannot_swap_its_body_through_the_guard() {
        use axum::body::Body;
        use axum::http::Request;
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        use tower::ServiceExt;

        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let mut agents = std::collections::BTreeMap::new();
        agents.insert("agent-1".to_owned(), vk);
        let router = app(
            st,
            Arc::new(caller::Caller::Signed(Box::new(crate::sig::SigConfig {
                agents,
                audience: "https://pdp.example/access/v1/evaluation".into(),
                pep: std::collections::BTreeSet::new(),
            }))),
        );

        // Named as itself: a subject the caller is not allowed to speak as would 403
        // at admission, and this test is about the digest, not that check.
        let read = br#"{"subject":{"type":"Principal","id":"agent-1"},"action":{"name":"Read"},"resource":{"type":"Resource","id":"claim1"}}"#;
        let r#move = br#"{"subject":{"type":"Principal","id":"agent-1"},"action":{"name":"MoveMoney"},"resource":{"type":"Resource","id":"claim1"}}"#;

        let token = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let header = serde_json::json!({ "typ": "dpop-bound+jwt", "alg": "EdDSA" });
            let claims = serde_json::json!({
                "sub": "agent-1",
                "iss": "https://agent-provider.example/",
                "aud": "https://pdp.example/access/v1/evaluation",
                "exp": 4_000_000_000u64,
                "cnf": { "jwk": {
                    "kty": "OKP", "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
                }},
            });
            let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
            format!("{h}.{p}.unverified")
        };
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let digest = format!(
            "sha-256=:{}:",
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(read))
        );
        let components =
            "\"@method\" \"@authority\" \"@path\" \"content-digest\" \"signature-key\"";
        let input = format!("sig1=({components});created={created}");
        let base_str = format!(
            "\"@method\": POST\n\"@authority\": pdp.example\n\"@path\": /access/v1/evaluation\n\"content-digest\": {digest}\n\"signature-key\": {token}\n\"@signature-params\": ({components});created={created}"
        );
        use ed25519_dalek::Signer as _;
        let sig = format!(
            "sig1=:{}:",
            base64::engine::general_purpose::STANDARD
                .encode(key.sign(base_str.as_bytes()).to_bytes())
        );

        let signed = |body: &'static [u8]| {
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("host", "pdp.example")
                .header("content-type", "application/json")
                .header("signature-key", token.as_str())
                .header("signature-input", input.as_str())
                .header("signature", sig.as_str())
                .header("content-digest", digest.as_str())
                .body(Body::from(body))
                .unwrap()
        };

        let ok = router.clone().oneshot(signed(read)).await.unwrap();
        assert_eq!(
            ok.status(),
            StatusCode::OK,
            "matching body must authenticate"
        );

        let swapped = router.oneshot(signed(r#move)).await.unwrap();
        assert_eq!(
            swapped.status(),
            StatusCode::UNAUTHORIZED,
            "a captured signature must not authorize a different body"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn every_deciding_route_refuses_an_unauthenticated_caller() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let cfg = bearer::Config {
            issuer: "https://issuer.example/".into(),
            audience: "https://pdp.example/".into(),
            keys: vec![SigningKey::from_bytes(&[3u8; 32]).verifying_key()],
            scopes: vec![],
        };
        let router = app(st, Arc::new(caller::Caller::Bearer(Box::new(cfg))));

        // Every route in the guarded half of `app()`, plus one wrong-method probe: the
        // guard is a route layer, so a mismatched method on a guarded path must still be
        // refused as 401, never answered 405 by a handler-side default.
        for (method, uri) in [
            ("POST", "/access/v1/evaluation"),
            ("POST", "/decide"),
            ("GET", "/decide"),
            ("POST", "/mission/v1/approve"),
            ("GET", "/mission/v1/AAAA"),
            ("POST", "/mission/v1/AAAA/terminate"),
            ("GET", "/directory/v1/principals/corp/descendants"),
        ] {
            let resp = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri} answered without establishing the caller"
            );
            // RFC 6750 §3: a 401 that does not say how to authenticate leaves the client
            // guessing, and OAuth 2.1 §5.3 requires the challenge.
            assert!(
                resp.headers()
                    .get(axum::http::header::WWW_AUTHENTICATE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("Bearer ")),
                "{method} {uri} returned no bearer challenge"
            );
        }

        // Every route in the open half stays reachable, pinned by expected status: an
        // anchor nobody can fetch is not an anchor, and a subject who cannot ask what was
        // decided about them has lost the surface this server exists to give them.
        for (uri, expect) in [
            ("/healthz", StatusCode::OK),
            ("/pubkey", StatusCode::OK),
            (
                "/.well-known/decern-subject-side-disclosure",
                StatusCode::OK,
            ),
            ("/anchor/v1/tree-head", StatusCode::OK),
            ("/audit/v1/subject?handle=ppid:nobody", StatusCode::OK),
        ] {
            let resp = router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), expect, "{uri} is open by intent");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The guard is a layer, so "does a valid token actually reach the handler" is a distinct
    /// question from "is the token accepted" — a `route_layer` that rejected everything would
    /// pass every test above.
    #[tokio::test]
    async fn a_valid_token_reaches_the_decision_handler() {
        use axum::body::Body;
        use axum::http::Request;
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::Signer;
        use tower::ServiceExt;

        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let issuer_key = SigningKey::from_bytes(&[4u8; 32]);
        let router = app(
            st,
            Arc::new(caller::Caller::Bearer(Box::new(bearer::Config {
                issuer: "https://issuer.example/".into(),
                audience: "https://pdp.example/".into(),
                keys: vec![issuer_key.verifying_key()],
                scopes: vec![],
            }))),
        );

        let h = URL_SAFE_NO_PAD.encode(br#"{"typ":"at+jwt","alg":"EdDSA"}"#);
        let claims = json!({
            "iss": "https://issuer.example/",
            "aud": "https://pdp.example/",
            "sub": "gateway-1",
            "client_id": "gw",
            "iat": now_secs(),
            "jti": "t1",
            // Far enough out that the wall clock the guard reads cannot overtake it.
            "exp": now_secs() + 3600,
        });
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let sig = issuer_key.sign(format!("{h}.{p}").as_bytes());
        let token = format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));

        let body = serde_json::to_vec(&json!({
            "subject": {"type": "Principal", "id": "corp"},
            "action": {"name": "Read"},
            "resource": {"type": "Resource", "id": "claimA"},
        }))
        .unwrap();
        let (status, body) = body_json(
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/access/v1/evaluation")
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a verified caller was still refused"
        );
        assert!(body.get("decision").is_some(), "no decision was returned");

        // The record says who asserted the request: the token's subject, client and
        // issuer, exactly as verified. This is the caller column's positive control;
        // the trusted-proxy test below is its negative.
        let raw = std::fs::read_to_string(base.join("decern-ledger.jsonl")).unwrap();
        let rec: Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(rec["entry"]["asserted_by"]["sub"], "gateway-1", "{rec}");
        assert_eq!(rec["entry"]["asserted_by"]["client_id"], "gw", "{rec}");
        assert_eq!(
            rec["entry"]["asserted_by"]["iss"], "https://issuer.example/",
            "{rec}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Through the router: a valid signature still cannot name a principal other
    /// than the agent it authenticated. 403, not 401 — the credential was accepted.
    #[tokio::test]
    async fn a_signed_agent_cannot_evaluate_as_another_principal_through_the_guard() {
        use tower::ServiceExt;

        let (router, req, base) = signed_eval_request("corp", false);
        let (status, body) = body_json(router.oneshot(req).await.unwrap()).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "admission is 403, not 401: {body}"
        );
        assert_eq!(body["error"], "caller_mismatch", "{body}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_pep_signed_agent_may_evaluate_as_another_principal_through_the_guard() {
        use tower::ServiceExt;

        let (router, req, base) = signed_eval_request("corp", true);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&base);
    }

    fn signed_eval_request(
        subject: &str,
        pep: bool,
    ) -> (
        axum::Router,
        axum::http::Request<axum::body::Body>,
        std::path::PathBuf,
    ) {
        use axum::body::Body;
        use axum::http::Request;
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        use sha2::{Digest, Sha256};

        let key = SigningKey::from_bytes(&[11u8; 32]);
        let vk = key.verifying_key();
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let mut agents = std::collections::BTreeMap::new();
        agents.insert("agent-1".to_owned(), vk);
        let mut cfg =
            crate::sig::SigConfig::new(agents, "https://pdp.example/access/v1/evaluation");
        if pep {
            cfg.pep.insert("agent-1".into());
        }
        let router = app(st, Arc::new(caller::Caller::Signed(Box::new(cfg))));
        let body = format!(
            r#"{{"subject":{{"type":"Principal","id":"{subject}"}},"action":{{"name":"Read"}},"resource":{{"type":"Resource","id":"claim1"}}}}"#
        );
        let token = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let header = serde_json::json!({ "typ": "dpop-bound+jwt", "alg": "EdDSA" });
            let claims = serde_json::json!({
                "sub": "agent-1",
                "iss": "https://agent-provider.example/",
                "aud": "https://pdp.example/access/v1/evaluation",
                "exp": 4_000_000_000u64,
                "cnf": { "jwk": {
                    "kty": "OKP", "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
                }},
            });
            let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
            format!("{h}.{p}.unverified")
        };
        let created = now_secs();
        // Cover this body's digest, or the guard 401s before admission can 403.
        let digest = format!(
            "sha-256=:{}:",
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body.as_bytes()))
        );
        let components =
            "\"@method\" \"@authority\" \"@path\" \"content-digest\" \"signature-key\"";
        let input = format!("sig1=({components});created={created}");
        let base_str = format!(
            "\"@method\": POST\n\"@authority\": pdp.example\n\"@path\": /access/v1/evaluation\n\"content-digest\": {digest}\n\"signature-key\": {token}\n\"@signature-params\": ({components});created={created}"
        );
        let sig = format!(
            "sig1=:{}:",
            base64::engine::general_purpose::STANDARD
                .encode(key.sign(base_str.as_bytes()).to_bytes())
        );
        let req = Request::builder()
            .method("POST")
            .uri("/access/v1/evaluation")
            .header("host", "pdp.example")
            .header("content-type", "application/json")
            .header("signature-key", token)
            .header("signature-input", input)
            .header("signature", sig)
            .header("content-digest", digest)
            .body(Body::from(body))
            .unwrap();
        (router, req, base)
    }

    /// Under a trusted front the server verified nothing itself, so the record carries
    /// no asserted_by at all — an absent column, never an empty or guessed one.
    #[tokio::test]
    async fn a_trusted_proxy_decision_records_no_asserted_by() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let router = app(st, open());
        let body = serde_json::to_vec(&json!({
            "subject": {"type": "Principal", "id": "corp"},
            "action": {"name": "Read"},
            "resource": {"type": "Resource", "id": "claim1"},
        }))
        .unwrap();
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluation")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = std::fs::read_to_string(base.join("decern-ledger.jsonl")).unwrap();
        let rec: Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert!(rec["entry"].get("asserted_by").is_none(), "{rec}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn mission_routes_are_reachable_through_the_router() {
        // The handler tests call the functions directly; this drives real requests
        // through `app()`, exercising the axum path layer: that the router BUILDS (a
        // route conflict would panic here), that `POST /mission/v1/approve` resolves to
        // the literal route rather than being captured as `{s256}="approve"`, and that
        // the `{s256}` (base64url) segment routes to get/terminate.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let router = app(st, open());

        let approve_body = serde_json::to_vec(&json!({
            "approver": "corp",
            "agent": "agent-mission",
            "description": "reconcile invoices",
            "approved_tools": ["read"],
            "expiry": corp_expiry(),
        }))
        .unwrap();
        let (status, body) = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mission/v1/approve")
                        .header("content-type", "application/json")
                        .body(Body::from(approve_body))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "approve routed to the literal path");
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let (status, body) = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/mission/v1/{s256}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"], "active", "{s256} routed to get");

        let (status, body) = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/mission/v1/{s256}/terminate"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"], "terminated", "{s256}/terminate routed");

        // The blast-radius preview resolves through the same path layer. A route
        // written in an older capture syntax compiles fine and panics only when the
        // router is built, so it has to be driven, not merely called.
        let (status, body) = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/directory/v1/principals/corp/descendants")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "descendants routed: {body}");
        assert_eq!(body["principal"], "corp");
        assert!(
            body["descendants"].is_array(),
            "descendants must be a list: {body}"
        );

        // The anchor endpoint resolves too, and returns a commitment a reader can check.
        let (status, th) = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/anchor/v1/tree-head")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "tree head routed: {th}");
        assert!(
            th["merkle_root"].as_str().is_some_and(|r| !r.is_empty()),
            "a commitment must carry a root: {th}"
        );
        assert!(th["tree_size"].as_u64().is_some(), "and a size: {th}");
        assert!(
            th["sig_b64"].as_str().is_some_and(|s| !s.is_empty()),
            "and a signature, or it commits nobody: {th}"
        );
        // It commits, and discloses nothing about what was decided.
        assert!(
            th.get("entries").is_none() && th.get("records").is_none(),
            "a tree head must not carry entry content: {th}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn decide_under_live_mission_allows_and_records_mission_ref() {
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        // Approve a Mission for corp (non-expired builtin principal) with move_money.
        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                None,
                Json(MissionApproveReq {
                    approver: "corp".into(),
                    agent: "corp".into(),
                    description: "under-mission decide".into(),
                    approved_tools: vec!["read".into(), "move_money".into()],
                    capabilities: vec![],
                    expiry: corp_expiry(),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let mut st = st;
        st.require_mission = true;
        let req: DecideReq = serde_json::from_str(&format!(
            r#"{{"subject":{{"type":"Principal","id":"corp"}},
                "action":{{"name":"MoveMoney"}},
                "resource":{{"type":"Resource","id":"claim1"}},
                "context":{{"mission":{{"approver":"corp","s256":"{s256}"}}}}}}"#
        ))
        .unwrap();
        let (status, body) = body_json(decide(State(st.clone()), None, Json(req)).await).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["decision"], true,
            "mission-gated MoveMoney allows: {body}"
        );

        let ledger_path = base.join("decern-ledger.jsonl");
        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 100).unwrap();
        let last = records.last().expect("decision recorded");
        assert_eq!(last["entry"]["action"], "MoveMoney");
        assert_eq!(last["entry"]["decision"], true);
        assert_eq!(last["entry"]["mission"]["s256"], s256);
        assert!(
            last["entry"]["digests"]["parameters"].as_str().is_some(),
            "the parameters digest must be written: {last}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The projection answers with what was decided about one party, and with proofs the
    /// party can check against the commitment themselves — the point being that none of it
    /// requires believing this server's account of events.
    #[tokio::test]
    async fn the_subject_projection_returns_checkable_proofs() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);

        // Two decisions about one party, and one about nobody in particular.
        for (resource, subject) in [
            ("claim1", Some("ppid:carol")),
            ("claim1", None),
            ("claim1", Some("ppid:carol")),
        ] {
            let ctx = match subject {
                Some(h) => format!(r#"{{"decision_subject":"{h}"}}"#),
                None => "{}".to_owned(),
            };
            let req: DecideReq = serde_json::from_str(&format!(
                r#"{{"subject":{{"type":"Principal","id":"agent1"}},
                    "action":{{"name":"Read"}},
                    "resource":{{"type":"Resource","id":"{resource}"}},
                    "context":{ctx}}}"#
            ))
            .unwrap();
            let (status, body) = body_json(decide(State(st.clone()), None, Json(req)).await).await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }

        // Driven through the router rather than called: a handler that is written but
        // never registered passes every direct call it is given and answers no request.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let (status, body) = body_json(
            app(st.clone(), open())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/audit/v1/subject?handle=ppid:carol")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the projection must be reachable: {body}"
        );
        let decisions = body["decisions"].as_array().expect("decisions array");
        assert_eq!(
            decisions.len(),
            2,
            "only the decisions about this party: {body}"
        );

        // Every proof checks against the head returned alongside it. A projection whose
        // proofs did not verify would be an assertion wearing a proof's clothes.
        let root: [u8; 32] = hex::decode(body["tree_head"]["merkle_root"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let tree_size = body["tree_head"]["tree_size"].as_u64().unwrap();
        for d in decisions {
            let p = &d["inclusion_proof"];
            // `leaf_data` is the record's chain hash; a verifier hashes it with the
            // RFC 9162 leaf prefix before checking the path, which is what stops a
            // record from being replayed as an interior node.
            let leaf_data = hex::decode(p["leaf_data"].as_str().unwrap()).unwrap();
            let leaf = decern_ledger::merkle::hash_leaf(&leaf_data);
            let path: Vec<[u8; 32]> = p["audit_path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| {
                    hex::decode(h.as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap()
                })
                .collect();
            assert!(
                decern_ledger::merkle::verify_inclusion(
                    p["leaf_index"].as_u64().unwrap(),
                    tree_size,
                    &leaf,
                    &root,
                    &path,
                ),
                "the proof for seq {} must verify against the returned head: {d}",
                p["leaf_index"]
            );
        }

        // Nothing the reader would have to trust this server about.
        assert!(
            body.get("pubkey").is_none() && body["tree_head"].get("privkey").is_none(),
            "the projection must return proofs, never keys: {body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The projection is bounded, and says so. The read holds the lock an append needs and a
    /// decision that cannot be recorded is refused, so an unbounded read is a way to stop the
    /// server deciding at all. A party reading a short list must not conclude that is all
    /// there was, so the cut is reported rather than left to be inferred from a count.
    #[tokio::test]
    async fn the_subject_projection_is_bounded_and_says_when_it_cut() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        for _ in 0..(MAX_PROJECTED_DECISIONS + 5) {
            let req: DecideReq = serde_json::from_str(
                r#"{"subject":{"type":"Principal","id":"agent1"},
                    "action":{"name":"Read"},
                    "resource":{"type":"Resource","id":"claim1"},
                    "context":{"decision_subject":"ppid:many"}}"#,
            )
            .unwrap();
            let (status, _) = body_json(decide(State(st.clone()), None, Json(req)).await).await;
            assert_eq!(status, StatusCode::OK);
        }

        let (status, body) = body_json(
            app(st.clone(), open())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/audit/v1/subject?handle=ppid:many")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["decisions"].as_array().unwrap().len(),
            MAX_PROJECTED_DECISIONS,
            "the projection must stop at the bound"
        );
        assert_eq!(
            body["truncated"], true,
            "a cut list must say it was cut: {body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A handle nobody has a record under gets an empty answer, not someone else's.
    #[tokio::test]
    async fn the_subject_projection_matches_a_handle_exactly() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"agent1"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claim1"},
                "context":{"decision_subject":"ppid:carol"}}"#,
        )
        .unwrap();
        let (status, _) = body_json(decide(State(st.clone()), None, Json(req)).await).await;
        assert_eq!(status, StatusCode::OK);

        // A prefix of a real handle is not that handle.
        let (status, body) = body_json(
            app(st.clone(), open())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/audit/v1/subject?handle=ppid:car")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body["decisions"].as_array().unwrap().is_empty(),
            "a prefix must not match, or the handle stops being the capability: {body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The disclosure is read from the running configuration, so it cannot drift from what
    /// the binary does — and it declines the outcome this deployment cannot route.
    #[tokio::test]
    async fn the_disclosure_reports_this_deployments_actual_configuration() {
        let base = mission_base();
        let (mut st, _pk) = mission_state_at(&base);
        let issuer = decern_crypto::generate().unwrap();
        st.standing_issuers = Arc::new(vec![issuer.verifying_key()]);

        // Driven through the router: a handler that is written but never registered
        // passes every direct call it is given and answers no request.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let (status, d) = body_json(
            app(st.clone(), open())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/.well-known/decern-subject-side-disclosure")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the disclosure must be reachable: {d}"
        );
        assert_eq!(
            d["standing_issuers"][0].as_str().unwrap(),
            hex::encode(issuer.verifying_key().to_bytes()),
            "the disclosure must name the issuers actually configured: {d}"
        );
        assert!(
            d["outcomes_not_supported"]
                .get("escalate_to_approver")
                .is_some(),
            "an outcome that routes nowhere must be declined, not claimed: {d}"
        );
        assert_eq!(d["notice"]["emitted_by_this_server"], false);
        assert_eq!(
            d["caller"]["mode"], "trusted-proxy",
            "the disclosure must state how this deployment establishes callers: {d}"
        );
        assert_eq!(d["caller"]["bind"], "any", "{d}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An action with no scope mapping cannot be shown to be covered by a grant,
    /// so under `--require-mission` it is refused. Skipping the check would let
    /// every future action ride on every Mission until someone mapped it.
    #[tokio::test]
    async fn mission_refuses_an_action_with_no_scope_mapping() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let (status, body) = body_json(
            mission_approve(
                State(st.clone()),
                None,
                Json(approve_req(&["read", "move_money"], corp_expiry())),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let s256 = body["s256"].as_str().unwrap().to_owned();

        let mut st = st;
        st.require_mission = true;
        let req: DecideReq = serde_json::from_str(&format!(
            r#"{{"subject":{{"type":"Principal","id":"corp"}},
                "action":{{"name":"SomeUnmappedFutureAction"}},
                "resource":{{"type":"Resource","id":"claim1"}},
                "context":{{"mission":{{"approver":"corp","s256":"{s256}"}}}}}}"#
        ))
        .unwrap();
        let (status, body) = body_json(decide(State(st.clone()), None, Json(req)).await).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["decision"], false,
            "an unmapped action must not inherit the grant: {body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn terminated_mission_cannot_justify_a_decision() {
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
        // approve_req uses agent-mission; terminate then try decide as that agent.
        let _ = mission_terminate(State(st.clone()), None, UrlPath(s256.clone())).await;

        let mut st = st;
        st.require_mission = true;
        let req: DecideReq = serde_json::from_str(&format!(
            r#"{{"subject":{{"type":"Principal","id":"agent-mission"}},
                "action":{{"name":"Read"}},
                "resource":{{"type":"Resource","id":"claim1"}},
                "context":{{"mission":{{"approver":"corp","s256":"{s256}"}}}}}}"#
        ))
        .unwrap();
        let (status, body) = body_json(decide(State(st), None, Json(req)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], false, "{body}");
        assert!(
            body["context"]["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e.as_str().unwrap_or("").contains("terminated")),
            "{body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn mission_tool_mismatch_denies() {
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

        let mut st = st;
        st.require_mission = true;
        // Mission only has read; MoveMoney needs move_money.
        let req: DecideReq = serde_json::from_str(&format!(
            r#"{{"subject":{{"type":"Principal","id":"agent-mission"}},
                "action":{{"name":"MoveMoney"}},
                "resource":{{"type":"Resource","id":"claim1"}},
                "context":{{"mission":{{"approver":"corp","s256":"{s256}"}}}}}}"#
        ))
        .unwrap();
        let (status, body) = body_json(decide(State(st), None, Json(req)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], false, "{body}");
        assert!(
            body["context"]["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e.as_str().unwrap_or("").contains("move_money")),
            "{body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
