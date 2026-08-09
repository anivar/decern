// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The audit surface: the signed tree-head anchor, the subject-side projection
//! and disclosure, and the read-only directory and key endpoints.

use axum::Json;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use decern_ledger::LedgerError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{AppState, LedgerBackend, now_secs};

/// `GET /anchor/v1/tree-head` — a signed commitment to the log's current Merkle state.
///
/// The point of publishing this is what an operator cannot do afterwards. A hash chain
/// proves a log is internally consistent, which its own author can always arrange by
/// rewriting it. A tree head published somewhere the operator does not control, and later
/// checked with a consistency proof, is what makes a dropped or back-dated record
/// detectable rather than merely against the rules.
///
/// It commits, and discloses nothing: a root, a size, a timestamp and a signature. Anyone
/// may fetch it, and it is worth exactly as much as the independence of wherever it is
/// published — a commitment only the operator ever holds proves nothing about the operator.
///
/// Sharded deployments have one chain per tenant and so no single tree, and say so rather
/// than returning a commitment to one of them.
pub(crate) async fn tree_head(State(st): State<AppState>) -> Response {
    match &*st.backend {
        LedgerBackend::Single(m) => {
            let ledger = match m.lock() {
                Ok(g) => g,
                Err(_) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({ "error": "tree head unavailable", "detail": "ledger mutex poisoned" })),
                    )
                        .into_response();
                }
            };
            match ledger.tree_head(now_secs().saturating_mul(1000)) {
                Ok(th) => (StatusCode::OK, Json(json!(th))).into_response(),
                Err(e) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "tree head unavailable", "detail": e.to_string() })),
                )
                    .into_response(),
            }
        }
        LedgerBackend::Sharded(_) => (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "no single tree head",
                "detail": "a sharded deployment keeps one chain per tenant; anchor each shard",
            })),
        )
            .into_response(),
    }
}

/// `GET /audit/v1/subject?handle=<h>` — the decisions recorded about one party, each with a
/// proof that it is in the log the anchor commits to.
///
/// A notice an operator is obliged to send is worth what their willingness to send it is
/// worth. This is the other direction: a party who suspects a decision was made about them
/// can ask, and can check the answer against a commitment the operator published earlier,
/// without believing anything the operator says in this response.
///
/// So the response carries proofs and never keys. The reader verifies with a key obtained
/// elsewhere; one handed over in the same response would prove only that the operator can
/// sign their own account of events.
///
/// The handle is the capability. It matches exactly — no prefix, no listing — so the
/// endpoint answers a party who already knows their own handle and tells everyone else
/// nothing. That, and the pseudonymity of the handle itself, is the entire access control
/// here, deliberately: this route stays outside the bearer guard, because the party a
/// decision was about will not hold a credential for the deployment that decided it.
/// What that choice costs is stated in the CLI reference's trust-boundary section.
///
/// The handle arrives as a query parameter rather than a path segment because a handle is an
/// opaque string chosen by whoever mints it — the conventional forms carry a colon — and a
/// path segment is the wrong carrier for one: it has to be percent-encoded to survive, and a
/// caller who forgets gets a routing miss rather than an answer, which reads as "no records
/// about you". A query parameter carries it as given.
///
/// Scans the log per request, which is honest for a reference implementation and would need
/// an index in a deployment large enough to feel it.
#[derive(Deserialize)]
pub(crate) struct SubjectQuery {
    handle: String,
}

/// How many decisions one projection will return. The read holds the same lock an append
/// needs, and a decision that cannot be recorded is refused rather than served — so an
/// unbounded read here is a way to stop the server deciding anything at all. A bounded page
/// that says it was cut is worth more than a complete one that costs availability.
pub(crate) const MAX_PROJECTED_DECISIONS: usize = 256;

pub(crate) async fn subject_audit(
    State(st): State<AppState>,
    Query(q): Query<SubjectQuery>,
) -> Response {
    let handle = q.handle;
    let LedgerBackend::Single(m) = &*st.backend else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "no single log to project",
                "detail": "a sharded deployment keeps one chain per tenant; query each shard",
            })),
        )
            .into_response();
    };
    // The lock an append needs is held twice, briefly: once to copy the raw bytes out,
    // once to sign the head. Every parse, match and proof happens between, unlocked —
    // the projection's cost stops competing with the server's ability to decide.
    let lines = {
        let ledger = match m.lock() {
            Ok(g) => g,
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "audit projection unavailable", "detail": "ledger mutex poisoned" })),
                )
                    .into_response();
            }
        };
        match ledger.raw_records() {
            Ok(l) => l,
            Err(e) => return audit_unavailable(&e),
        }
    };

    let leaves = match decern_ledger::leaves_from_lines(&lines) {
        Ok(l) => l,
        Err(e) => return audit_unavailable(&e),
    };

    /// Just enough of a record to match on, so a log of a million strangers' decisions
    /// is not deserialized in full to answer for one handle.
    #[derive(serde::Deserialize)]
    struct Probe {
        #[serde(default)]
        entry: ProbeEntry,
    }
    #[derive(serde::Deserialize, Default)]
    struct ProbeEntry {
        #[serde(default)]
        decision_subject: Option<ProbeSubject>,
    }
    #[derive(serde::Deserialize)]
    struct ProbeSubject {
        #[serde(default)]
        handle: Option<String>,
    }

    let mut matched = Vec::new();
    let mut truncated = false;
    for (seq, line) in lines.iter().enumerate() {
        if matched.len() >= MAX_PROJECTED_DECISIONS {
            truncated = true;
            break;
        }
        let recorded = serde_json::from_str::<Probe>(line)
            .ok()
            .and_then(|p| p.entry.decision_subject)
            .and_then(|ds| ds.handle);
        if recorded.as_deref() != Some(handle.as_str()) {
            continue;
        }
        // Only a match is parsed in full — the page is bounded, so this is too.
        match serde_json::from_str::<Value>(line) {
            Ok(rec) => matched.push((seq as u64, rec)),
            Err(e) => return audit_unavailable(&decern_ledger::LedgerError::Serde(e.to_string())),
        }
    }

    let seqs: Vec<u64> = matched.iter().map(|(seq, _)| *seq).collect();
    let proofs = match decern_ledger::inclusion_proofs_over(&leaves, &seqs) {
        Ok(p) => p,
        Err(e) => return audit_unavailable(&e),
    };

    // Signed over the snapshot the proofs are against. An append that lands between the
    // two locks makes this a head over the earlier prefix — the same consistent answer
    // the caller would have gotten before the append, never a mixed one.
    let now_ms = now_secs().saturating_mul(1000);
    let root_hex = hex::encode(decern_ledger::merkle::tree_hash(&leaves));
    let head = {
        let ledger = match m.lock() {
            Ok(g) => g,
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "audit projection unavailable", "detail": "ledger mutex poisoned" })),
                )
                    .into_response();
            }
        };
        ledger.sign_tree_head(root_hex, leaves.len() as u64, now_ms)
    };

    let decisions: Vec<Value> = matched
        .into_iter()
        .zip(proofs)
        .map(|((seq, rec), proof)| json!({ "seq": seq, "record": rec, "inclusion_proof": proof }))
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "decision_subject": handle,
            "tree_head": head,
            "decisions": decisions,
            // Said out loud rather than left to be inferred from a count: a party
            // reading a short list must not conclude that is all there was.
            "truncated": truncated,
        })),
    )
        .into_response()
}

/// A projection that cannot be read is unavailable, never an empty answer: "no decisions
/// about you" and "the log would not open" must not look the same to the party asking.
fn audit_unavailable(e: &LedgerError) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "audit projection unavailable", "detail": e.to_string() })),
    )
        .into_response()
}

/// `GET /.well-known/decern-subject-side-disclosure` — what this deployment actually does
/// about challenges, as opposed to what it could be assumed to.
///
/// Every value here is read from the running configuration rather than written down, so a
/// deployment that accepts no issuers says so, and a claim cannot drift from the binary
/// that makes it. The two things worth reading before relying on any of it: which issuers
/// this deployment will believe, and which answers it can give.
///
/// It is honest about the answer it does not give. Handing a challenge to a human approver
/// needs an approver service this server does not have; claiming that outcome while routing
/// nowhere would be worse than declining it.
pub(crate) async fn subject_side_disclosure(State(st): State<AppState>) -> Json<Value> {
    Json(json!({
        "caller": *st.caller_disclosure,
        "standing_issuers": st
            .standing_issuers
            .iter()
            .map(|k| hex::encode(k.to_bytes()))
            .collect::<Vec<_>>(),
        "standing_token_formats": ["compact-jws-eddsa"],
        "standing_issuer_discovery": "configured",
        "outcomes_supported": ["affirm_prior_decision", "reevaluate_with_subject_context"],
        "outcomes_not_supported": {
            "escalate_to_approver": "no approver service is configured for this deployment",
        },
        "challenge_bases_that_reopen_a_decision": [
            "factual-error",
            "category-mismatch",
            "change-in-circumstances",
        ],
        "notice": {
            "emitted_by_this_server": false,
            "recorded_by_this_server": true,
            "detail": "this server decides and records; emitting notice belongs to whoever \
                       enforces the decision",
        },
        "audit": {
            "substrate": "append-only hash-chained log, Ed25519-signed per record",
            "anchor": "/anchor/v1/tree-head",
            "subject_projection": "/audit/v1/subject?handle=",
        },
    }))
}

pub(crate) async fn pubkey(State(st): State<AppState>) -> Json<Value> {
    Json(json!({ "kid": hex::encode(st.pubkey.to_bytes()) }))
}

/// `GET /directory/v1/principals/{id}/descendants` — the blast radius of revoking
/// `id`: every principal that would lose authority along with it.
///
/// Read-only and deliberately not recorded. The ledger is the record of decisions,
/// and asking what a revocation would cost is not one; recording it would put
/// operator curiosity in the same log as authorization outcomes.
///
/// Guarded, though it is a read: it discloses more than a single decision does — the
/// delegation shape of a tenant, and who acts for whom. Under `--trust-proxy` that
/// disclosure is the fronting proxy's to control, as every route is; under bearer
/// validation an org chart is not something an unverified caller gets to read.
pub(crate) async fn descendants(
    State(st): State<AppState>,
    UrlPath(id): UrlPath<String>,
) -> Response {
    let dir = st.kernel.directory();
    let descendants = dir.descendants_of(&id);
    (
        StatusCode::OK,
        Json(json!({ "principal": id, "descendants": descendants })),
    )
        .into_response()
}
