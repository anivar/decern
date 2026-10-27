// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The audit surface: the signed tree-head anchor, the subject-side projection
//! and disclosure, and the read-only directory and key endpoints.

use axum::Json;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use decern_ledger::{Ledger, LedgerError, TreeHead};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::Instant;

use crate::record::poisoned;
use crate::{AppState, LedgerBackend};

/// A tree head is recomputed at most this often; between, the last one is served. It commits
/// to a prefix of the log, and a prefix a moment old is as checkable as the latest.
pub(crate) const TREE_HEAD_REFRESH: std::time::Duration = std::time::Duration::from_secs(1);

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
    if let LedgerBackend::Sharded(_) = &*st.backend {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "no single tree head",
                "detail": "a sharded deployment keeps one chain per tenant; anchor each shard",
            })),
        )
            .into_response();
    }
    let unavailable = |detail: String| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "tree head unavailable", "detail": detail })),
        )
            .into_response()
    };
    // One computation at a time; the rest wait here, holding neither a thread nor the
    // ledger's lock, and are served what it computed. The computation keeps its turn until
    // it finishes, so a request that gives up cannot let a second read of the log start.
    let mut cached = st.tree_head.clone().lock_owned().await;
    let (backend, clock) = (st.backend.clone(), st.clock);
    let computed = tokio::task::spawn_blocking(move || {
        let fresh = current_tree_head(&backend, cached.clone(), clock)?;
        *cached = Some(fresh.clone());
        Ok::<_, HeadError>(fresh.1)
    });
    match computed.await {
        Ok(Ok(head)) => (StatusCode::OK, Json(json!(head))).into_response(),
        Ok(Err(HeadError::Clock)) => crate::clock_unavailable().into_response(),
        Ok(Err(HeadError::Ledger(e))) => unavailable(e.to_string()),
        Err(_) => unavailable("the tree head did not complete".into()),
    }
}

/// The tree head over the log as it is, or `last` while it still covers every record or is
/// under [`TREE_HEAD_REFRESH`] old. The lock an append holds across its fsync is taken only
/// to count the records and to sign; the read and the hashing happen between, unlocked. A
/// cached head needs no clock; a new one is timed by [`signing_time`]. Blocking, so it runs
/// on a thread that serves no requests.
fn current_tree_head(
    backend: &LedgerBackend,
    last: Option<(Instant, TreeHead)>,
    clock: crate::Clock,
) -> Result<(Instant, TreeHead), HeadError> {
    let m = single(backend)?;
    let prefix = m.lock().map_err(|_| poisoned())?.prefix();
    if let Some((at, head)) = last
        && (head.tree_size == prefix.count() || at.elapsed() < TREE_HEAD_REFRESH)
    {
        return Ok((at, head));
    }
    let leaves = decern_ledger::leaves_from_lines(&prefix.lines()?)?;
    let root = hex::encode(decern_ledger::merkle::tree_hash(&leaves));
    let now_ms = signing_time(clock)?;
    let head = m
        .lock()
        .map_err(|_| poisoned())?
        .sign_tree_head(root, leaves.len() as u64, now_ms);
    Ok((Instant::now(), head))
}

/// Why a head could not be produced: the log could not be read, or the clock has no time
/// to sign it at.
enum HeadError {
    Ledger(LedgerError),
    Clock,
}

impl From<LedgerError> for HeadError {
    fn from(e: LedgerError) -> Self {
        HeadError::Ledger(e)
    }
}

/// The time a head is signed at, in milliseconds, read when it is signed: after the wait for
/// a turn and the read of the log, so a head is never timed earlier than a record it covers.
fn signing_time(clock: crate::Clock) -> Result<u64, HeadError> {
    clock()
        .map(|secs| secs.saturating_mul(1000))
        .ok_or(HeadError::Clock)
}

/// The single-file ledger, the only one the audit surface reads. Each handler answers a
/// sharded deployment `501` before it gets here.
fn single(backend: &LedgerBackend) -> Result<&Mutex<Ledger>, LedgerError> {
    match backend {
        LedgerBackend::Single(m) => Ok(m),
        LedgerBackend::Sharded(_) => Err(LedgerError::Io {
            path: "ledger".into(),
            err: "a sharded deployment has no single log".into(),
        }),
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

/// How many decisions one projection will return. Anyone holding a handle may ask, and each
/// match is parsed in full and proved, so the page is bounded and says when it was cut. A
/// bounded page that says it was cut is worth more than a complete one that costs
/// availability.
pub(crate) const MAX_PROJECTED_DECISIONS: usize = 256;

pub(crate) async fn subject_audit(
    State(st): State<AppState>,
    Query(q): Query<SubjectQuery>,
) -> Response {
    if let LedgerBackend::Sharded(_) = &*st.backend {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "no single log to project",
                "detail": "a sharded deployment keeps one chain per tenant; query each shard",
            })),
        )
            .into_response();
    }
    // Refused before the whole log is read; the head is timed when it is signed, below.
    if (st.clock)().is_none() {
        return crate::clock_unavailable().into_response();
    }
    // One projection at a time, and it keeps its turn until it finishes: each reads the
    // whole log into memory, and an open route must not let a crowd of them, or of requests
    // that gave up on them, do so at once.
    let turn = st.projection.clone().lock_owned().await;
    let (backend, clock) = (st.backend.clone(), st.clock);
    let projected = tokio::task::spawn_blocking(move || {
        let _turn = turn;
        project(&backend, q.handle, clock)
    });
    let Projection {
        handle,
        head,
        matched,
        proofs,
        truncated,
    } = match projected.await {
        Ok(Ok(p)) => p,
        Ok(Err(HeadError::Clock)) => return crate::clock_unavailable().into_response(),
        Ok(Err(HeadError::Ledger(e))) => return audit_unavailable(e),
        Err(_) => return audit_unavailable("the projection did not complete"),
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

/// What [`subject_audit`] answers from.
struct Projection {
    handle: String,
    head: TreeHead,
    matched: Vec<(u64, Value)>,
    proofs: Vec<decern_ledger::InclusionProof>,
    truncated: bool,
}

/// The records that name `handle` as their decision subject, each with its inclusion proof,
/// and a head signed over the prefix they are proved against. The lock an append holds across
/// its fsync is taken twice, briefly: once to count the records, once to sign. Reading,
/// parsing, matching and proving happen between, unlocked. Blocking, so it runs on a thread
/// that serves no requests.
fn project(
    backend: &LedgerBackend,
    handle: String,
    clock: crate::Clock,
) -> Result<Projection, HeadError> {
    let m = single(backend)?;
    let prefix = m.lock().map_err(|_| poisoned())?.prefix();
    let lines = prefix.lines()?;
    let leaves = decern_ledger::leaves_from_lines(&lines)?;
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
            Err(e) => return Err(LedgerError::Serde(e.to_string()).into()),
        }
    }

    let seqs: Vec<u64> = matched.iter().map(|(seq, _)| *seq).collect();
    let proofs = decern_ledger::inclusion_proofs_over(&leaves, &seqs)?;

    // Signed over the snapshot the proofs are against. An append that lands between the
    // two locks makes this a head over the earlier prefix — the same consistent answer
    // the caller would have gotten before the append, never a mixed one.
    let root = hex::encode(decern_ledger::merkle::tree_hash(&leaves));
    let now_ms = signing_time(clock)?;
    let head = m
        .lock()
        .map_err(|_| poisoned())?
        .sign_tree_head(root, leaves.len() as u64, now_ms);
    Ok(Projection {
        handle,
        head,
        matched,
        proofs,
        truncated,
    })
}

/// A projection that cannot be read is unavailable, never an empty answer: "no decisions
/// about you" and "the log would not open" must not look the same to the party asking.
fn audit_unavailable(detail: impl std::fmt::Display) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "audit projection unavailable", "detail": detail.to_string() })),
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
        "outcomes_supported": crate::challenge::Outcome::NAMES,
        // Said here, beside the names, so no reader takes an outcome for a second decision.
        "outcomes_describe": "whether a challenge whose standing names the request's decision \
                              subject bears on the facts the decision was made from; the \
                              decision is not evaluated again and stands as recorded",
        "outcomes_not_supported": {
            "escalate_to_approver": "no approver service is configured for this deployment",
        },
        "challenge_bases_that_bear_on_the_facts": crate::challenge::BASES_ON_THE_FACTS,
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

/// `GET /pubkey` — `kid`, the key signing records now, and `keys`, every key a record of this
/// ledger may be verified under: the retired keys in the order configured, then `kid`.
pub(crate) async fn pubkey(State(st): State<AppState>) -> Json<Value> {
    let kid = hex::encode(st.pubkey.to_bytes());
    let mut keys: Vec<String> = st
        .retired_keys
        .iter()
        .map(|k| hex::encode(k.to_bytes()))
        .collect();
    keys.push(kid.clone());
    Json(json!({ "kid": kid, "keys": keys }))
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
/// validation an org chart is not something an unverified caller gets to read. Under
/// signed-request mode, a workload may only inspect its own blast radius unless it is
/// named in `--pep`.
pub(crate) async fn descendants(
    State(st): State<AppState>,
    caller: Option<axum::Extension<crate::caller::Authenticated>>,
    UrlPath(id): UrlPath<String>,
) -> Response {
    if let Some(refusal) = crate::caller::refuse_unless_admits(&caller, &id) {
        return refusal;
    }
    let dir = st.kernel.directory();
    let descendants = dir.descendants_of(&id);
    (
        StatusCode::OK,
        Json(json!({ "principal": id, "descendants": descendants })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::extract::{Path as UrlPath, State};
    use axum::http::StatusCode;

    use super::*;

    use crate::testutil::{body_json, mission_base, mission_state_at};

    /// A tree head is recomputed at most once a refresh interval: a request soon after the
    /// last is served the cached head, and one after the interval sees the log as it is.
    #[tokio::test]
    async fn a_tree_head_is_recomputed_at_most_once_a_refresh_interval() {
        let base = crate::testutil::mission_base();
        let (st, _pk) = crate::testutil::mission_state_at(&base);
        let append = || {
            let LedgerBackend::Single(m) = &*st.backend else {
                panic!("single-file backend expected");
            };
            m.lock()
                .unwrap()
                .append(decern_ledger::Entry {
                    action: "Read".into(),
                    subject_type: "Principal".into(),
                    subject_id: "corp".into(),
                    resource_type: "Resource".into(),
                    resource_id: "r".into(),
                    context: json!({ "now": 1 }),
                    ..Default::default()
                })
                .unwrap();
        };
        async fn size(r: Response) -> Value {
            crate::testutil::body_json(r).await.1["tree_size"].clone()
        }
        append();
        assert_eq!(size(tree_head(State(st.clone())).await).await, 1);
        append();
        assert_eq!(
            size(tree_head(State(st.clone())).await).await,
            1,
            "served from the cache"
        );
        tokio::time::sleep(TREE_HEAD_REFRESH + std::time::Duration::from_millis(100)).await;
        assert_eq!(size(tree_head(State(st.clone())).await).await, 2);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A head is timed when it is signed, after the wait for its turn and the read of the log,
    /// never when it was asked for: a record that lands during the wait is covered by a head
    /// timed after it. The test clock steps forward while each request waits for its turn.
    #[tokio::test]
    async fn a_head_is_timed_when_it_is_signed_not_when_it_was_asked_for() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn stepped() -> Option<u64> {
            Some(NOW.load(Ordering::SeqCst))
        }
        let base = mission_base();
        let (mut st, _pk) = mission_state_at(&base);
        st.clock = stepped;
        let wait = std::time::Duration::from_millis(50);

        NOW.store(1_000_000, Ordering::SeqCst);
        let turn = st.tree_head.clone().lock_owned().await;
        let asked = tokio::spawn(tree_head(State(st.clone())));
        tokio::time::sleep(wait).await;
        NOW.store(2_000_000, Ordering::SeqCst);
        drop(turn);
        let (_, head) = body_json(asked.await.unwrap()).await;
        assert_eq!(head["ts_ms"], 2_000_000_000_u64, "tree head: {head}");

        NOW.store(1_000_000, Ordering::SeqCst);
        let turn = st.projection.clone().lock_owned().await;
        let asked = tokio::spawn(subject_audit(
            State(st.clone()),
            Query(SubjectQuery { handle: "h".into() }),
        ));
        tokio::time::sleep(wait).await;
        NOW.store(2_000_000, Ordering::SeqCst);
        drop(turn);
        let (_, body) = body_json(asked.await.unwrap()).await;
        assert_eq!(
            body["tree_head"]["ts_ms"], 2_000_000_000_u64,
            "subject audit: {body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The audit routes wait for the ledger's lock, which an append holds across its fsync, on
    /// a blocking thread. A test runtime has one thread, so a handler that waited on it would
    /// hold the timer below until the lock was let go.
    #[tokio::test]
    async fn the_audit_routes_wait_for_the_ledger_off_the_request_threads() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let hold = std::time::Duration::from_secs(1);
        for route in ["tree head", "subject audit"] {
            let (taken, held) = std::sync::mpsc::channel();
            let holder = {
                let st = st.clone();
                std::thread::spawn(move || {
                    let LedgerBackend::Single(m) = &*st.backend else {
                        panic!("single-file backend expected");
                    };
                    let _held = m.lock().unwrap();
                    taken.send(()).unwrap();
                    std::thread::sleep(hold);
                })
            };
            held.recv().unwrap();
            let answer = match route {
                "tree head" => tokio::spawn(tree_head(State(st.clone()))),
                _ => tokio::spawn(subject_audit(
                    State(st.clone()),
                    Query(SubjectQuery { handle: "h".into() }),
                )),
            };
            let started = std::time::Instant::now();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            assert!(
                started.elapsed() < hold / 2,
                "{route}: the runtime waited {:?} for the ledger",
                started.elapsed()
            );
            assert_eq!(answer.await.unwrap().status(), StatusCode::OK, "{route}");
            holder.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// One projection runs at a time: the next waits for the turn, holding no thread.
    #[tokio::test]
    async fn a_projection_waits_for_the_one_before_it() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let turn = st.projection.clone().lock_owned().await;
        let answer = tokio::spawn(subject_audit(
            State(st.clone()),
            Query(SubjectQuery { handle: "h".into() }),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!answer.is_finished(), "a projection ran out of turn");
        drop(turn);
        assert_eq!(answer.await.unwrap().status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A read of the whole log keeps its turn until it finishes, even once its request has
    /// given up, so requests that time out cannot pile reads up behind the deadline.
    #[tokio::test]
    async fn an_abandoned_read_of_the_log_keeps_its_turn_until_it_finishes() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        for route in ["tree head", "subject audit"] {
            let (taken, held) = std::sync::mpsc::channel();
            let (let_go, release) = std::sync::mpsc::channel::<()>();
            let holder = {
                let st = st.clone();
                std::thread::spawn(move || {
                    let LedgerBackend::Single(m) = &*st.backend else {
                        panic!("single-file backend expected");
                    };
                    let _held = m.lock().unwrap();
                    taken.send(()).unwrap();
                    release.recv().unwrap();
                })
            };
            held.recv().unwrap();
            let request: std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> =
                match route {
                    "tree head" => Box::pin(tree_head(State(st.clone()))),
                    _ => Box::pin(subject_audit(
                        State(st.clone()),
                        Query(SubjectQuery { handle: "h".into() }),
                    )),
                };
            let gave_up = tokio::time::timeout(std::time::Duration::from_millis(100), request);
            assert!(
                gave_up.await.is_err(),
                "{route}: answered while the ledger was held"
            );
            let turn_is_free = || match route {
                "tree head" => st.tree_head.try_lock().is_ok(),
                _ => st.projection.try_lock().is_ok(),
            };
            assert!(!turn_is_free(), "{route}: the turn went with the request");
            let_go.send(()).unwrap();
            holder.join().unwrap();
            let finished = async {
                while !turn_is_free() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            };
            tokio::time::timeout(std::time::Duration::from_secs(10), finished)
                .await
                .unwrap_or_else(|_| panic!("{route}: the turn was never given back"));
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_self_only_caller_cannot_read_anothers_blast_radius() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let who = crate::caller::Authenticated::new("agent-1", "agent-1", "https://iss.example/")
            .self_only();
        let (status, body) = body_json(
            descendants(
                State(st),
                Some(axum::Extension(who)),
                UrlPath("corp".into()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "caller_mismatch");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_pep_caller_may_read_anothers_blast_radius() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let who = crate::caller::Authenticated::new("gateway-1", "gw", "https://iss.example/");
        let (status, body) = body_json(
            descendants(
                State(st),
                Some(axum::Extension(who)),
                UrlPath("corp".into()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["principal"], "corp");
        let _ = std::fs::remove_dir_all(&base);
    }
}
