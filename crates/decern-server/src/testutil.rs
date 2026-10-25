// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Shared fixtures for the server's unit tests.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::response::Response;
use decern_kernel::{Directory, Kernel, Model};
use decern_ledger::Ledger;
use decern_store::{FileMissionRegistry, MissionEntry, MissionRegistry};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};

use crate::mission::MissionApproveReq;
use crate::{AppState, LedgerBackend, caller_disclosure};

/// The posture every pre-existing test runs under: the caller is taken on trust, which is
/// what those tests are about. The guard's own behaviour is tested separately, below.
pub(crate) fn open() -> Arc<crate::caller::Caller> {
    Arc::new(crate::caller::Caller::TrustedProxy)
}

/// A small directory with a real 3-hop chain a <- b <- c, a standalone
/// self-root `solo`, and (implicitly) ids absent from it entirely.
pub(crate) fn test_dir() -> Directory {
    let principal = |id: &str, delegator: Option<&str>| {
        let mut attrs = json!({
            "kind": "Agent", "tenant": "A", "expiry": 1000, "scopes": ["read"],
        });
        if let Some(d) = delegator {
            attrs["delegator"] = json!({"__entity": {"type": "Principal", "id": d}});
        }
        json!({"uid": {"type": "Principal", "id": id}, "attrs": attrs, "parents": []})
    };
    let ents = json!([
        principal("a", None),
        principal("b", Some("a")),
        principal("c", Some("b")),
        principal("solo", None),
    ]);
    let dir = Directory::parse(&ents).unwrap();
    assert!(dir.validate().is_empty(), "fixture must be well-formed");
    dir
}

pub(crate) fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

// ============================ Mission service ============================

/// A throwaway durable mission registry for a test that needs an `AppState` but
/// does not exercise missions (its own temp file, cleaned by the OS).
pub(crate) fn test_missions() -> Arc<FileMissionRegistry> {
    let path = std::env::temp_dir().join(format!(
        "decern-serve-missions-{}-{}.json",
        std::process::id(),
        now_nanos()
    ));
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(path.with_extension("lock")).ok();
    Arc::new(FileMissionRegistry::open(&path).unwrap())
}

/// A fresh temp directory to hold a test's ledger + mission registry together.
pub(crate) fn mission_base() -> PathBuf {
    // A per-call atomic sequence guarantees a UNIQUE directory even when two parallel
    // mission tests hit the same wall-clock nanosecond — a shared dir would mean a
    // shared ledger file, whose interleaved appends would break the hash chain and
    // fail an unrelated test's `Ledger::open`.
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let base = std::env::temp_dir().join(format!(
        "decern-serve-mission-{}-{}-{}",
        std::process::id(),
        now_nanos(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

/// A single-file-ledger `AppState` whose ledger and mission registry both live under
/// `base`. Reopening the same `base` yields FRESH durable handles (nothing carried in
/// memory), which is exactly what the durability test needs. The signing seed is fixed
/// so a reopened ledger's existing records still verify under the returned key.
pub(crate) fn mission_state_at(base: &Path) -> (AppState, VerifyingKey) {
    mission_state_with(base, Model::builtin())
}

/// [`mission_state_at`] over `model` instead of the builtin.
pub(crate) fn mission_state_with(base: &Path, model: Model) -> (AppState, VerifyingKey) {
    let ledger_path = base.join("decern-ledger.jsonl");
    let missions_path = base.join("decern-missions.json");
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = key.verifying_key();
    let mut ledger = Ledger::open(&ledger_path, key).unwrap();
    ledger.set_sync(true);
    let st = AppState {
        kernel: Arc::new(Kernel::new(&model).unwrap()),
        model: Arc::new(model),
        backend: Arc::new(LedgerBackend::Single(Mutex::new(ledger))),
        missions: Arc::new(FileMissionRegistry::open(&missions_path).unwrap()),
        pubkey,
        retired_keys: Arc::new(Vec::new()),
        clock: crate::now_secs,
        tree_head: Arc::default(),
        projection: Arc::default(),
        require_mission: false,
        standing_issuers: Arc::new(Vec::new()),
        authority_digest: Arc::from("test-authority"),
        caller_disclosure: Arc::new(caller_disclosure(&crate::caller::Caller::TrustedProxy)),
        type_aliases: Arc::new(std::collections::BTreeMap::new()),
        public_url: None,
    };
    (st, pubkey)
}

pub(crate) async fn body_json(resp: Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, v)
}

/// `corp`'s authority expiry — the attenuation ceiling for a mission it approves.
/// Read from the model (32503680000, far past wall clock) rather than hardcoded, so
/// an approved mission is never GC'd out from under a test by the registry's
/// evict-past-`now` sweep.
pub(crate) fn corp_expiry() -> u64 {
    decern_identity::exchange::delegator_attrs(&Model::builtin(), "corp")
        .unwrap()
        .1
}

/// The builtin model with `agent1` given `corp`'s expiry, so a decision about it is not
/// decayed: the builtin has no other live principal in tenant A holding `move_money`
/// besides `corp`, which may not approve a Mission for itself.
pub(crate) fn live_agent1_model() -> Model {
    let mut model = Model::builtin();
    let expiry = corp_expiry();
    for e in model.entities.as_array_mut().unwrap() {
        if e["uid"]["id"] == "agent1" {
            e["attrs"]["expiry"] = json!(expiry);
        }
    }
    model
}

pub(crate) fn approve_req(tools: &[&str], expiry: u64) -> MissionApproveReq {
    MissionApproveReq {
        approver: "corp".into(),
        agent: "agent1".into(),
        description: "reconcile invoices".into(),
        approved_tools: tools.iter().map(|s| s.to_string()).collect(),
        capabilities: vec![],
        expiry,
    }
}

/// Whether a decision's `context.errors` has an entry containing `needle`.
pub(crate) fn has_error(body: &Value, needle: &str) -> bool {
    body["context"]["errors"].as_array().is_some_and(|errors| {
        errors
            .iter()
            .any(|e| e.as_str().is_some_and(|e| e.contains(needle)))
    })
}

/// Put `entry` in the registry under `s256` without going through `approve`, as a
/// registry written by an earlier release can hold it, then decide `action` on `claim1`
/// for `subject`, naming that Mission.
pub(crate) async fn decide_under_registered_mission(
    st: &AppState,
    s256: &str,
    entry: MissionEntry,
    subject: &str,
    action: &str,
) -> (StatusCode, Value) {
    let approver = entry.approver.clone();
    st.missions
        .register(s256, entry, crate::now_secs().unwrap())
        .unwrap();
    let req: crate::decide::DecideReq = serde_json::from_value(json!({
        "subject": {"type": "Principal", "id": subject},
        "action": {"name": action},
        "resource": {"type": "Resource", "id": "claim1"},
        "context": {"mission": {"approver": approver, "s256": s256}},
    }))
    .unwrap();
    body_json(
        crate::decide::decide(axum::extract::State(st.clone()), None, Ok(axum::Json(req))).await,
    )
    .await
}
