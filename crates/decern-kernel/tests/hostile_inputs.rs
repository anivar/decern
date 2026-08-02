// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Hostile-input regression tests.
//! Every one of these encodes a bypass or edge that was (or could have been)
//! an escalation path. All must fail CLOSED.

use decern_kernel::{EntityRef, Kernel, KernelError, Model};
use serde_json::json;

fn sub(id: &str) -> EntityRef {
    EntityRef {
        ty: "Principal".into(),
        id: id.into(),
    }
}
fn res(id: &str) -> EntityRef {
    EntityRef {
        ty: "Resource".into(),
        id: id.into(),
    }
}

/// CONFIRMED review finding: a delegator written in Cedar's implicit
/// entity-ref form (no `__entity` escape) used to bypass the attenuation
/// validator while Cedar itself honored the edge. The kernel must refuse
/// to load the escalated graph.
#[test]
fn implicit_delegator_escalation_refused_at_load() {
    let entities = json!([
        { "uid": {"type":"Principal","id":"corp"},
          "attrs": {"kind":"Human","tenant":"A","expiry":100,"scopes":["read"]},
          "parents": [] },
        { "uid": {"type":"Principal","id":"evil"},
          "attrs": {"kind":"Agent","tenant":"A","expiry":999999,
                    "scopes":["read","move_money"],
                    "delegator":{"type":"Principal","id":"corp"}},
          "parents": [] },
        { "uid": {"type":"Resource","id":"claim1"},
          "attrs": {"owner":{"__entity":{"type":"Principal","id":"corp"}},"tenant":"A"},
          "parents": [] }
    ]);
    let mut model = Model::builtin();
    model.entities = entities;
    let err = Kernel::new(&model)
        .err()
        .expect("escalated graph must not load");
    assert!(matches!(err, KernelError::Graph(_)), "{err}");
    let msg = err.to_string();
    assert!(msg.contains("outlives") && msg.contains("exceed"), "{msg}");
}

/// Duplicate uids could let the validator check one set of attrs while the
/// engine enforces another. Refuse.
#[test]
fn duplicate_uid_refused_at_load() {
    let entities = json!([
        { "uid": {"type":"Principal","id":"corp"},
          "attrs": {"kind":"Human","tenant":"A","expiry":100,"scopes":["read"]},
          "parents": [] },
        { "uid": {"type":"Principal","id":"agent"},
          "attrs": {"kind":"Agent","tenant":"A","expiry":100,"scopes":["read"],
                    "delegator":{"__entity":{"type":"Principal","id":"corp"}}},
          "parents": [] },
        { "uid": {"type":"Principal","id":"agent"},
          "attrs": {"kind":"Agent","tenant":"A","expiry":100,
                    "scopes":["read","move_money"],
                    "delegator":{"__entity":{"type":"Principal","id":"corp"}}},
          "parents": [] },
        { "uid": {"type":"Resource","id":"claim1"},
          "attrs": {"owner":{"__entity":{"type":"Principal","id":"corp"}},"tenant":"A"},
          "parents": [] }
    ]);
    let mut model = Model::builtin();
    model.entities = entities;
    assert!(Kernel::new(&model).is_err(), "duplicate uids must not load");
}

/// Malformed clocks: negative, fractional, and out-of-Long-range `now`
/// must all Deny. (now = -1 used to ALLOW — decay is an upper bound only.)
#[test]
fn malformed_now_always_denies() {
    let k = Kernel::new(&Model::builtin()).expect("builtin");
    for now in [
        json!(-1),
        json!(1.5),
        json!(u64::MAX),
        json!("100"),
        json!(null),
    ] {
        let r = k.check(&sub("agent1"), "Read", &res("claim1"), &json!({"now": now}));
        assert!(!r.decision, "now={now} must deny, got ALLOW");
        assert!(!r.errors.is_empty(), "now={now} must carry an error");
    }
    // sanity: the largest VALID clock still evaluates (deny by decay, no error path)
    let r = k.check(
        &sub("agent1"),
        "Read",
        &res("claim1"),
        &json!({"now": i64::MAX}),
    );
    assert!(!r.decision);
}
