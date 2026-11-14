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

/// An id is taken byte for byte and never read as Cedar source. Each case stores two
/// principals in two tenants, each the owner of a resource that carries its own id: the id a
/// request names, and the different id a `uid` that parsed, unescaped, trimmed, cut or
/// normalised the text would make of it. Each principal reads its own resource and neither
/// reads the other's, so neither id is taken for the other, as a principal or as a resource.
#[test]
fn an_id_names_exactly_the_entity_stored_under_it() {
    let cases = [
        // Does not parse as Cedar source; `corp` is who the text tries to become.
        ("x\" || principal == Principal::\"corp", "corp"),
        // Parses as Cedar source, where two backslashes read as one.
        ("a\\\\b", "a\\b"),
        (" a ", "a"),
        ("a\0b", "a"),
        ("e\u{301}", "\u{e9}"),
    ];
    for (named, other) in cases {
        let principal = |id: &str, tenant: &str| {
            json!({ "uid": {"type":"Principal","id":id},
                    "attrs": {"kind":"Human","tenant":tenant,"expiry":32_503_680_000_i64,
                              "scopes":["read"]},
                    "parents": [] })
        };
        let resource = |id: &str, tenant: &str| {
            json!({ "uid": {"type":"Resource","id":id},
                    "attrs": {"owner":{"__entity":{"type":"Principal","id":id}},"tenant":tenant},
                    "parents": [] })
        };
        let mut model = Model::builtin();
        model.entities = json!([
            principal(named, "A"),
            principal(other, "B"),
            resource(named, "A"),
            resource(other, "B"),
        ]);
        let k = Kernel::new(&model).unwrap_or_else(|e| panic!("{named:?} must load: {e}"));
        let reads = |who: &str, what: &str| {
            k.check(&sub(who), "Read", &res(what), &json!({"now": 100}))
                .decision
        };
        assert!(reads(named, named), "{named:?} reads its own");
        assert!(reads(other, other), "{other:?} reads its own");
        assert!(
            !reads(named, other),
            "{named:?} must not read what {other:?} owns"
        );
        assert!(
            !reads(other, named),
            "{other:?} must not read what {named:?} owns"
        );
    }
}
