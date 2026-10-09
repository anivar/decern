// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The Batch level (C-3): Core and Properties, the semantics, admission over the exchange,
//! and the bounds a batch keeps.

use super::*;

/// C-3-2-1, C-3-2-2, C-3-2-5, C-3-2-6, C-3-3-x: the Batch Core requests, answered in
/// request order with the defaults filled in and no top-level decision.
#[tokio::test]
async fn batch_core_decides_in_request_order_with_defaults_filled_in() {
    let (st, _base) = fixture_state();
    // C-3-2-1: structure.
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "evaluations": [
                { "resource": { "type": "record", "id": "record-1" } },
                { "resource": { "type": "record", "id": "record-2" } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(decisions(&resp).iter().all(Value::is_boolean), "{resp}");
    assert_eq!(decisions(&resp).len(), 2, "{resp}");
    assert!(
        resp.get("decision").is_none(),
        "no top-level decision: {resp}"
    );
    // C-3-2-2: rules 3 and 4, in order.
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "bob" },
            "resource": { "type": "record", "id": "record-1" },
            "evaluations": [{ "action": { "name": "read" } }, { "action": { "name": "write" } }],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(true), json!(false)], "{resp}");
    // C-3-2-5: fully specified items, no defaults.
    let (status, resp) = evaluations(
        &st,
        &json!({
            "evaluations": [
                { "subject": { "type": "user", "id": "alice" }, "action": { "name": "read" },
                  "resource": { "type": "record", "id": "record-1" } },
                { "subject": { "type": "user", "id": "bob" }, "action": { "name": "write" },
                  "resource": { "type": "record", "id": "record-1" } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(true), json!(false)], "{resp}");
    // C-3-2-6: a top-level context, overridden whole by the second item.
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "context": { "time": "2025-06-27T18:03-07:00" },
            "evaluations": [
                { "resource": { "type": "record", "id": "record-1" } },
                { "resource": { "type": "record", "id": "record-2" },
                  "context": { "time": "2025-06-27T19:00-07:00", "source": "batch-override" } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(true), json!(true)], "{resp}");
}

/// C-3-2-3, C-3-2-4, C-3-2-7: properties are evaluated per item, and a key an item carries
/// replaces the top-level default whole.
#[tokio::test]
async fn batch_properties_are_evaluated_per_item() {
    let (st, _base) = fixture_state();
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "write" },
            "evaluations": [
                { "resource": { "type": "record", "id": "record-1", "properties": { "status": "active" } } },
                { "resource": { "type": "record", "id": "record-2", "properties": { "status": "archived" } } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        decisions(&resp),
        [json!(true), json!(false)],
        "C-3-2-3: {resp}"
    );
    let (status, resp) = evaluations(
        &st,
        &json!({
            "action": { "name": "write" },
            "resource": { "type": "record", "id": "record-2", "properties": { "status": "archived" } },
            "evaluations": [
                { "subject": { "type": "user", "id": "alice" } },
                { "subject": { "type": "user", "id": "bob", "properties": { "role": "admin" } } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        decisions(&resp),
        [json!(false), json!(true)],
        "C-3-2-4: {resp}"
    );
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "write" },
            "resource": { "type": "record", "id": "record-1", "properties": { "status": "active" } },
            "evaluations": [
                {},
                { "resource": { "type": "record", "id": "record-2", "properties": { "status": "archived" } } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        decisions(&resp),
        [json!(true), json!(false)],
        "C-3-2-7: {resp}"
    );
}

/// C-3-4-1: under `execute_all`, an item that is not an evaluation is answered
/// `decision: false` with the reason in its context (§7.2.1's shape: `context.error`
/// with the status the single endpoint would have answered), in its place, and nothing is
/// recorded for it — it decided nothing.
#[tokio::test]
async fn a_batch_item_that_is_not_an_evaluation_is_denied_in_place_and_not_recorded() {
    let (st, base) = fixture_state();
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "options": { "evaluations_semantic": "execute_all" },
            "evaluations": [{ "resource": { "type": "record", "id": "record-1" } }, {}],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(true), json!(false)], "{resp}");
    let error = &resp["evaluations"][1]["context"]["error"];
    assert_eq!(error["status"], 400, "{resp}");
    assert_eq!(error["code"], "invalid_request", "{resp}");
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|m| m.contains("resource")),
        "the reason names what is missing: {resp}"
    );
    let records = records_in(&base, &st);
    assert_eq!(
        records.len(),
        1,
        "only the evaluated item is recorded: {records:?}"
    );
    assert_eq!(records[0]["entry"]["resource_id"], "record-1");
}

/// C-3-4-2, C-3-4-3: no items, or an empty array, is the single evaluation — in request
/// and in answer.
#[tokio::test]
async fn a_batch_without_items_is_the_single_evaluation() {
    let (st, _base) = fixture_state();
    for body in [
        json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
        }),
        json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "evaluations": [],
        }),
    ] {
        let (status, resp) = evaluations(&st, &body).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        assert_eq!(resp["decision"], true, "{resp}");
        assert!(resp.get("evaluations").is_none(), "{resp}");
    }
    // And a single evaluation that is not one is 400, as on the single endpoint.
    let (status, resp) = evaluations(
        &st,
        &json!({ "subject": { "type": "user", "id": "alice" }, "action": { "name": "read" } }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert!(
        resp["detail"]
            .as_str()
            .is_some_and(|d| d.contains("resource") && !d.contains("evaluations[")),
        "a batch without items names no item: {resp}"
    );
}

/// §7.1.2.1: `deny_on_first_deny` stops at the first deny, `permit_on_first_permit` at
/// the first permit, `execute_all` at the end; a semantic this server does not know is
/// refused rather than executed as another.
#[tokio::test]
async fn batch_semantics_stop_where_the_specification_says() {
    let (st, base) = fixture_state();
    let items = json!([
        { "subject": { "type": "user", "id": "alice" }, "action": { "name": "read" } },
        { "subject": { "type": "user", "id": "bob" }, "action": { "name": "write" } },
        { "subject": { "type": "user", "id": "alice" }, "action": { "name": "write" } },
    ]);
    for (semantic, expect) in [
        ("execute_all", vec![true, false, true]),
        ("deny_on_first_deny", vec![true, false]),
        ("permit_on_first_permit", vec![true]),
    ] {
        let (status, resp) = evaluations(
            &st,
            &json!({
                "resource": { "type": "record", "id": "record-1" },
                "options": { "evaluations_semantic": semantic },
                "evaluations": items,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{semantic}: {resp}");
        assert_eq!(
            decisions(&resp),
            expect.iter().map(|d| json!(d)).collect::<Vec<_>>(),
            "{semantic}: {resp}"
        );
    }
    // Every evaluated item, and only those, is on the record: 3 + 2 + 1.
    assert_eq!(records_in(&base, &st).len(), 6);
    let (status, resp) = evaluations(
        &st,
        &json!({
            "resource": { "type": "record", "id": "record-1" },
            "options": { "evaluations_semantic": "first_come_first_served" },
            "evaluations": items,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert_eq!(resp["error"], "invalid_request");
}

/// Admission is for the whole exchange and comes first: a caller bound to itself that
/// names another principal in any item is refused before anything is evaluated or
/// recorded.
#[tokio::test]
async fn a_batch_is_refused_whole_when_one_item_is_not_the_callers_to_ask() {
    let (st, base) = fixture_state();
    let req: crate::batch::BatchReq = serde_json::from_value(json!({
        "action": { "name": "read" },
        "resource": { "type": "record", "id": "record-1" },
        "evaluations": [
            { "subject": { "type": "user", "id": "bob" } },
            { "subject": { "type": "user", "id": "alice" } },
        ],
    }))
    .unwrap();
    let workload =
        crate::caller::Authenticated::new("bob", "bob", "https://iss.example/").self_only();
    let (status, resp) = body_json(
        crate::batch::evaluations(
            State(st.clone()),
            Some(axum::Extension(workload)),
            Ok(Json(req)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(resp["error"], "caller_mismatch");
    assert!(records_in(&base, &st).is_empty(), "nothing was recorded");

    // An item that is not an evaluation still names whom it names: the refusal does not
    // hide behind a malformed item's per-item deny.
    let req: crate::batch::BatchReq = serde_json::from_value(json!({
        "action": { "name": "read" },
        "evaluations": [
            { "subject": { "type": "user", "id": "bob" },
              "resource": { "type": "record", "id": "record-1" } },
            { "subject": { "type": "user", "id": "alice" } },
        ],
    }))
    .unwrap();
    let workload =
        crate::caller::Authenticated::new("bob", "bob", "https://iss.example/").self_only();
    let (status, resp) = body_json(
        crate::batch::evaluations(
            State(st.clone()),
            Some(axum::Extension(workload)),
            Ok(Json(req)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(records_in(&base, &st).is_empty(), "nothing was recorded");
}

/// A bounded exchange: one over the cap is refused with the cap named.
#[tokio::test]
async fn a_batch_over_the_cap_is_refused() {
    let (st, _base) = fixture_state();
    let items: Vec<Value> = (0..=crate::batch::MAX_EVALUATIONS)
        .map(|_| json!({ "resource": { "type": "record", "id": "record-1" } }))
        .collect();
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "evaluations": items,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert!(
        resp["detail"]
            .as_str()
            .is_some_and(|d| d.contains(&crate::batch::MAX_EVALUATIONS.to_string())),
        "{resp}"
    );
}

/// A refusal this server would answer 422 on the single endpoint — here, a decision
/// subject that identifies a person — is carried inside the item that earned it, as that
/// item's deny with `context.error` carrying the status and code, and the item is not
/// recorded; the rest of the exchange is unaffected, and `deny_on_first_deny` treats it as
/// the deny it is.
#[tokio::test]
async fn a_refusal_inside_a_batch_item_is_that_items_deny_and_records_nothing_for_it() {
    let (st, base) = fixture_state();
    let body = json!({
        "subject": { "type": "user", "id": "alice" },
        "action": { "name": "read" },
        "resource": { "type": "record", "id": "record-1" },
        "evaluations": [
            {},
            { "context": { "decision_subject": "carol@example.com" } },
            {},
        ],
    });
    let (status, resp) = evaluations(&st, &body).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        decisions(&resp),
        [json!(true), json!(false), json!(true)],
        "{resp}"
    );
    let error = &resp["evaluations"][1]["context"]["error"];
    assert_eq!(error["status"], 422, "{resp}");
    assert_eq!(error["code"], "decision_subject", "{resp}");
    let records = records_in(&base, &st);
    assert_eq!(
        records.len(),
        2,
        "the refused item decided nothing: {records:?}"
    );
    assert!(
        !records
            .iter()
            .any(|r| r.to_string().contains("carol@example.com")),
        "a refused handle never reaches the ledger"
    );

    let mut short = body.clone();
    short["options"] = json!({ "evaluations_semantic": "deny_on_first_deny" });
    let (status, resp) = evaluations(&st, &short).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(true), json!(false)], "{resp}");
}

/// A context larger than one evaluation may carry is refused before it is evaluated or
/// recorded — 413 on the single endpoint, that item's answer in a batch — and a batch
/// whose default context is too large does not copy it into every item to find out; an
/// item that brings its own context is judged on that.
#[tokio::test]
async fn an_oversize_context_is_refused_before_it_is_evaluated_or_recorded() {
    let (st, base) = fixture_state();
    let pad = "x".repeat(crate::decide::MAX_CONTEXT_BYTES + 1);
    let (status, resp) = decision(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "context": { "pad": pad },
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{resp}");
    assert_eq!(resp["error"], "context_too_large");
    assert!(records_in(&base, &st).is_empty(), "nothing recorded");

    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "context": { "pad": pad },
            "evaluations": [{}, { "context": { "small": true } }],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(false), json!(true)], "{resp}");
    assert_eq!(
        resp["evaluations"][0]["context"]["error"]["status"], 413,
        "{resp}"
    );
    assert_eq!(
        records_in(&base, &st).len(),
        1,
        "only the decided item is recorded"
    );

    // The same for a party whose default `properties` are that large: the item that
    // inherits it is answered without the copy, the item that brings its own is decided.
    let (status, resp) = evaluations(
        &st,
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1", "properties": { "pad": pad } },
            "evaluations": [
                {},
                { "resource": { "type": "record", "id": "record-1", "properties": {} } },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(decisions(&resp), [json!(false), json!(true)], "{resp}");
    assert_eq!(
        resp["evaluations"][0]["context"]["error"]["status"], 413,
        "{resp}"
    );
    assert_eq!(
        records_in(&base, &st).len(),
        2,
        "one more decided item is recorded"
    );
}
