// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The Search level (C-4): Core and Properties over the three endpoints, pagination
//! parameters accepted, empty results, the errors, admission, and what a search records.

use super::*;

/// `POST /access/v1/search/{which}` with a JSON body, under `--trust-proxy`.
async fn search(st: &AppState, which: &str, body: &Value) -> (StatusCode, Value) {
    let resp = app(st.clone(), open())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/access/v1/search/{which}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(resp).await
}

/// The ids (or action names) a search answered with.
fn found(resp: &Value) -> Vec<String> {
    resp["results"]
        .as_array()
        .unwrap_or_else(|| panic!("results array: {resp}"))
        .iter()
        .map(|e| {
            e["id"]
                .as_str()
                .or_else(|| e["name"].as_str())
                .unwrap_or_else(|| panic!("an id or a name: {e}"))
                .to_owned()
        })
        .collect()
}

fn has(resp: &Value, id: &str) -> bool {
    found(resp).iter().any(|f| f == id)
}

/// C-4-2-1, C-4-2-2, C-4-2-3 (S1): a subject search for `read` on `record-1` finds alice
/// and bob, in the request's type spelling; a context changes nothing; a `subject.id`
/// is ignored, so bob is still found when alice's id was sent.
#[tokio::test]
async fn subject_search_finds_alice_and_bob_and_ignores_context_and_a_subject_id() {
    let (st, _base) = fixture_state();
    let base = json!({
        "subject": { "type": "user" },
        "action": { "name": "read" },
        "resource": { "type": "record", "id": "record-1" },
    });
    let (status, resp) = search(&st, "subject", &base).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has(&resp, "alice") && has(&resp, "bob"), "{resp}");
    assert!(
        resp["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["type"] == "user"),
        "{resp}"
    );
    let core = found(&resp);

    let mut with_context = base.clone();
    with_context["context"] = json!({ "time": "2025-06-27T18:03-07:00", "ip": "192.168.1.1" });
    let (status, resp) = search(&st, "subject", &with_context).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(found(&resp), core, "C-4-2-2: {resp}");

    let mut with_id = base.clone();
    with_id["subject"]["id"] = json!("alice");
    let (status, resp) = search(&st, "subject", &with_id).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(found(&resp), core, "C-4-2-3: {resp}");
}

/// C-4-2-4 (S4): who may `write` the archived `record-2` — bob, an admin on the
/// authority's side and a viewer of the record; not alice, its owner.
#[tokio::test]
async fn subject_search_with_resource_properties_finds_the_admin() {
    let (st, _base) = fixture_state();
    let (status, resp) = search(
        &st,
        "subject",
        &json!({
            "subject": { "type": "user" },
            "action": { "name": "write" },
            "resource": { "type": "record", "id": "record-2", "properties": { "status": "archived" } },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has(&resp, "bob") && !has(&resp, "alice"), "{resp}");
}

/// C-4-3-1, C-4-3-2, C-4-3-3 (S2): what alice may `read` includes `record-1`; a context
/// changes nothing; a `resource.id` is ignored and does not narrow the results.
#[tokio::test]
async fn resource_search_finds_record_one_and_ignores_context_and_a_resource_id() {
    let (st, _base) = fixture_state();
    let base = json!({
        "subject": { "type": "user", "id": "alice" },
        "action": { "name": "read" },
        "resource": { "type": "record" },
    });
    let (status, resp) = search(&st, "resource", &base).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has(&resp, "record-1") && has(&resp, "record-2"), "{resp}");
    assert!(
        resp["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["type"] == "record"),
        "{resp}"
    );
    let core = found(&resp);

    let mut with_context = base.clone();
    with_context["context"] = json!({ "time": "2025-06-27T18:03-07:00", "ip": "192.168.1.1" });
    assert_eq!(found(&search(&st, "resource", &with_context).await.1), core);

    let mut with_id = base.clone();
    with_id["resource"]["id"] = json!("record-1");
    assert_eq!(
        found(&search(&st, "resource", &with_id).await.1),
        core,
        "C-4-3-3"
    );
}

/// C-4-3-4 (S5): what bob, described as an admin, may `write` includes the archived
/// `record-2` and not the active `record-1`.
#[tokio::test]
async fn resource_search_with_subject_properties_finds_the_archived_record() {
    let (st, _base) = fixture_state();
    let (status, resp) = search(
        &st,
        "resource",
        &json!({
            "subject": { "type": "user", "id": "bob", "properties": { "role": "admin" } },
            "action": { "name": "write" },
            "resource": { "type": "record" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has(&resp, "record-2") && !has(&resp, "record-1"), "{resp}");
}

/// C-4-4-1, C-4-4-2 (S3): what alice may do to `record-1` includes `read` and `write`
/// (not `delete`: nothing said it was soft); a context changes nothing.
#[tokio::test]
async fn action_search_finds_read_and_write_and_ignores_context() {
    let (st, _base) = fixture_state();
    let base = json!({
        "subject": { "type": "user", "id": "alice" },
        "resource": { "type": "record", "id": "record-1" },
    });
    let (status, resp) = search(&st, "action", &base).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(
        has(&resp, "read") && has(&resp, "write") && !has(&resp, "delete"),
        "{resp}"
    );
    assert!(
        resp["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["name"].is_string()),
        "{resp}"
    );
    let core = found(&resp);
    let mut with_context = base.clone();
    with_context["context"] = json!({ "time": "2025-06-27T18:03-07:00", "ip": "192.168.1.1" });
    assert_eq!(found(&search(&st, "action", &with_context).await.1), core);
}

/// C-4-4-3 (S6): what bob, described as an admin, may do to the archived `record-2`
/// includes `write`.
#[tokio::test]
async fn action_search_with_properties_finds_write() {
    let (st, _base) = fixture_state();
    let (status, resp) = search(
        &st,
        "action",
        &json!({
            "subject": { "type": "user", "id": "bob", "properties": { "role": "admin" } },
            "resource": { "type": "record", "id": "record-2", "properties": { "status": "archived" } },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has(&resp, "write"), "{resp}");
}

/// C-4-5-1, C-4-5-4: a `page` with a limit is accepted, every result comes in one page
/// and no `page` is claimed in the answer; a token this server never issued is 400.
#[tokio::test]
async fn pagination_parameters_are_accepted_and_every_result_comes_in_one_page() {
    let (st, _base) = fixture_state();
    let (status, resp) = search(
        &st,
        "subject",
        &json!({
            "subject": { "type": "user" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "page": { "limit": 1 },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(
        has(&resp, "alice") && has(&resp, "bob"),
        "every result: {resp}"
    );
    assert!(
        resp.get("page").is_none_or(|p| p["next_token"] == ""),
        "no page, or an empty token: {resp}"
    );
    let (status, resp) = search(
        &st,
        "subject",
        &json!({
            "subject": { "type": "user" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "page": { "token": "not-ours" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
}

/// C-4-6-1, C-4-6-2: an unknown identifier, or a type the model does not know, is an
/// empty result and not an error — on every endpoint.
#[tokio::test]
async fn an_unknown_id_or_type_is_an_empty_result_not_an_error() {
    let (st, _base) = fixture_state();
    for (which, body) in [
        (
            "action",
            json!({ "subject": { "type": "user", "id": "nonexistent-user" },
                    "resource": { "type": "record", "id": "record-1" } }),
        ),
        (
            "subject",
            json!({ "subject": { "type": "spaceship" }, "action": { "name": "read" },
                    "resource": { "type": "record", "id": "record-1" } }),
        ),
        (
            "resource",
            json!({ "subject": { "type": "user", "id": "alice" }, "action": { "name": "read" },
                    "resource": { "type": "spaceship" } }),
        ),
        (
            "subject",
            json!({ "subject": { "type": "user" }, "action": { "name": "read" },
                    "resource": { "type": "record", "id": "no-such-record" } }),
        ),
    ] {
        let (status, resp) = search(&st, which, &body).await;
        assert_eq!(status, StatusCode::OK, "{which}: {resp}");
        assert_eq!(resp["results"], json!([]), "{which}: {resp}");
    }
}

/// C-4-7-1, C-4-7-2: a search missing what its kind requires is 400 — the fields, and
/// the ids of its input parties.
#[tokio::test]
async fn a_search_missing_what_its_kind_requires_is_400() {
    let (st, _base) = fixture_state();
    for (which, body) in [
        (
            "subject",
            json!({ "subject": { "type": "user" },
                    "resource": { "type": "record", "id": "record-1" } }),
        ),
        (
            "resource",
            json!({ "action": { "name": "read" }, "resource": { "type": "record" } }),
        ),
        (
            "action",
            json!({ "subject": { "type": "user", "id": "alice" } }),
        ),
        (
            "subject",
            json!({ "subject": { "type": "user" }, "action": { "name": "read" },
                    "resource": { "type": "record" } }),
        ),
        (
            "resource",
            json!({ "subject": { "type": "user" }, "action": { "name": "read" },
                    "resource": { "type": "record" } }),
        ),
        (
            "action",
            json!({ "subject": { "type": "user" },
                    "resource": { "type": "record", "id": "record-1" } }),
        ),
    ] {
        let (status, resp) = search(&st, which, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{which} {body}: {resp}");
    }
}

/// A caller bound to itself may search for what it may do, and for nothing about
/// others: a subject search names everyone, a resource or action search for another
/// principal names them, and describing a party is a PEP's act.
#[tokio::test]
async fn a_caller_bound_to_itself_may_search_only_for_itself() {
    let (st, base) = fixture_state();
    let workload =
        || crate::caller::Authenticated::new("bob", "bob", "https://iss.example/").self_only();
    let parse = |v: Value| serde_json::from_value::<crate::search::SearchReq>(v).unwrap();

    let (status, resp) = body_json(
        crate::search::search_subject(
            State(st.clone()),
            Some(axum::Extension(workload())),
            Ok(Json(parse(json!({
                "subject": { "type": "user" }, "action": { "name": "read" },
                "resource": { "type": "record", "id": "record-1" },
            })))),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(resp["error"], "caller_mismatch");

    let (status, resp) = body_json(
        crate::search::search_resource(
            State(st.clone()),
            Some(axum::Extension(workload())),
            Ok(Json(parse(json!({
                "subject": { "type": "user", "id": "alice" },
                "action": { "name": "read" }, "resource": { "type": "record" },
            })))),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "another principal: {resp}");

    let (status, resp) = body_json(
        crate::search::search_action(
            State(st.clone()),
            Some(axum::Extension(workload())),
            Ok(Json(parse(json!({
                "subject": { "type": "user", "id": "bob" },
                "resource": { "type": "record", "id": "record-1" },
            })))),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "itself: {resp}");
    assert!(has(&resp, "read"), "{resp}");

    let (status, resp) = body_json(
        crate::search::search_action(
            State(st.clone()),
            Some(axum::Extension(workload())),
            Ok(Json(parse(json!({
                "subject": { "type": "user", "id": "bob", "properties": { "role": "admin" } },
                "resource": { "type": "record", "id": "record-2" },
            })))),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "describing itself: {resp}");
    assert_eq!(
        records_in(&base, &st).len(),
        1,
        "only the admitted search was recorded"
    );
}

/// A search binds no Mission: under `--require-mission`, or with a `context.mission`, it
/// is refused — the caller wanted a decision, and this endpoint makes none.
#[tokio::test]
async fn a_search_does_not_run_under_a_mission() {
    let (mut st, _base) = fixture_state();
    let body = json!({
        "subject": { "type": "user", "id": "alice" },
        "action": { "name": "read" },
        "resource": { "type": "record" },
    });
    let mut named = body.clone();
    named["context"] = json!({ "mission": { "approver": "alice", "s256": "x" } });
    let (status, resp) = search(&st, "resource", &named).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{resp}");
    assert_eq!(resp["error"], "search_under_mission");

    st.require_mission = true;
    let (status, resp) = search(&st, "resource", &body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{resp}");
    assert_eq!(resp["error"], "search_under_mission");
}

/// Each search is recorded once, as the search it was: the parties in the model's terms
/// (the searched side with no id), what came back and how many, under `Search.*`; a
/// decision subject sent along is not recorded, since nothing was decided about anyone.
#[tokio::test]
async fn each_search_is_recorded_once_with_what_came_back() {
    let (st, base) = fixture_state();
    let (status, resp) = search(
        &st,
        "subject",
        &json!({
            "subject": { "type": "user" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "context": { "decision_subject": "ppid:someone", "ip": "192.168.1.1" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let records = records_in(&base, &st);
    assert_eq!(records.len(), 1, "{records:?}");
    let entry = &records[0]["entry"];
    assert_eq!(entry["action"], "Search.Subject");
    assert_eq!(entry["subject_type"], "Principal");
    assert_eq!(entry["subject_id"], "");
    assert_eq!(entry["resource_id"], "record-1");
    assert_eq!(entry["context"]["search"]["for"], "subject");
    assert_eq!(entry["context"]["search"]["action"], "read");
    assert_eq!(entry["context"]["search"]["count"], 2);
    let recorded: Vec<&str> = entry["context"]["search"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(recorded, ["alice", "bob"]);
    assert!(
        entry["context"].get("decision_subject").is_none(),
        "{entry}"
    );
    assert!(entry["context"].get("ip").is_none(), "pruned: {entry}");
    assert!(entry.get("decision_subject").is_none(), "{entry}");
}

/// An action search decides every action over the context, so its record carries what
/// any action declares and nothing more: a declared description stays, an undeclared one
/// and an undeclared attribute go — as on a decision's record.
#[tokio::test]
async fn an_action_search_records_only_what_some_action_declares() {
    let (st, base) = fixture_state();
    let (status, resp) = search(
        &st,
        "action",
        &json!({
            "subject": { "type": "user", "id": "bob",
                         "properties": { "role": "admin", "email": "bob@corp.example" } },
            "resource": { "type": "record", "id": "record-2",
                          "properties": { "status": "archived", "owner": "alice" } },
            "context": { "ip": "192.168.1.1", "time": "2025-06-27T18:03-07:00" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has(&resp, "write"), "{resp}");
    let records = records_in(&base, &st);
    let ctx = &records.last().expect("recorded")["entry"]["context"];
    assert_eq!(ctx["subject"], json!({ "role": "admin" }), "{ctx}");
    assert_eq!(ctx["resource"], json!({ "status": "archived" }), "{ctx}");
    for absent in ["ip", "time"] {
        assert!(ctx.get(absent).is_none(), "{absent} is undeclared: {ctx}");
    }
}

/// An action the model does not declare declares no context: the search finds nothing,
/// and its record carries the clock and nothing the caller sent.
#[tokio::test]
async fn an_unknown_action_finds_nothing_and_records_only_the_clock() {
    let (st, base) = fixture_state();
    let (status, resp) = search(
        &st,
        "subject",
        &json!({
            "subject": { "type": "user" },
            "action": { "name": "fly" },
            "resource": { "type": "record", "id": "record-1" },
            "context": { "ip": "192.168.1.1", "consent": true },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["results"], json!([]), "{resp}");
    let records = records_in(&base, &st);
    let ctx = &records.last().expect("recorded")["entry"]["context"];
    let keys: Vec<&String> = ctx.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["now", "search"], "{ctx}");
}

/// The searched side's id is ignored all the way down: it reaches neither the decision
/// nor the record, which names no subject (or no resource) and no sponsor.
#[tokio::test]
async fn the_searched_side_id_reaches_neither_the_decision_nor_the_record() {
    let (st, base) = fixture_state();
    let (status, resp) = search(
        &st,
        "subject",
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has(&resp, "bob"), "{resp}");
    let (status, resp) = search(
        &st,
        "resource",
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has(&resp, "record-2"), "{resp}");
    let records = records_in(&base, &st);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["entry"]["subject_id"], "", "{}", records[0]);
    assert!(
        records[0]["entry"].get("sponsor").is_none(),
        "{}",
        records[0]
    );
    assert_eq!(records[1]["entry"]["resource_id"], "", "{}", records[1]);
    assert_eq!(records[1]["entry"]["subject_id"], "alice", "{}", records[1]);
}

/// An action search carries no `action` (§8.6.1): one sent is 400, not an input whose
/// name is ignored and whose properties are not.
#[tokio::test]
async fn an_action_in_an_action_search_is_400() {
    let (st, _base) = fixture_state();
    let (status, resp) = search(
        &st,
        "action",
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "resource": { "type": "record", "id": "record-1" },
            "action": { "name": "read", "properties": { "soft": true } },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
}

/// A `mission` that is null names no Mission, as it names none on an evaluation.
#[tokio::test]
async fn a_null_mission_is_no_mission() {
    let (st, _base) = fixture_state();
    let (status, resp) = search(
        &st,
        "resource",
        &json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record" },
            "context": { "mission": null },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has(&resp, "record-1"), "{resp}");
}
