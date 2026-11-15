// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! AuthZEN 1.0 Access Evaluations (§7): several evaluations in one exchange. Each one is
//! a decision of its own — admitted, evaluated and recorded exactly as a single one is —
//! and the exchange adds only the defaults, the order and the stopping rule.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use decern_ledger::Entry;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::decide::{
    CONTEXT_TOO_LARGE, DecideReq, Refusal, admit, admit_named, context_too_large, decide_one,
    evaluate_one,
};
use crate::record::{Shard, evaluation_body, not_recorded, record_decision, record_decisions};

/// The most evaluations one exchange may carry. Each is a recorded decision, so a batch
/// is bounded the way a single request's body is, and says so rather than timing out.
pub(crate) const MAX_EVALUATIONS: usize = 1000;

/// The most one exchange may put on the ledger, measured as the JSON each item decides on.
/// Every item repeats the defaults it does not override, so without this a request could
/// record a thousand times its own size.
pub(crate) const MAX_RECORDED_BYTES: usize = 16 * 1024 * 1024;

/// The fields an item inherits from the top level when it does not name its own.
const KEYS: [&str; 4] = ["subject", "action", "resource", "context"];

fn json_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// What `items` would put on the ledger: each item's own fields, and each default it
/// inherits, except a default too large to evaluate, which the item is refused for.
fn recorded_bytes(top: &BatchReq, items: &[Value], oversize_default: [bool; 4]) -> usize {
    let defaults = KEYS.map(|key| top.default_for(key).map_or(0, json_len));
    items
        .iter()
        .map(|item| {
            KEYS.iter()
                .enumerate()
                .map(|(i, key)| match item.get(*key) {
                    Some(own) => json_len(own),
                    None if oversize_default[i] => 0,
                    None => defaults[i],
                })
                .fold(0usize, usize::saturating_add)
        })
        .fold(0usize, usize::saturating_add)
}

/// §7.1: top-level `subject`, `action`, `resource` and `context` are defaults for every
/// item of `evaluations`; an item's own key replaces the default whole. Each top-level
/// field is kept as it arrived, since an item may supply its own and never use it.
#[derive(Deserialize)]
#[serde(remote = "Self")]
pub(crate) struct BatchReq {
    #[serde(default)]
    subject: Option<Value>,
    #[serde(default)]
    action: Option<Value>,
    #[serde(default)]
    resource: Option<Value>,
    #[serde(default)]
    context: Option<Value>,
    #[serde(default)]
    evaluations: Option<Vec<Value>>,
    #[serde(default)]
    options: Option<Options>,
}

impl BatchReq {
    /// The top-level default for `key`.
    fn default_for(&self, key: &str) -> Option<&Value> {
        match key {
            "subject" => self.subject.as_ref(),
            "action" => self.action.as_ref(),
            "resource" => self.resource.as_ref(),
            "context" => self.context.as_ref(),
            _ => None,
        }
    }
}

/// §7.1.2: PEP-supplied metadata on how to execute. Only the semantic is read; any other
/// option is ignored, as the specification allows.
#[derive(Deserialize, Default)]
#[serde(remote = "Self")]
struct Options {
    #[serde(default)]
    evaluations_semantic: Option<String>,
}

// As a single evaluation's: the request and its options are objects (§7.1, §7.1.2).
crate::object::object_only!(Options, BatchReq);

/// §7.1.2.1: when the exchange stops.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Semantic {
    ExecuteAll,
    DenyOnFirstDeny,
    PermitOnFirstPermit,
}

impl Semantic {
    fn parse(name: Option<&str>) -> Result<Self, String> {
        match name {
            None | Some("execute_all") => Ok(Semantic::ExecuteAll),
            Some("deny_on_first_deny") => Ok(Semantic::DenyOnFirstDeny),
            Some("permit_on_first_permit") => Ok(Semantic::PermitOnFirstPermit),
            Some(other) => Err(format!(
                "options.evaluations_semantic {other:?} is not one of execute_all, \
                 deny_on_first_deny, permit_on_first_permit"
            )),
        }
    }
}

fn invalid_request(detail: impl Into<String>) -> Response {
    Refusal::invalid_request(detail).into_response()
}

/// The value `key` has for `item`: the item's own, or the top-level default behind it.
/// Borrowed: a default is not copied into an item to read it, only to decide it.
fn field<'a>(
    top: &'a BatchReq,
    item: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Option<&'a Value> {
    item.get(key).or_else(|| top.default_for(key))
}

/// What admission needs to know about an item that will not be decided, read in place: whom
/// it names, whether it describes a party through `properties`, whether it asserts consent
/// or approval, and whom it names as the decision subject. An item that will be decided is
/// admitted off the parsed request instead, by [`admit`].
/// An item that is not an object names nobody, and is answered for what it is when its
/// turn comes. The same four facts [`DecideReq::facts`] reads off a parsed request, which
/// a test holds them to for every item that is an evaluation.
fn facts<'a>(top: &'a BatchReq, item: &'a Value) -> (Option<&'a str>, bool, bool, Option<&'a str>) {
    let Some(item) = item.as_object() else {
        return (None, false, false, None);
    };
    let subject_id = field(top, item, "subject")
        .and_then(|s| s.get("id"))
        .and_then(Value::as_str);
    let describes = ["subject", "resource", "action"].iter().any(|key| {
        field(top, item, key)
            .and_then(|party| party.get("properties"))
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty())
    });
    let context = field(top, item, "context");
    let asserts = context
        .and_then(Value::as_object)
        .is_some_and(crate::decide::asserts_approval);
    let decision_subject =
        crate::decide::named_decision_subject(context.and_then(|c| c.get("decision_subject")));
    (subject_id, describes, asserts, decision_subject)
}

/// Item `i` with the defaults filled in, as the request one evaluation would be — or what
/// keeps it from being one. A key the item carries replaces the default whole (§7.1.1).
/// Built one item at a time, so one copy of the defaults is alive at once. `i` names the
/// item in an error; a batch without items has no item to name.
fn merged(top: &BatchReq, i: Option<usize>, item: &Value) -> Result<DecideReq, String> {
    let at = |what: &str| match i {
        Some(i) => format!("evaluations[{i}]{what}"),
        None => what.trim_start_matches(": ").to_owned(),
    };
    let Some(item) = item.as_object() else {
        return Err(at(" is not an object"));
    };
    let mut merged = serde_json::Map::new();
    for key in ["subject", "action", "resource", "context"] {
        if let Some(v) = field(top, item, key) {
            merged.insert(key.to_owned(), v.clone());
        }
    }
    serde_json::from_value(Value::Object(merged)).map_err(|e| at(&format!(": {e}")))
}

/// §7.2.1: an item that was not decided says why, in the shape the specification's own
/// example uses — `context.error` with the status this server would have answered on the
/// single endpoint — so a PEP can tell a refusal from a policy deny, which carries
/// `context.errors` from the kernel instead.
fn undecided(status: StatusCode, code: &str, message: String) -> Value {
    json!({
        "decision": false,
        "context": { "error": { "status": status.as_u16(), "code": code, "message": message } },
    })
}

/// An item's answer: what is served for it, and — when it was decided — what must land
/// before it is.
struct Answer {
    decision: bool,
    body: Value,
    /// The evaluation's errors, served beside the decision as recorded.
    errors: Vec<String>,
    record: Option<(Shard, Entry)>,
}

fn undecided_answer(status: StatusCode, code: &str, message: String) -> Answer {
    Answer {
        decision: false,
        body: undecided(status, code, message),
        errors: Vec::new(),
        record: None,
    }
}

/// Whether `item` inherits a default too large to evaluate. It is then answered for that
/// without the default being copied into it.
fn inherits_oversize(item: &Value, oversize_default: [bool; 4]) -> bool {
    KEYS.iter()
        .zip(oversize_default)
        .any(|(key, oversize)| oversize && !item.as_object().is_some_and(|o| o.contains_key(*key)))
}

/// Item `i`, answered.
fn answer(
    st: &AppState,
    caller: &Option<axum::Extension<crate::caller::Authenticated>>,
    top: &BatchReq,
    i: usize,
    item: &Value,
    inherits_an_oversize_default: bool,
) -> Answer {
    if inherits_an_oversize_default {
        return undecided_answer(
            StatusCode::PAYLOAD_TOO_LARGE,
            "context_too_large",
            CONTEXT_TOO_LARGE.to_owned(),
        );
    }
    match merged(top, Some(i), item) {
        Err(detail) => undecided_answer(StatusCode::BAD_REQUEST, "invalid_request", detail),
        Ok(req) => match evaluate_one(st, caller, req) {
            Err(refusal) => undecided_answer(refusal.status, &refusal.error, refusal.detail),
            Ok(e) => Answer {
                decision: e.decision,
                body: evaluation_body(e.decision, &e.reasons, &e.errors),
                errors: e.errors,
                record: Some((e.shard, e.entry)),
            },
        },
    }
}

/// `POST /access/v1/evaluations`.
///
/// Without an `evaluations` array, or with an empty one, this is the single Access
/// Evaluation over the top-level fields, answered in that shape (§7.1). With items, every
/// item is admitted before any is evaluated — a caller that may not name or describe a
/// party, or assert consent or approval, in one of them, evaluation or not, is refused for
/// the whole batch before anything is evaluated or recorded — and then the
/// items are evaluated in order under the requested semantic. An item that is not an
/// evaluation, or that this server refuses, is answered `decision: false` with the reason
/// in its context (§7.2.1) and, having decided nothing, is not recorded. Every decision
/// made lands before any is served, and a record that cannot land fails the whole exchange
/// closed, as it does the single one.
pub(crate) async fn evaluations(
    State(st): State<AppState>,
    caller: Option<axum::Extension<crate::caller::Authenticated>>,
    req: Result<Json<BatchReq>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(top) = match req {
        Ok(req) => req,
        Err(rejection) => return invalid_request(rejection.body_text()),
    };
    crate::blocking::off_the_executor(&st.blocking.clone(), "decision_unavailable", move || {
        evaluate_all(&st, &caller, top)
    })
    .await
}

/// Every item of one exchange, admitted, decided and recorded, on a blocking thread.
fn evaluate_all(
    st: &AppState,
    caller: &Option<axum::Extension<crate::caller::Authenticated>>,
    top: BatchReq,
) -> Response {
    let semantic = match Semantic::parse(
        top.options
            .as_ref()
            .and_then(|o| o.evaluations_semantic.as_deref()),
    ) {
        Ok(s) => s,
        Err(detail) => return invalid_request(detail),
    };
    let items = top.evaluations.as_deref().unwrap_or_default();
    if items.is_empty() {
        // Backwards-compatible with the single evaluation, in request and in answer.
        return match merged(&top, None, &json!({})) {
            Ok(req) => decide_one(st, caller, req),
            Err(detail) => invalid_request(detail),
        };
    }
    if items.len() > MAX_EVALUATIONS {
        return invalid_request(format!(
            "evaluations: {} items; at most {MAX_EVALUATIONS} in one request",
            items.len()
        ));
    }

    // A default too large to evaluate — a context, or a party whose `properties` are —
    // is answered per item without being copied into each; an item that brings its own
    // value for that key is judged on that.
    let oversize_default = KEYS.map(|key| top.default_for(key).is_some_and(context_too_large));
    if recorded_bytes(&top, items, oversize_default) > MAX_RECORDED_BYTES {
        return Refusal::payload_too_large(
            "batch_too_large",
            "the evaluations would record more than 16 MiB",
        )
        .into_response();
    }

    // Admission for every item — an evaluation or not — before any item is evaluated: a
    // refusal is for the whole exchange and comes before a single record has landed. Only a
    // caller bound to itself can be refused (`self_bound`), so for anyone else this is
    // skipped and no item is copied to read it. An item that will be decided is admitted as
    // the request it will be decided as, which the same `merged` builds for the decision, so
    // the two cannot read an item differently. An item that is not an evaluation, or that
    // inherits a default too large to copy, decides nothing; it still names whom it names,
    // and that is read in place. What this loop copies is bounded by the 16 MiB above, one
    // item at a time.
    if crate::caller::self_bound(caller) {
        for (i, item) in items.iter().enumerate() {
            let request = if inherits_oversize(item, oversize_default) {
                None
            } else {
                merged(&top, Some(i), item).ok()
            };
            let refusal = match &request {
                Some(request) => admit(caller, request),
                None => {
                    let (subject_id, describes, asserts, decision_subject) = facts(&top, item);
                    admit_named(caller, subject_id, describes, asserts, decision_subject)
                }
            };
            if let Some(refusal) = refusal {
                return refusal;
            }
        }
    }
    let mut results = Vec::with_capacity(items.len());
    let mut decided = Vec::new();
    let mut decided_items = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let mut a = answer(
            st,
            caller,
            &top,
            i,
            item,
            inherits_oversize(item, oversize_default),
        );
        match (&semantic, a.record.take()) {
            // A short-circuit follows the decision as settled: the item is recorded, and its
            // answer fixed, before the next is evaluated, so a Mission terminated since the
            // evaluation stops a `deny_on_first_deny` batch and does not end a
            // `permit_on_first_permit` one.
            (Semantic::DenyOnFirstDeny | Semantic::PermitOnFirstPermit, Some((shard, entry))) => {
                let recorded = match record_decision(st, shard, entry) {
                    Ok(recorded) => recorded,
                    Err(e) => return not_recorded(e),
                };
                a.decision = recorded.decision;
                a.body = evaluation_body(recorded.decision, &recorded.reasons, &a.errors);
            }
            (Semantic::ExecuteAll, Some(record)) => {
                decided.push(record);
                decided_items.push((results.len(), std::mem::take(&mut a.errors)));
            }
            (_, None) => {}
        }
        results.push(a.body);
        match semantic {
            Semantic::DenyOnFirstDeny if !a.decision => break,
            Semantic::PermitOnFirstPermit if a.decision => break,
            _ => {}
        }
    }
    // Under `execute_all` every decision lands before any is served, as one durable step on
    // the single-file ledger, and each is served as recorded: a decision settled to a Deny at
    // the record is answered as one. A batch that decided nothing, every item refused or every
    // decision already recorded above, takes no lock and syncs nothing.
    if !decided.is_empty() {
        let recorded = match record_decisions(st, decided) {
            Ok(recorded) => recorded,
            Err(e) => return not_recorded(e),
        };
        for ((at, errors), entry) in decided_items.into_iter().zip(recorded) {
            results[at] = evaluation_body(entry.decision, &entry.reasons, &errors);
        }
    }
    (StatusCode::OK, Json(json!({ "evaluations": results }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An item that is an evaluation is admitted off the parsed request; one that is not is
    /// read in place. The two readers agree on every item that is an evaluation: whom it
    /// names, whether it describes a party and whether it asserts consent or approval. So
    /// which of the two an item meets changes no answer.
    #[test]
    fn facts_read_in_place_match_facts_read_off_the_parsed_request() {
        let top: BatchReq = serde_json::from_value(json!({
            "subject": { "type": "user", "id": "alice", "properties": {} },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
        }))
        .unwrap();
        for item in [
            json!({}),
            json!({ "subject": { "type": "user", "id": "bob" } }),
            json!({ "subject": { "type": "user", "id": "bob", "properties": { "role": "admin" } } }),
            json!({ "resource": { "type": "record", "id": "record-2", "properties": { "status": "archived" } } }),
            json!({ "action": { "name": "delete", "properties": { "soft": true } } }),
            json!({ "action": { "name": "delete", "properties": {} } }),
            json!({ "context": { "decision_subject": "ppid:carol" } }),
            json!({ "context": { "decision_subject": { "handle": "ppid:carol" } } }),
            json!({ "context": { "decision_subject": null } }),
            json!({ "context": { "consent": true } }),
            json!({ "context": { "human_approved": false, "ip": "192.168.1.1" } }),
            json!({ "context": { "ip": "192.168.1.1" } }),
        ] {
            let (id, describes, asserts, about) = facts(&top, &item);
            let parsed = merged(&top, Some(0), &item).expect("a well-formed item");
            let (parsed_id, parsed_describes, parsed_asserts, parsed_about) = parsed.facts();
            assert_eq!(id, parsed_id, "{item}");
            assert_eq!(describes, parsed_describes, "{item}");
            assert_eq!(asserts, parsed_asserts, "{item}");
            assert_eq!(about, parsed_about, "{item}");
        }
        // The same over parties and contexts in every written form, each as an item's own and
        // as a default it inherits: an item that parses is read alike by both, and a party
        // that is not an object never parses, so only the in-place reader ever sees one.
        let object = json!({ "type": "user", "id": "bob" });
        let parties = [
            object.clone(),
            json!({ "type": "user", "id": "bob", "properties": { "role": "admin" } }),
            json!({ "type": "user", "id": "bob", "properties": null }),
            json!({ "type": "user", "id": "bob", "id2": "carol", "extra": ["x"] }),
            json!(["user", "bob"]),
            json!(["user", "bob", { "role": "admin" }]),
            json!([]),
            json!("bob"),
            json!(7),
            json!(null),
        ];
        let contexts = [
            json!({}),
            json!({ "consent": false }),
            json!({ "decision_subject": { "handle": "ppid:carol" } }),
            json!({ "decision_subject": ["ppid:carol"] }),
            json!(["consent"]),
            json!(null),
        ];
        let mut parsed_items = 0;
        for key in ["subject", "resource"] {
            for party in &parties {
                for context in &contexts {
                    for inherited in [false, true] {
                        let mut whole = json!({
                            "subject": object, "action": { "name": "read" }, "resource": object,
                        });
                        let mut item = json!({});
                        let holder = if inherited { &mut whole } else { &mut item };
                        holder[key] = party.clone();
                        holder["context"] = context.clone();
                        let top: BatchReq = serde_json::from_value(whole).unwrap();
                        let what = format!("{key}={party} context={context} inherited={inherited}");
                        match merged(&top, Some(0), &item) {
                            Ok(parsed) => {
                                assert!(party.is_object(), "{what}: parsed");
                                assert_eq!(facts(&top, &item), parsed.facts(), "{what}");
                                parsed_items += 1;
                            }
                            Err(_) => assert!(
                                !party.is_object() || !(context.is_object() || context.is_null()),
                                "{what}: a well-formed item did not parse"
                            ),
                        }
                    }
                }
            }
        }
        assert_eq!(
            parsed_items,
            2 * 4 * 5 * 2,
            "every well-formed item was compared"
        );

        // A decision subject in the defaults reaches every item that names none of its own.
        let about_top: BatchReq = serde_json::from_value(json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "context": { "decision_subject": "ppid:carol" },
        }))
        .unwrap();
        assert_eq!(facts(&about_top, &json!({})).3, Some("ppid:carol"));
        assert_eq!(
            facts(
                &about_top,
                &json!({ "context": { "decision_subject": "ppid:dave" } })
            )
            .3,
            Some("ppid:dave")
        );
        // An approval flag in the defaults reaches every item that brings no context of its
        // own; an item's context, or its `null`, replaces the default whole.
        let claiming_top: BatchReq = serde_json::from_value(json!({
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "read" },
            "resource": { "type": "record", "id": "record-1" },
            "context": { "consent": true },
        }))
        .unwrap();
        for (item, asserts) in [
            (json!({}), true),
            (json!({ "context": { "ip": "192.168.1.1" } }), false),
            (json!({ "context": null }), false),
            (json!({ "context": { "human_approved": true } }), true),
        ] {
            assert_eq!(facts(&claiming_top, &item).2, asserts, "{item}");
            let parsed = merged(&claiming_top, Some(0), &item).expect("a well-formed item");
            assert_eq!(parsed.facts().2, asserts, "{item}");
        }
        // What cannot be parsed still names whom it names.
        let unparseable = json!({ "subject": { "type": "user", "id": "bob" }, "action": 7 });
        assert_eq!(facts(&top, &unparseable), (Some("bob"), false, false, None));
        assert_eq!(
            facts(&top, &json!("not an object")),
            (None, false, false, None)
        );
    }
}
