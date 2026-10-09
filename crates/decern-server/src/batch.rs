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
    CONTEXT_TOO_LARGE, DecideReq, Refusal, admit_named, context_too_large, decide_one, evaluate_one,
};
use crate::record::{append_all_to_backend, evaluation_body, record_or_503};

/// The most evaluations one exchange may carry. Each is a recorded decision, so a batch
/// is bounded the way a single request's body is, and says so rather than timing out.
pub(crate) const MAX_EVALUATIONS: usize = 1000;

/// §7.1: top-level `subject`, `action`, `resource` and `context` are defaults for every
/// item of `evaluations`; an item's own key replaces the default whole. Each top-level
/// field is kept as it arrived, since an item may supply its own and never use it.
#[derive(Deserialize)]
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
struct Options {
    #[serde(default)]
    evaluations_semantic: Option<String>,
}

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
/// Borrowed, so admission reads a thousand items without copying a thousand defaults.
fn field<'a>(
    top: &'a BatchReq,
    item: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Option<&'a Value> {
    item.get(key).or_else(|| top.default_for(key))
}

/// What admission needs to know about an item, read in place: whom it names, and whether
/// it describes a party through `properties`. An item that is not an object names nobody,
/// and is answered for what it is when its turn comes. The same two facts
/// [`DecideReq::facts`] reads off a parsed request, which a test holds them to.
fn facts<'a>(top: &'a BatchReq, item: &'a Value) -> (Option<&'a str>, bool) {
    let Some(item) = item.as_object() else {
        return (None, false);
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
    (subject_id, describes)
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

/// `POST /access/v1/evaluations`.
///
/// Without an `evaluations` array, or with an empty one, this is the single Access
/// Evaluation over the top-level fields, answered in that shape (§7.1). With items, every
/// item is admitted first — a caller that may not name or describe a party in one of them,
/// evaluation or not, is refused before anything is evaluated or recorded — and then the
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
            Ok(req) => decide_one(&st, &caller, req),
            Err(detail) => invalid_request(detail),
        };
    }
    if items.len() > MAX_EVALUATIONS {
        return invalid_request(format!(
            "evaluations: {} items; at most {MAX_EVALUATIONS} in one request",
            items.len()
        ));
    }

    // Admission for every item — an evaluation or not — before any item is evaluated,
    // read off the items and the defaults in place: a refusal is for the whole exchange,
    // costs no copies, and comes before a single record has landed.
    for item in items {
        let (subject_id, describes) = facts(&top, item);
        if let Some(refusal) = admit_named(&caller, subject_id, describes) {
            return refusal;
        }
    }

    // A default too large to evaluate — a context, or a party whose `properties` are —
    // is answered per item without being copied into each; an item that brings its own
    // value for that key is judged on that.
    const KEYS: [&str; 4] = ["subject", "action", "resource", "context"];
    let oversize_default = KEYS.map(|key| top.default_for(key).is_some_and(context_too_large));
    let mut results = Vec::with_capacity(items.len());
    let mut decided: Vec<(Option<Result<String, String>>, Entry)> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let inherits_an_oversize_default =
            KEYS.iter().zip(oversize_default).any(|(key, oversize)| {
                oversize && !item.as_object().is_some_and(|o| o.contains_key(*key))
            });
        let (decision, body) = if inherits_an_oversize_default {
            (
                false,
                undecided(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "context_too_large",
                    CONTEXT_TOO_LARGE.to_owned(),
                ),
            )
        } else {
            match merged(&top, Some(i), item) {
                Err(detail) => (
                    false,
                    undecided(StatusCode::BAD_REQUEST, "invalid_request", detail),
                ),
                Ok(req) => match evaluate_one(&st, &caller, req) {
                    Err(refusal) => (
                        false,
                        undecided(refusal.status, &refusal.error, refusal.detail),
                    ),
                    Ok(e) => {
                        decided.push((e.shard, e.entry));
                        (
                            e.decision,
                            evaluation_body(e.decision, &e.reasons, &e.errors),
                        )
                    }
                },
            }
        };
        results.push(body);
        match semantic {
            Semantic::DenyOnFirstDeny if !decision => break,
            Semantic::PermitOnFirstPermit if decision => break,
            _ => {}
        }
    }
    // Every decision made lands before any is served.
    if let Some(unavailable) = record_or_503(|| append_all_to_backend(&st.backend, decided)) {
        return unavailable;
    }
    (StatusCode::OK, Json(json!({ "evaluations": results }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Admission reads an item in place; evaluation parses it. The two must agree on whom
    /// an item names and whether it describes a party, or admission could pass what
    /// evaluation then treats differently.
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
        ] {
            let (id, describes) = facts(&top, &item);
            let parsed = merged(&top, Some(0), &item).expect("a well-formed item");
            let (parsed_id, parsed_describes) = parsed.facts();
            assert_eq!(id, parsed_id, "{item}");
            assert_eq!(describes, parsed_describes, "{item}");
        }
        // What cannot be parsed still names whom it names.
        let unparseable = json!({ "subject": { "type": "user", "id": "bob" }, "action": 7 });
        assert_eq!(facts(&top, &unparseable), (Some("bob"), false));
        assert_eq!(facts(&top, &json!("not an object")), (None, false));
    }
}
