// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! AuthZEN 1.0 Access Evaluations (§7): several evaluations in one exchange. Each one is
//! a decision of its own — admitted, evaluated and recorded exactly as a single one is —
//! and the exchange adds only the defaults, the order and the stopping rule.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::decide::{DecideReq, Refusal, admit_named, evaluate_one};
use crate::record::{append_to_backend, evaluation_body, record_and_respond, record_or_503};

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

/// Item `i` with the defaults filled in: the request one evaluation would be, or what
/// keeps it from being one — and, either way, what admission needs to know about it,
/// because an item that is not an evaluation still names whom it names.
struct Item {
    /// The principal it names, where it names one.
    subject_id: Option<String>,
    /// Whether it describes a party.
    describes: bool,
    request: Result<DecideReq, String>,
}

/// A key the item carries replaces the default whole (§7.1.1).
fn merged(top: &BatchReq, i: usize, item: &Value) -> Item {
    let Some(item) = item.as_object() else {
        return Item {
            subject_id: None,
            describes: false,
            request: Err(format!("evaluations[{i}] is not an object")),
        };
    };
    let mut merged = serde_json::Map::new();
    for (key, default) in [
        ("subject", &top.subject),
        ("action", &top.action),
        ("resource", &top.resource),
        ("context", &top.context),
    ] {
        if let Some(v) = item.get(key).or(default.as_ref()) {
            merged.insert(key.to_owned(), v.clone());
        }
    }
    let subject_id = merged
        .get("subject")
        .and_then(|s| s.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let describes = ["subject", "resource", "action"].iter().any(|key| {
        merged
            .get(*key)
            .and_then(|party| party.get("properties"))
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty())
    });
    let request =
        serde_json::from_value(Value::Object(merged)).map_err(|e| format!("evaluations[{i}]: {e}"));
    Item {
        subject_id,
        describes,
        request,
    }
}

/// `POST /access/v1/evaluations`.
///
/// Without an `evaluations` array, or with an empty one, this is the single Access
/// Evaluation over the top-level fields, answered in that shape (§7.1). With items, every
/// item is admitted first — a caller that may not name or describe a party in one of them
/// is refused before anything is evaluated or recorded — and then evaluated in order under
/// the requested semantic. An item that is not a valid evaluation is answered
/// `decision: false` with the reason in its context (§7.2.1) and, having decided nothing,
/// is not recorded; an evaluated item is recorded before the batch is served, and a record
/// that cannot land fails the whole exchange closed, as it does the single one.
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
        let single = merged(&top, 0, &json!({}));
        let request = match single.request {
            Ok(req) => req,
            Err(detail) => return invalid_request(detail),
        };
        if let Some(refusal) = admit_named(&caller, single.subject_id.as_deref(), single.describes)
        {
            return refusal;
        }
        return match evaluate_one(&st, &caller, request) {
            Err(refusal) => refusal.into_response(),
            Ok(e) => {
                let backend = st.backend.clone();
                record_and_respond(e.decision, e.reasons, e.errors, move || {
                    append_to_backend(&backend, e.shard, e.entry)
                })
            }
        };
    }
    if items.len() > MAX_EVALUATIONS {
        return invalid_request(format!(
            "evaluations: {} items; at most {MAX_EVALUATIONS} in one request",
            items.len()
        ));
    }

    let items: Vec<Item> = items
        .iter()
        .enumerate()
        .map(|(i, item)| merged(&top, i, item))
        .collect();
    // Admission for every item — an evaluation or not — before any item is evaluated: a
    // refusal is for the whole exchange, and it comes before a single record has landed.
    for item in &items {
        if let Some(refusal) = admit_named(&caller, item.subject_id.as_deref(), item.describes) {
            return refusal;
        }
    }

    let mut results = Vec::with_capacity(items.len());
    for item in items {
        let (decision, body) = match item.request {
            Err(detail) => (false, evaluation_body(false, &[], &[detail])),
            Ok(req) => match evaluate_one(&st, &caller, req) {
                Err(refusal) => (
                    false,
                    evaluation_body(
                        false,
                        &[],
                        &[format!("{}: {}", refusal.error, refusal.detail)],
                    ),
                ),
                Ok(e) => {
                    if let Some(unavailable) =
                        record_or_503(|| append_to_backend(&st.backend, e.shard, e.entry))
                    {
                        return unavailable;
                    }
                    (
                        e.decision,
                        evaluation_body(e.decision, &e.reasons, &e.errors),
                    )
                }
            },
        };
        results.push(body);
        match semantic {
            Semantic::DenyOnFirstDeny if !decision => break,
            Semantic::PermitOnFirstPermit if decision => break,
            _ => {}
        }
    }
    (StatusCode::OK, Json(json!({ "evaluations": results }))).into_response()
}
