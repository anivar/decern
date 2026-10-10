// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! AuthZEN 1.0 Search (§8): the subjects, resources or actions a context permits. A search
//! is an enumeration of decisions — every candidate goes through the kernel's `check`,
//! exactly as an evaluation would, over the same prepared context — and it is recorded
//! once, as the search it was: who asked, over what, and what came back. Parity is with
//! what the authority records: a fact that lives only in a request's `properties` for the
//! side being searched cannot be supplied, since that side is what the search resolves.
//!
//! What a search is not: a decision under a Mission (it binds none, is refused where one
//! would be required, and never lists an action a decision would refuse for want of one),
//! a decision about a third party (a `decision_subject` or a challenge in its context is
//! dropped, since nothing is decided about anyone), or paginated (every result comes back
//! in one page, as the specification allows).

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use decern_kernel::EntityRef;
use decern_ledger::Entry;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::decide::{
    MissionBind, Refusal, admit_named, bind_mission, prepare_context, resolve_sponsor,
    strip_client_approval_flags,
};
use crate::record::{Shard, append_to_backend, record_or_503, shard_for, shard_for_tenant};
use crate::{AppState, challenge};

/// The most result ids one search record carries. The count is always exact.
pub(crate) const MAX_RECORDED_RESULTS: usize = 1000;

/// A party in a search request: the one being searched for carries a type and no id (an
/// id, if sent, is ignored, as §8.4.1 and §8.5.1 say — and ignored means it reaches
/// neither the decision nor the record); the inputs carry both.
#[derive(Deserialize)]
struct Party {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    properties: Option<serde_json::Map<String, Value>>,
}

#[derive(Deserialize)]
struct ActionIn {
    name: String,
    #[serde(default)]
    properties: Option<serde_json::Map<String, Value>>,
}

/// §8.2.1: accepted so a PEP that paginates is not refused; only the token is read, since
/// a token this server never issued cannot name a page.
#[derive(Deserialize, Default)]
struct Page {
    #[serde(default)]
    token: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct SearchReq {
    subject: Party,
    #[serde(default)]
    action: Option<ActionIn>,
    resource: Party,
    #[serde(default)]
    context: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    page: Option<Page>,
}

/// Which side a search resolves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum For {
    Subject,
    Resource,
    Action,
}

impl For {
    fn name(self) -> &'static str {
        match self {
            For::Subject => "subject",
            For::Resource => "resource",
            For::Action => "action",
        }
    }

    /// The action a search is recorded under, alongside the decisions it enumerated.
    fn recorded_as(self) -> &'static str {
        match self {
            For::Subject => "Search.Subject",
            For::Resource => "Search.Resource",
            For::Action => "Search.Action",
        }
    }
}

pub(crate) async fn search_subject(
    State(st): State<AppState>,
    caller: Option<axum::Extension<crate::caller::Authenticated>>,
    req: Result<Json<SearchReq>, axum::extract::rejection::JsonRejection>,
) -> Response {
    off_the_executor(move || search(&st, &caller, req, For::Subject)).await
}

pub(crate) async fn search_resource(
    State(st): State<AppState>,
    caller: Option<axum::Extension<crate::caller::Authenticated>>,
    req: Result<Json<SearchReq>, axum::extract::rejection::JsonRejection>,
) -> Response {
    off_the_executor(move || search(&st, &caller, req, For::Resource)).await
}

pub(crate) async fn search_action(
    State(st): State<AppState>,
    caller: Option<axum::Extension<crate::caller::Authenticated>>,
    req: Result<Json<SearchReq>, axum::extract::rejection::JsonRejection>,
) -> Response {
    off_the_executor(move || search(&st, &caller, req, For::Action)).await
}

/// A search decides once per directory entry, so it runs on a blocking thread rather than
/// holding an executor worker for the length of the directory.
async fn off_the_executor(work: impl FnOnce() -> Response + Send + 'static) -> Response {
    match tokio::task::spawn_blocking(work).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "search_failed", "detail": "the search did not complete" })),
        )
            .into_response(),
    }
}

/// One search, start to finish: the request checked for what its kind requires, the
/// searched side's id discarded, the caller admitted, the context prepared as an
/// evaluation's is, the candidates decided, the search recorded, the results served — in
/// that order, and served only once recorded.
fn search(
    st: &AppState,
    caller: &Option<axum::Extension<crate::caller::Authenticated>>,
    req: Result<Json<SearchReq>, axum::extract::rejection::JsonRejection>,
    what: For,
) -> Response {
    let Json(mut req) = match req {
        Ok(req) => req,
        Err(rejection) => return Refusal::invalid_request(rejection.body_text()).into_response(),
    };
    if let Err(refusal) = checked(&req, what) {
        return refusal.into_response();
    }
    // The searched side's id is ignored: it names nothing the search decides, and it
    // must not name whose act the record is, nor whose shard it lands in.
    match what {
        For::Subject => req.subject.id = None,
        For::Resource => req.resource.id = None,
        For::Action => {}
    }
    // Admission: an input party is named, so the caller must be allowed to name it; the
    // searched-for side names everyone, so a caller bound to itself may not search for
    // subjects at all. Describing a party is a PEP's act on either endpoint.
    let describes = [
        &req.subject.properties,
        &req.resource.properties,
        &req.action.as_ref().and_then(|a| a.properties.clone()),
    ]
    .iter()
    .any(|p| p.as_ref().is_some_and(|m| !m.is_empty()));
    if what == For::Subject
        && let Some(refusal) = crate::caller::refuse_unless_pep(caller, "search for subjects")
    {
        return refusal;
    }
    let named_subject = req.subject.id.clone();
    if let Some(refusal) = admit_named(caller, named_subject.as_deref(), describes) {
        return refusal;
    }
    // A search binds no Mission. Where one would be required, or one is named, the
    // caller wanted a decision, and this is not the endpoint that makes one.
    let names_a_mission = req
        .context
        .as_ref()
        .and_then(|c| c.get("mission"))
        .is_some_and(|m| !m.is_null());
    if st.require_mission || names_a_mission {
        return Refusal::unprocessable(
            "search_under_mission",
            "a search does not run under a Mission; it enumerates decisions rather than \
             making one — evaluate the decision instead",
        )
        .into_response();
    }

    // The context, prepared as an evaluation's is; then the keys a decision record
    // would carry and a search does not, dropped.
    let described = [
        ("subject", req.subject.properties.take()),
        ("resource", req.resource.properties.take()),
        (
            "action",
            req.action.as_mut().and_then(|a| a.properties.take()),
        ),
    ]
    .map(|(key, p)| (key, p.filter(|m| !m.is_empty())));
    let (mut ctx, now_s, asserted_by) =
        match prepare_context(caller, req.context.take().unwrap_or_default(), described) {
            Ok(prepared) => prepared,
            Err(refusal) => return refusal.into_response(),
        };
    if let Some(obj) = ctx.as_object_mut() {
        obj.remove("decision_subject");
    }
    let _ = challenge::take_raw(&mut ctx);

    // The parties in the model's terms; results come back in the request's.
    let subject = EntityRef {
        ty: st.model_type(&req.subject.ty),
        id: req.subject.id.clone().unwrap_or_default(),
    };
    let resource = EntityRef {
        ty: st.model_type(&req.resource.ty),
        id: req.resource.id.clone().unwrap_or_default(),
    };
    let action = req.action.as_ref().map(|a| a.name.clone());

    let ids = enumerate(
        st,
        what,
        &subject,
        &resource,
        action.as_deref(),
        &mut ctx,
        now_s,
    );
    let results: Vec<Value> = ids
        .iter()
        .map(|id| match what {
            For::Subject => json!({ "type": req.subject.ty, "id": id }),
            For::Resource => json!({ "type": req.resource.ty, "id": id }),
            For::Action => json!({ "name": id }),
        })
        .collect();

    // The record: the search, over the context every candidate was decided on, with what
    // came back — the ids up to a bound, and the count exactly. A subject search names no
    // subject, so its record belongs to the resource's tenant.
    let dir = st.kernel.directory();
    let sponsor = named_subject
        .as_deref()
        .and_then(|id| resolve_sponsor(dir, id));
    let shard: Shard = match what {
        For::Subject => shard_for_tenant(
            &st.backend,
            dir.resources.get(&resource.id).map(|r| r.tenant.as_str()),
        ),
        For::Resource | For::Action => shard_for(&st.backend, dir, &subject.id),
    };
    let parameters_digest = decern_ledger::digest(&json!({
        "search": what.name(),
        "subject": {"type": subject.ty, "id": subject.id},
        "action": action,
        "resource": {"type": resource.ty, "id": resource.id},
        "context": ctx,
    }));
    ctx["search"] = json!({
        "for": what.name(),
        "action": action,
        "count": ids.len(),
        "results": ids[..ids.len().min(MAX_RECORDED_RESULTS)],
    });
    let entry = Entry {
        ts_ms: now_s.saturating_mul(1000),
        subject_type: subject.ty,
        subject_id: subject.id,
        action: what.recorded_as().to_owned(),
        resource_type: resource.ty,
        resource_id: resource.id,
        context: ctx,
        decision: true,
        sponsor,
        asserted_by,
        digests: std::collections::BTreeMap::from([
            (
                decern_ledger::DIGEST_PARAMETERS.to_owned(),
                parameters_digest,
            ),
            (
                decern_ledger::DIGEST_AUTHORITY.to_owned(),
                st.authority_digest.to_string(),
            ),
        ]),
        ..Default::default()
    };
    if let Some(unavailable) = record_or_503(|| append_to_backend(&st.backend, shard, entry)) {
        return unavailable;
    }
    (StatusCode::OK, Json(json!({ "results": results }))).into_response()
}

/// The candidates `check` permits, and the context left as the record may carry it:
/// pruned to what the searched action declares (or, for an action search, to what any
/// action declares) — an undeclared attribute reaches neither a decision nor the record.
/// The rule a decision applies before the kernel is applied here too: an action that
/// needs a Mission, which no search binds, is refused as a decision and so is never a
/// result, and a body-asserted approval is stripped as a refused decision strips it. An
/// input the directory does not know, or a type that is not the kernel's, finds nothing
/// without a scan, which is also what every candidate's `check` would have said.
fn enumerate(
    st: &AppState,
    what: For,
    subject: &EntityRef,
    resource: &EntityRef,
    action: Option<&str>,
    ctx: &mut Value,
    now_s: u64,
) -> Vec<String> {
    let dir = st.kernel.directory();
    let refused_without_a_mission = |action: &str, ctx: &Value| {
        matches!(
            bind_mission(st.missions.as_ref(), false, &subject.id, action, ctx, now_s),
            MissionBind::Deny(_)
        )
    };
    match what {
        For::Subject | For::Resource => {
            let action = action.unwrap_or_default();
            st.kernel.prune_undeclared_context(action, ctx);
            if refused_without_a_mission(action, ctx) {
                strip_client_approval_flags(ctx);
                return Vec::new();
            }
            let known = match what {
                For::Subject => {
                    subject.ty == "Principal" && dir.resources.contains_key(&resource.id)
                }
                _ => resource.ty == "Resource" && dir.principals.contains_key(&subject.id),
            };
            if !known {
                return Vec::new();
            }
            let found = match what {
                For::Subject => st.kernel.search_subjects(action, resource, ctx),
                _ => st.kernel.search_resources(subject, action, ctx),
            };
            found.into_iter().map(|e| e.id).collect()
        }
        For::Action => {
            let known = subject.ty == "Principal"
                && resource.ty == "Resource"
                && dir.principals.contains_key(&subject.id)
                && dir.resources.contains_key(&resource.id);
            let found: Vec<String> = if known {
                st.kernel
                    .search_actions(subject, resource, ctx)
                    .into_iter()
                    .filter(|name| !refused_without_a_mission(name, ctx))
                    .collect()
            } else {
                Vec::new()
            };
            // Every action was decided over this context; the record carries what any of
            // them declares and nothing more.
            st.kernel.prune_to_any_declared(ctx);
            found
        }
    }
}

/// What each kind of search requires of its request (§8.4.1, §8.5.1, §8.6.1): the input
/// parties carry an id, a search that names an action carries one and an action search
/// carries none, and a page token is one this server issued — which is none.
fn checked(req: &SearchReq, what: For) -> Result<(), Refusal> {
    let needs = |present: bool, field: &str| {
        if present {
            Ok(())
        } else {
            Err(Refusal::invalid_request(format!(
                "{field} is required for a {} search",
                what.name()
            )))
        }
    };
    let has_id = |p: &Party| p.id.as_ref().is_some_and(|id| !id.is_empty());
    match what {
        For::Subject => {
            needs(has_id(&req.resource), "resource.id")?;
            needs(req.action.is_some(), "action")?;
        }
        For::Resource => {
            needs(has_id(&req.subject), "subject.id")?;
            needs(req.action.is_some(), "action")?;
        }
        For::Action => {
            needs(has_id(&req.subject), "subject.id")?;
            needs(has_id(&req.resource), "resource.id")?;
            if req.action.is_some() {
                return Err(Refusal::invalid_request(
                    "action is omitted from an action search; the actions are what it resolves",
                ));
            }
        }
    }
    if req
        .page
        .as_ref()
        .and_then(|p| p.token.as_deref())
        .is_some_and(|t| !t.is_empty())
    {
        return Err(Refusal::invalid_request(
            "page.token: this server issued no token; it returns every result in one page",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::Json;
    use axum::extract::State;
    use axum::http::StatusCode;
    use serde_json::json;

    use super::*;
    use crate::testutil::{body_json, mission_base, mission_state_at};

    /// The claim a search makes — a result is one the evaluation endpoint would permit —
    /// holds for the action a decision refuses without a Mission: `MoveMoney` is never a
    /// search result, however the context asserts approval, and the evaluation of the
    /// same request says `false` for the same reason. The record of such a search carries
    /// no body-asserted approval, as the refused decision's would not.
    #[tokio::test]
    async fn an_action_a_decision_refuses_without_a_mission_is_never_a_result() {
        let base = mission_base();
        let (st, pk) = mission_state_at(&base);
        let ctx = json!({ "human_approved": true });
        let req: SearchReq = serde_json::from_value(json!({
            "subject": { "type": "Principal", "id": "corp" },
            "resource": { "type": "Resource", "id": "claim1" },
            "context": ctx,
        }))
        .unwrap();
        let (status, resp) =
            body_json(search_action(State(st.clone()), None, Ok(Json(req))).await).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let names: Vec<&str> = resp["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"Read"), "{resp}");
        assert!(!names.contains(&"MoveMoney"), "{resp}");

        let subjects: SearchReq = serde_json::from_value(json!({
            "subject": { "type": "Principal" },
            "action": { "name": "MoveMoney" },
            "resource": { "type": "Resource", "id": "claim1" },
            "context": ctx,
        }))
        .unwrap();
        let (status, resp) =
            body_json(search_subject(State(st.clone()), None, Ok(Json(subjects))).await).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        assert_eq!(resp["results"], json!([]), "{resp}");

        let decision: crate::decide::DecideReq = serde_json::from_value(json!({
            "subject": { "type": "Principal", "id": "corp" },
            "action": { "name": "MoveMoney" },
            "resource": { "type": "Resource", "id": "claim1" },
            "context": ctx,
        }))
        .unwrap();
        let (status, resp) =
            body_json(crate::decide::decide(State(st.clone()), None, Ok(Json(decision))).await)
                .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        assert_eq!(resp["decision"], false, "the two agree: {resp}");

        let ledger = base.join("decern-ledger.jsonl");
        let (_r, records) = decern_ledger::read_verified(&ledger, Some(&pk), 0, 10).unwrap();
        let subject_search = &records[1]["entry"];
        assert_eq!(subject_search["action"], "Search.Subject");
        assert!(
            subject_search["context"].get("human_approved").is_none(),
            "a refused decision's approval is not recorded: {subject_search}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
