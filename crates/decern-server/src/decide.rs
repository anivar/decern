// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The decision layer: the AuthZEN evaluation handler, the server-derived facts
//! that ride with it (sponsor, decision subject), and decision-under-mission binding.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use decern_kernel::{Directory, EntityRef};
use decern_ledger::{DecisionSubject, Entry, Party};
use decern_store::MissionRegistry;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::record::{append_to_backend, record_and_respond, shard_for};
use crate::{AppState, challenge, now_secs};

#[derive(Deserialize)]
struct Ref {
    #[serde(rename = "type")]
    ty: String,
    id: String,
}

/// AuthZEN action: an object with a `name` (optional `properties` are accepted and ignored).
#[derive(Deserialize)]
struct Action {
    name: String,
}

#[derive(Deserialize)]
pub(crate) struct DecideReq {
    subject: Ref,
    action: Action,
    resource: Ref,
    #[serde(default)]
    context: Value,
}

/// Derive the accountable-owner ("sponsor") for a decision: the pure ROOT of
/// `subject_id`'s delegation chain, resolved server-side from the directory —
/// never a decision input, never read from the request body.
///
/// Three cases, discriminated in this exact order (the membership check FIRST,
/// because `ancestors_of` returns an empty vec for BOTH a self-root and an
/// unknown id — the empty vec alone cannot tell them apart):
///   - `subject_id` is NOT a known principal → `None` (a global/static-token
///     caller the directory doesn't recognize; nothing to stand behind).
///   - known, with ancestors → the LAST ancestor (the root of the chain), not
///     the nearest delegator.
///   - known, no ancestors → a self-sponsored root: the subject stands behind
///     itself, so `sponsor.id == subject_id`.
///
/// The caller leaves `sponsor_source` at its `Derived` default; this function
/// only ever computes, never asserts.
pub(crate) fn resolve_sponsor(dir: &Directory, subject_id: &str) -> Option<Party> {
    if !dir.contains(subject_id) {
        return None;
    }
    // Chain is nearest-first, root LAST; a self-root's chain is empty → itself.
    // `validate()` gates kernel load and rejects cycles, so on a served kernel
    // this last element is always the true root, never a cycle member.
    let root = dir
        .ancestors_of(subject_id)
        .pop()
        .unwrap_or_else(|| subject_id.to_owned());
    Some(Party {
        kind: "Principal".to_owned(),
        id: root,
    })
}

/// Take the decision subject out of the context, and decide whether it belongs
/// on the record.
///
/// It is removed from the context either way, before the kernel ever sees it: a
/// claim about who a decision concerns is not an input to whether the decision is
/// allowed, and the cheapest way to guarantee that is to make it unreachable.
///
/// It is recorded only when it says something the record does not already say.
/// A decision about the requester is described by the subject; a decision about
/// the owner of the resource named is described by the resource. Repeating either
/// as a decision subject adds an identifier and no information, so both are
/// dropped rather than stored.
///
/// A handle that is plainly a person — an address someone could be reached at —
/// is refused instead. This is the last moment it can be: the record is appended,
/// signed and chained, so anything written here is permanent, and a pseudonymous
/// reference is the only form of this claim that stays safe to keep.
fn take_decision_subject(
    ctx: &mut Value,
    subject_id: &str,
    resource_owner: Option<&str>,
) -> Result<Option<DecisionSubject>, String> {
    let Some(raw) = ctx
        .as_object_mut()
        .and_then(|o| o.remove("decision_subject"))
    else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    let ds: DecisionSubject = serde_json::from_value(raw)
        .map_err(|e| format!("decision_subject must be a handle or an object with one: {e}"))?;
    if ds.handle.trim().is_empty() {
        return Err("decision_subject handle must not be empty".to_owned());
    }
    if ds.handle.contains('@') {
        return Err(
            "decision_subject handle must be a pseudonymous reference, not an address a party \
             could be identified or contacted by"
                .to_owned(),
        );
    }
    if ds.handle == subject_id || Some(ds.handle.as_str()) == resource_owner {
        return Ok(None);
    }
    Ok(Some(ds))
}

pub(crate) async fn decide(
    State(st): State<AppState>,
    caller: Option<axum::Extension<crate::bearer::Authenticated>>,
    Json(req): Json<DecideReq>,
) -> Response {
    // Who asserted this request, when the guard verified a token. Under a trusted
    // front there is no extension and the column stays off the record: an assertion
    // this server did not verify itself does not belong on a permanent one.
    let asserted_by = caller.map(|axum::Extension(who)| decern_ledger::AssertedBy {
        sub: who.subject,
        client_id: who.client_id,
        iss: who.issuer,
    });
    let now_s = now_secs();
    let mut ctx = if req.context.is_object() {
        req.context
    } else {
        json!({})
    };
    // `now` is a server-derived fact, like `sponsor` and `shard` below — the PEP
    // is the clock authority. Set it UNCONDITIONALLY from the server clock,
    // overriding any body-supplied value: the kernel uses `context.now` as its
    // sole time source for the decay/expiry gate, so honoring a caller's `now`
    // would let `{"now":0}` win an Allow for an expired principal.
    ctx["now"] = json!(now_s);
    // A caller-supplied `asserted_by` key in the request context must not appear
    // on the permanent record alongside the server-derived top-level column.
    if let Some(obj) = ctx.as_object_mut() {
        obj.remove("asserted_by");
    }
    let subject = EntityRef {
        ty: req.subject.ty,
        id: req.subject.id,
    };
    let resource = EntityRef {
        ty: req.resource.ty,
        id: req.resource.id,
    };
    let action = req.action.name;

    // Decision-under-mission: bind (and optionally require) a live Mission.
    // Client-supplied human_approved/consent are stripped whenever a mission is
    // in play; the server re-derives them from the verified grant.
    let mission_bind = bind_mission(
        st.missions.as_ref(),
        st.require_mission,
        &subject.id,
        &action,
        &ctx,
        now_s,
    );
    let (mission_ref, mission_errors) = match mission_bind {
        // No Mission named and none required: `context` is left as the caller sent
        // it, including any approval flags. Establishing the caller (the bearer guard,
        // or the trusted front) says who is asserting those flags, not that they are
        // true — approval is server-derived only under a Mission, so an operator who
        // wants that guarantee for money must run `--require-mission`.
        MissionBind::None => (None, Vec::new()),
        MissionBind::Ok(mref) => {
            apply_mission_context(&mut ctx, &action);
            (Some(mref), Vec::new())
        }
        MissionBind::Deny(errs) => {
            // Strip forged approval flags; force a Deny path (kernel will Deny
            // MoveMoney without human_approved, etc.) and surface the mission errors.
            strip_client_approval_flags(&mut ctx);
            (None, errs)
        }
    };
    // `mission` is not in the Cedar context schema — strip before check, re-attach
    // on the ledger Entry (Entry.mission + context.mission for auditors).
    let mission_for_context = if let Some(obj) = ctx.as_object_mut() {
        obj.remove("mission")
    } else {
        None
    };

    // A challenge from the party a decision was about is removed here too, and
    // unconditionally: a request carrying one is evaluated exactly as the same request
    // without it. Answering it is a separate act, after the decision is made.
    let raw_challenge = challenge::take_raw(&mut ctx);

    // Out of the context before the check too, and for a stronger reason: who a
    // decision is about must not be able to change what the decision is.
    let resource_owner = st
        .kernel
        .directory()
        .resources
        .get(&resource.id)
        .map(|r| r.owner.clone());
    let decision_subject =
        match take_decision_subject(&mut ctx, &subject.id, resource_owner.as_deref()) {
            Ok(ds) => ds,
            Err(detail) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "decision_subject", "detail": detail })),
                )
                    .into_response();
            }
        };

    let mut r = st.kernel.check(&subject, &action, &resource, &ctx);
    if !mission_errors.is_empty() {
        r.decision = false;
        r.errors.extend(mission_errors);
        r.reasons.clear();
    }

    // Accountable-owner, derived server-side from the delegation chain BEFORE
    // `subject.id` is moved into the entry. Never read from the request body.
    let sponsor = resolve_sponsor(st.kernel.directory(), &subject.id);

    // Shard (sharded backend only), likewise derived server-side from the
    // directory BEFORE `subject.id` is moved. `None` for the single-file
    // backend, which has no shards. Resolution errors (reserved-name collision)
    // are carried into the append closure so they fail closed as a 503.
    let shard = shard_for(&st.backend, st.kernel.directory(), &subject.id);

    if let Some(m) = mission_for_context {
        ctx["mission"] = m;
    }

    // Bind the exact parameters evaluated: subject/action/resource + post-mission ctx.
    let parameters_digest = decern_ledger::digest(&json!({
        "subject": {"type": subject.ty, "id": subject.id},
        "action": action,
        "resource": {"type": resource.ty, "id": resource.id},
        "context": ctx,
        "mission": mission_ref.as_ref().map(|m| json!({"approver": m.approver, "s256": m.s256})),
        "decision_subject": decision_subject,
    }));

    // Answer the challenge, if one came with the request — after the decision, never
    // before it, so the answer is about a decision that has already been made rather than
    // an influence on making it. A challenge that cannot be believed is refused outright:
    // recording an answer to a claim whose standing was never proved would put a party's
    // name on the record on nobody's authority.
    let challenge_record = match raw_challenge {
        None => None,
        Some(raw) => match challenge::parse(&raw, &st.standing_issuers, now_s) {
            Err(e) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": e.kind(), "detail": e.detail() })),
                )
                    .into_response();
            }
            Ok(c) => {
                let subject_matches = decision_subject
                    .as_ref()
                    .is_some_and(|ds| ds.handle == c.standing.decision_subject);
                let (outcome, outcome_basis) = match challenge::answer(&c, subject_matches) {
                    challenge::Outcome::AffirmPriorDecision { affirm_basis } => {
                        ("affirm_prior_decision", affirm_basis)
                    }
                    challenge::Outcome::ReevaluateWithSubjectContext { reevaluation_basis } => {
                        ("reevaluate_with_subject_context", reevaluation_basis)
                    }
                };
                Some(decern_ledger::ChallengeRecord {
                    decision_ref: c.decision_ref,
                    decision_subject: c.standing.decision_subject,
                    basis: c.basis,
                    requested_effect: c.requested_effect,
                    outcome: outcome.to_owned(),
                    outcome_basis,
                    // The digest, never the evidence itself: what a party sends to argue
                    // their case is likely to be about them, and this log cannot be edited.
                    evidence_digest: c.evidence.as_ref().map(decern_ledger::digest),
                })
            }
        },
    };

    // A decision that names an affected party is one an affected party should hear about.
    let notice_required = decision_subject.is_some();

    let entry = Entry {
        ts_ms: now_s.saturating_mul(1000),
        subject_type: subject.ty,
        subject_id: subject.id,
        action,
        resource_type: resource.ty,
        resource_id: resource.id,
        context: ctx,
        decision: r.decision,
        reasons: r.reasons.clone(),
        sponsor,
        mission: mission_ref,
        decision_subject,
        notice_required,
        asserted_by,
        challenge: challenge_record.clone(),
        digests: BTreeMap::from([
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

    let backend = st.backend.clone();
    record_and_respond(r.decision, r.reasons, r.errors, move || {
        append_to_backend(&backend, shard, entry)
    })
}

/// Outcome of resolving `context.mission` against the registry.
enum MissionBind {
    /// No mission named and `--require-mission` is off.
    None,
    /// Live Mission bound; caller should inject server-side approval flags.
    Ok(decern_ledger::MissionRef),
    /// Mission required or named but invalid — force Deny with these errors.
    Deny(Vec<String>),
}

fn strip_client_approval_flags(ctx: &mut Value) {
    if let Some(obj) = ctx.as_object_mut() {
        obj.remove("human_approved");
        obj.remove("consent");
    }
}

/// Map action → required scope name (mirrors the scope-gate convention).
///
/// `None` means "this action has no scope mapping", which under a Mission is a
/// refusal, not a pass — see `bind_mission`. An action added to the model without
/// a mapping here must not inherit every Mission's approval by omission.
fn scope_for_action(action: &str) -> Option<&'static str> {
    match action {
        "Read" => Some("read"),
        "MoveMoney" => Some("move_money"),
        "AccessPII" => Some("pii:read"),
        _ => None,
    }
}

/// After a Mission is verified, set approval flags from the grant — never from the body.
///
/// The flags say only what the grant establishes: an approver, holding the scope,
/// approved this action for this agent. `bind_mission` has already refused any
/// action the grant does not cover, so each flag set here is backed by that check.
fn apply_mission_context(ctx: &mut Value, action: &str) {
    strip_client_approval_flags(ctx);
    // A verified Mission that covers the action is the human/consent approval.
    if action == "MoveMoney" {
        ctx["human_approved"] = json!(true);
    }
    // Consent is asserted only where the action is itself the consent-bearing one.
    // `Read` is not: a Mission approving reads is not a data subject's consent, and
    // recording it as one would put a claim in the ledger the grant never made.
    if action == "AccessPII" {
        ctx["consent"] = json!(true);
    }
}

fn bind_mission(
    registry: &dyn MissionRegistry,
    require: bool,
    subject_id: &str,
    action: &str,
    ctx: &Value,
    now: u64,
) -> MissionBind {
    let mission_val = ctx.get("mission");
    let named = mission_val.is_some() && !mission_val.map(|v| v.is_null()).unwrap_or(true);
    if !named {
        return if require {
            MissionBind::Deny(vec![
                "context.mission is required (--require-mission)".into(),
            ])
        } else {
            MissionBind::None
        };
    }
    let Some(obj) = mission_val.and_then(|v| v.as_object()) else {
        return MissionBind::Deny(vec![
            "context.mission must be an object {approver,s256}".into(),
        ]);
    };
    let approver = obj.get("approver").and_then(|v| v.as_str()).unwrap_or("");
    let s256 = obj.get("s256").and_then(|v| v.as_str()).unwrap_or("");
    if approver.is_empty() || s256.is_empty() {
        return MissionBind::Deny(vec![
            "context.mission requires non-empty approver and s256".into(),
        ]);
    }

    let entry = match registry.status(s256) {
        Ok(Some(e)) => e,
        Ok(None) => {
            return MissionBind::Deny(vec![format!("mission {s256} names no registered approval")]);
        }
        Err(e) => {
            return MissionBind::Deny(vec![format!("mission registry unavailable: {e}")]);
        }
    };
    if entry.terminated {
        return MissionBind::Deny(vec![format!("mission {s256} is terminated")]);
    }
    if entry.expiry <= now {
        return MissionBind::Deny(vec![format!("mission {s256} is expired")]);
    }
    if entry.approver != approver {
        return MissionBind::Deny(vec![format!(
            "mission {s256} approver mismatch (registry {}, request {approver})",
            entry.approver
        )]);
    }
    if entry.agent.is_empty() {
        return MissionBind::Deny(vec![format!(
            "mission {s256} has no agent on file (re-approve to enable decision-under-mission)"
        )]);
    }
    if entry.agent != subject_id {
        return MissionBind::Deny(vec![format!(
            "mission {s256} authorizes agent {}, not subject {subject_id}",
            entry.agent
        )]);
    }
    match scope_for_action(action) {
        Some(scope) if !entry.approved_tools.iter().any(|t| t == scope) => {
            return MissionBind::Deny(vec![format!(
                "mission {s256} does not approve tool/scope `{scope}` for action {action}"
            )]);
        }
        // An action with no scope mapping cannot be shown to be covered by this
        // grant, so it is refused. Silently skipping the check would let any new
        // action ride on every Mission until someone remembered to map it.
        None => {
            return MissionBind::Deny(vec![format!(
                "action {action} has no scope mapping, so mission {s256} cannot be shown to approve it"
            )]);
        }
        _ => {}
    }

    MissionBind::Ok(decern_ledger::MissionRef {
        approver: approver.to_owned(),
        s256: s256.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::testutil::{body_json, mission_base, mission_state_at, test_dir};

    #[test]
    fn accepts_authzen_request_shape() {
        // AuthZEN 1.0: action is an object with a `name`; optional `properties` are ignored.
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"corp"},
                "action":{"name":"Read","properties":{}},
                "resource":{"type":"Resource","id":"claim1"}}"#,
        )
        .unwrap();
        assert_eq!(req.action.name, "Read");
        assert_eq!(req.subject.id, "corp");
    }

    #[test]
    fn sponsor_of_multi_hop_delegate_is_the_root_not_the_delegator() {
        // c's nearest delegator is b, but accountability rolls all the way to a.
        let s = resolve_sponsor(&test_dir(), "c").expect("known principal has a sponsor");
        assert_eq!(
            s,
            Party {
                kind: "Principal".into(),
                id: "a".into()
            }
        );
    }

    #[test]
    fn self_root_sponsors_itself() {
        let s = resolve_sponsor(&test_dir(), "solo").expect("known root has a sponsor");
        assert_eq!(
            s,
            Party {
                kind: "Principal".into(),
                id: "solo".into()
            }
        );
        // The root `a` is likewise its own sponsor.
        let a = resolve_sponsor(&test_dir(), "a").unwrap();
        assert_eq!(a.id, "a");
    }

    #[test]
    fn unknown_subject_has_no_sponsor() {
        // A global/static-token caller the directory doesn't recognize — distinct
        // from a self-root, even though both yield an empty ancestor chain.
        assert!(resolve_sponsor(&test_dir(), "ghost").is_none());
    }

    #[test]
    fn derivation_is_never_sourced_from_the_request() {
        // The derived sponsor is carried on an Entry whose sponsor_source stays
        // at the Derived default (this helper only ever computes, never asserts).
        use decern_ledger::SponsorSource;
        let entry = Entry {
            sponsor: resolve_sponsor(&test_dir(), "c"),
            ..Default::default()
        };
        assert_eq!(entry.sponsor_source, SponsorSource::Derived);
        assert_eq!(entry.sponsor.unwrap().id, "a");
    }

    #[tokio::test]
    async fn server_ignores_body_now_and_decays_by_its_own_clock() {
        // Regression guard: the server must use its OWN wall clock, never the request
        // body's `now`. `agent1` is a builtin principal with `expiry: 200`, far in the
        // past relative to the wall clock the server uses.
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);

        // Non-vacuous: at now=100 (< agent1's expiry 200) agent1 MAY read claim1 — so the
        // ONLY reason the server denies below is that it ignored the body `now`.
        let allow_at_100 = st.kernel.check(
            &EntityRef {
                ty: "Principal".into(),
                id: "agent1".into(),
            },
            "Read",
            &EntityRef {
                ty: "Resource".into(),
                id: "claim1".into(),
            },
            &json!({ "now": 100 }),
        );
        assert!(
            allow_at_100.decision,
            "fixture guard: agent1 reads claim1 at now=100 (before its expiry)"
        );

        // The request carries {"now":100}; honoring it would wrongly ALLOW. The server
        // must instead use its own clock (>> 200) → agent1 is decayed → DENY.
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"agent1"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claim1"},
                "context":{"now":100}}"#,
        )
        .unwrap();
        let (status, body) = body_json(decide(State(st), None, Json(req)).await).await;
        assert_eq!(status, StatusCode::OK, "a recorded decision is served");
        assert_eq!(
            body["decision"], false,
            "server ignored body now=100 and decayed agent1 by its own wall clock"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn require_mission_denies_without_a_mission() {
        let base = mission_base();
        let (mut st, _pk) = mission_state_at(&base);
        st.require_mission = true;
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"agent1"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claim1"},
                "context":{"human_approved":true}}"#,
        )
        .unwrap();
        let (status, body) = body_json(decide(State(st), None, Json(req)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], false, "missing mission must Deny: {body}");
        assert!(
            body["context"]["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e.as_str().unwrap_or("").contains("require-mission")),
            "{body}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Sign a standing token the way an issuer would.
    fn standing_token(
        key: &decern_crypto::SigningKey,
        decision_ref: &str,
        handle: &str,
        exp: u64,
    ) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use ed25519_dalek::Signer as _;
        let h = B64.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let p = B64.encode(
            serde_json::to_vec(&json!({
                "decision_ref": decision_ref,
                "decision_subject": handle,
                "exp": exp,
            }))
            .unwrap(),
        );
        let sig = B64.encode(key.sign(format!("{h}.{p}").as_bytes()).to_bytes());
        format!("{h}.{p}.{sig}")
    }

    /// The guarantee the whole surface rests on: a challenge is answered, and answering it
    /// changes nothing about what was permitted. The same request with and without one
    /// must decide identically, and the challenge must not survive into what was evaluated.
    #[tokio::test]
    async fn a_challenge_is_answered_and_never_changes_the_decision() {
        let base = mission_base();
        let (mut st, pubkey) = mission_state_at(&base);
        let issuer = decern_crypto::generate().unwrap();
        st.standing_issuers = Arc::new(vec![issuer.verifying_key()]);

        let plain: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"agent1"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claim1"},
                "context":{"decision_subject":"ppid:carol"}}"#,
        )
        .unwrap();
        let (status, without) = body_json(decide(State(st.clone()), None, Json(plain)).await).await;
        assert_eq!(status, StatusCode::OK, "{without}");

        let token = standing_token(&issuer, "dec-1", "ppid:carol", now_secs() + 3600);
        let challenged: DecideReq = serde_json::from_str(&format!(
            r#"{{"subject":{{"type":"Principal","id":"agent1"}},
                "action":{{"name":"Read"}},
                "resource":{{"type":"Resource","id":"claim1"}},
                "context":{{"decision_subject":"ppid:carol",
                            "subject_side_challenge":{{
                                "standing_token":"{token}",
                                "decision_ref":"dec-1",
                                "challenge_basis":["factual-error"],
                                "requested_effect":"reverse"}}}}}}"#
        ))
        .unwrap();
        let (status, with) =
            body_json(decide(State(st.clone()), None, Json(challenged)).await).await;
        assert_eq!(status, StatusCode::OK, "{with}");
        assert_eq!(
            without["decision"], with["decision"],
            "a challenge must not change what was permitted: {without} vs {with}"
        );

        let ledger_path = base.join("decern-ledger.jsonl");
        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 100).unwrap();
        let last = records.last().expect("recorded");
        assert_eq!(
            last["entry"]["challenge"]["outcome"], "reevaluate_with_subject_context",
            "a basis bearing on the facts reopens the decision: {last}"
        );
        assert_eq!(last["entry"]["challenge"]["decision_ref"], "dec-1");
        assert!(
            !last["entry"]["challenge"]["outcome_basis"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
            "an answer without a reason is a dismissal: {last}"
        );
        // The challenge must not have reached the evaluated context.
        assert!(
            last["entry"]["context"]
                .get("subject_side_challenge")
                .is_none(),
            "the challenge must not survive into what was evaluated: {last}"
        );
        // A decision naming an affected party is one they should hear about.
        assert_eq!(last["entry"]["notice_required"], true, "{last}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A challenge whose standing was never proved is refused rather than answered:
    /// recording an answer would put a party's name on the record on nobody's authority.
    #[tokio::test]
    async fn a_challenge_without_proved_standing_is_refused_and_not_recorded() {
        let base = mission_base();
        let (mut st, pubkey) = mission_state_at(&base);
        let issuer = decern_crypto::generate().unwrap();
        let stranger = decern_crypto::generate().unwrap();
        st.standing_issuers = Arc::new(vec![issuer.verifying_key()]);

        let token = standing_token(&stranger, "dec-1", "ppid:carol", now_secs() + 3600);
        let req: DecideReq = serde_json::from_str(&format!(
            r#"{{"subject":{{"type":"Principal","id":"agent1"}},
                "action":{{"name":"Read"}},
                "resource":{{"type":"Resource","id":"claim1"}},
                "context":{{"decision_subject":"ppid:carol",
                            "subject_side_challenge":{{
                                "standing_token":"{token}",
                                "decision_ref":"dec-1",
                                "challenge_basis":["factual-error"],
                                "requested_effect":"reverse"}}}}}}"#
        ))
        .unwrap();
        let (status, body) = body_json(decide(State(st.clone()), None, Json(req)).await).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"], "standing_not_proved");

        let ledger_path = base.join("decern-ledger.jsonl");
        let recorded = std::fs::read_to_string(&ledger_path).unwrap_or_default();
        assert!(
            !recorded.contains("dec-1"),
            "an unproved challenge must leave no answer behind: {recorded}"
        );
        let _ = std::fs::remove_dir_all(&base);
        let _ = pubkey;
    }

    /// A third party the record does not otherwise name is carried onto it.
    #[tokio::test]
    async fn a_third_party_decision_subject_is_recorded() {
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        // corp reads a claim corp owns, but the decision is about someone else.
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"corp"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claim1"},
                "context":{"decision_subject":{"handle":"ppid:9c1ea4",
                                               "scheme":"pairwise-sha256",
                                               "purpose":"eligibility-audit"}}}"#,
        )
        .unwrap();
        let (status, body) = body_json(decide(State(st.clone()), None, Json(req)).await).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let ledger_path = base.join("decern-ledger.jsonl");
        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 100).unwrap();
        let last = records.last().expect("decision recorded");
        assert_eq!(last["entry"]["decision_subject"]["handle"], "ppid:9c1ea4");
        assert_eq!(
            last["entry"]["decision_subject"]["purpose"],
            "eligibility-audit"
        );
        // It reached the record, and nothing else: the context the kernel saw, and
        // which the record preserves, must not carry it.
        assert!(
            last["entry"]["context"].get("decision_subject").is_none(),
            "the decision subject must not survive into the evaluated context: {last}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A bare handle is the same claim with less typing.
    #[tokio::test]
    async fn a_bare_handle_is_accepted_as_the_decision_subject() {
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"corp"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claim1"},
                "context":{"decision_subject":"ppid:bare"}}"#,
        )
        .unwrap();
        let (status, body) = body_json(decide(State(st.clone()), None, Json(req)).await).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let ledger_path = base.join("decern-ledger.jsonl");
        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 100).unwrap();
        let last = records.last().expect("decision recorded");
        assert_eq!(last["entry"]["decision_subject"]["handle"], "ppid:bare");
        assert!(last["entry"]["decision_subject"].get("scheme").is_none());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A decision about the requester is already described by the subject, and a
    /// decision about the resource's owner by the resource. Repeating either adds
    /// an identifier and no information, so neither is kept. agent1 acts on a claim
    /// corp owns, so the two cases are distinct here and both are exercised.
    #[tokio::test]
    async fn a_decision_subject_the_record_already_names_is_not_kept() {
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        for handle in ["agent1", "corp"] {
            let req: DecideReq = serde_json::from_str(&format!(
                r#"{{"subject":{{"type":"Principal","id":"agent1"}},
                    "action":{{"name":"Read"}},
                    "resource":{{"type":"Resource","id":"claim1"}},
                    "context":{{"decision_subject":"{handle}"}}}}"#
            ))
            .unwrap();
            let (status, body) = body_json(decide(State(st.clone()), None, Json(req)).await).await;
            assert_eq!(status, StatusCode::OK, "{handle}: {body}");
        }

        let ledger_path = base.join("decern-ledger.jsonl");
        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 100).unwrap();
        assert_eq!(records.len(), 2, "both decisions recorded");
        for rec in &records {
            assert!(
                rec["entry"].get("decision_subject").is_none(),
                "a decision subject the record already names must not be kept: {rec}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The record is appended, signed and chained, so what lands in it stays. A
    /// handle someone could be contacted at is refused at the only moment it can be.
    #[tokio::test]
    async fn decide_refuses_a_decision_subject_that_identifies_a_person() {
        let base = mission_base();
        let (st, _pk) = mission_state_at(&base);
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"corp"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claim1"},
                "context":{"decision_subject":"carol@example.com"}}"#,
        )
        .unwrap();
        let (status, body) = body_json(decide(State(st.clone()), None, Json(req)).await).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "an identifying handle must be refused: {body}"
        );

        let ledger_path = base.join("decern-ledger.jsonl");
        let recorded = std::fs::read_to_string(&ledger_path).unwrap_or_default();
        assert!(
            !recorded.contains("carol@example.com"),
            "a refused handle must never reach the ledger: {recorded}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A caller-supplied `context.asserted_by` look-alike must be stripped before recording.
    /// It must not shadow or coexist with the top-level server-derived `asserted_by` column.
    #[tokio::test]
    async fn forged_context_asserted_by_is_stripped_from_ledger_entry() {
        let base = mission_base();
        let (st, pubkey) = mission_state_at(&base);
        let req: DecideReq = serde_json::from_str(
            r#"{"subject":{"type":"Principal","id":"corp"},
                "action":{"name":"Read"},
                "resource":{"type":"Resource","id":"claim1"},
                "context":{"asserted_by":{"sub":"forged-caller"}}}"#,
        )
        .unwrap();
        let (status, body) = body_json(decide(State(st.clone()), None, Json(req)).await).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let ledger_path = base.join("decern-ledger.jsonl");
        let (_r, records) =
            decern_ledger::read_verified(&ledger_path, Some(&pubkey), 0, 100).unwrap();
        let last = records.last().expect("decision recorded");
        assert!(
            last["entry"]["context"].get("asserted_by").is_none(),
            "caller-supplied asserted_by must be stripped from context: {last}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
