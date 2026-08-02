// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! decern-identity::exchange — the native ISSUE side: an RFC 8693 token-exchange
//! that mints an *attenuated* agent credential.
//!
//! Each issued token is a delegation edge whose authority is strictly inside the
//! delegator's. That bound is enforced TWICE — defence in depth:
//!   1. by construction here: child scopes = requested ∩ delegator-held, child
//!      expiry = min(requested, delegator), same tenant;
//!   2. by the load-time attenuation PROOF in [`crate::admit`], which refuses the
//!      credential if it ever exceeds its delegator (the kernel's SMT-checked
//!      attenuation-edge invariant).
//!
//! Downstream authority is ALWAYS bounded by upstream — a delegate can never exceed
//! its delegator — and that boundedness is exactly decern's proven invariant. The
//! authority ceiling is read from the delegator's CURRENT graph node — so revocation
//! and decay already applied to the delegator flow into every token minted from it,
//! not stale token claims.

use decern_crypto::SigningKey;
use decern_kernel::Model;
use serde_json::Value;

use crate::{BADGE_TYPE, Badge, BadgeSubject, IdentityError, MissionRef, VC_CONTEXT, admit, issue};

/// An RFC 8693 token-exchange request. `delegator_id` is the principal proving
/// current authority (the `subject_token` subject, already in the graph);
/// `sub_agent_id` is the new child the credential is minted for.
pub struct ExchangeRequest<'a> {
    pub delegator_id: &'a str,
    pub sub_agent_id: &'a str,
    /// Scopes the child asks for; silently narrowed to those the delegator holds.
    pub requested_scopes: &'a [String],
    /// Requested child expiry (epoch secs); clamped to the delegator's expiry.
    pub requested_expiry: u64,
    /// Injected wall-clock (epoch secs) — never read from a clock here.
    pub now: u64,
    /// The Mission this token is minted under, if any — stamped into the badge
    /// so it is bindable/auditable. `None` for plain (non-mission) exchange.
    pub mission: Option<MissionRef>,
    /// Audience restriction for the minted token (the badge subject's `aud`). Set by
    /// callers that mint a token bound to one downstream — e.g. an EMA ID-JAG
    /// redemption pins it to the target MCP Server's `resource`. `None` = a general
    /// decern token usable wherever its authority admits it.
    pub aud: Option<String>,
}

/// The result: the signed child credential (compact JWS) and the graph with the
/// child admitted. That the admission SUCCEEDED is the proof the delegation is
/// attenuated — the same gate every decern graph change passes.
pub struct Exchanged {
    pub token: String,
    pub badge: Badge,
    pub model: Model,
}

/// Subject-id prefixes reserved for a specific, cryptographically-verified
/// provenance path — never mintable through plain, caller-driven token exchange:
/// `fed:<issuer>:<subject>` (federation / native-login), `id-jag:<sub>:<client>`
/// (EMA ID-JAG redemption), `oauth:<client_id>:<subject>` (OAuth 2.1
/// authorization-code — a third-party-client-scoped child, deliberately namespaced
/// so it can never match `fed:native:<domain>:` prefix-matching and be replayed at
/// a self-service native-auth endpoint), and `spiffe://<trust_domain>/<path>`
/// (workload SVID, gated on a controller-binding registry check plain token
/// exchange has no knowledge of). Downstream code treats a subject id matching one
/// of these prefixes as PROOF of that stronger provenance purely by string shape.
/// So every caller-influenced `sub_agent_id` (plain token-exchange's `sub_agent`,
/// and a Mission-grant's `sub_agent_id`) MUST be checked against this list with
/// [`reserved_subject_id_prefix`] before being accepted, or it could forge an
/// identity into a namespace it never earned.
///
/// [`exchange`] enforces this at the funnel: it refuses any `sub_agent_id` matching
/// a reserved prefix UNLESS that prefix is in the caller's `allowed_reserved_prefixes`
/// entitlement. A plain, caller-driven exchange passes `&[]` and so can mint into no
/// reserved namespace at all; only a verified-provenance mint path (federation /
/// ID-JAG redemption / OAuth code / SVID) passes the single prefix it is entitled to.
/// The entitlement is a SEPARATE argument, never a field on the request: it states
/// what THIS mint path may produce, and must not be carried alongside the untrusted
/// `sub_agent_id` it authorizes. [`crate::mission::issue_under_mission`] additionally
/// refuses reserved prefixes before it ever reaches here (it is entitled to none), so
/// the funnel check is its backstop. Keep this list and both guards even though no
/// mint path in this crate currently produces these prefixes: dropping them would
/// silently re-open the forgery the instant such a path returns.
pub const RESERVED_SUBJECT_ID_PREFIXES: &[&str] = &["fed:", "id-jag:", "oauth:", "spiffe://"];

/// The reserved prefix `id` matches, if any — see [`RESERVED_SUBJECT_ID_PREFIXES`].
pub fn reserved_subject_id_prefix(id: &str) -> Option<&'static str> {
    RESERVED_SUBJECT_ID_PREFIXES
        .iter()
        .find(|p| id.starts_with(**p))
        .copied()
}

/// The attenuation clamp for a token-exchange delegation: the requested scopes
/// narrowed to what the delegator actually holds, and the requested expiry
/// capped at the delegator's own. Pure — no signing, no admit-proof, no I/O —
/// so both the real mint (`exchange`, below) and any dry-run caller can share it
/// without either reimplementing this or invoking the other's side effects.
pub fn clamp_delegation(
    del_scopes: &[String],
    del_expiry: u64,
    requested_scopes: &[String],
    requested_expiry: u64,
) -> (Vec<String>, u64) {
    let scopes: Vec<String> = requested_scopes
        .iter()
        .filter(|s| del_scopes.contains(s))
        .cloned()
        .collect();
    let expiry = requested_expiry.min(del_expiry);
    (scopes, expiry)
}

/// Read a Principal's `(tenant, expiry, scopes)` from the model's entity array.
///
/// `pub`, not `pub(crate)`: any dry-run caller must resolve the delegator from this
/// SAME function against this SAME model type — reading tenant/scopes/expiry any
/// other way (e.g. from the overlay-merged `Directory`) would let a preview diverge
/// from what `exchange` above would actually grant, since `exchange` is only ever
/// called against the boot-pinned base model, never the live directory overlay.
pub fn delegator_attrs(model: &Model, id: &str) -> Option<(String, u64, Vec<String>)> {
    for e in model.entities.as_array()? {
        let uid = e.get("uid")?;
        if uid.get("type") == Some(&Value::from("Principal"))
            && uid.get("id") == Some(&Value::from(id))
        {
            let attrs = e.get("attrs")?;
            let tenant = attrs.get("tenant")?.as_str()?.to_owned();
            let expiry = attrs.get("expiry")?.as_u64()?;
            let scopes = attrs
                .get("scopes")?
                .as_array()?
                .iter()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect();
            return Some((tenant, expiry, scopes));
        }
    }
    None
}

/// Mint an attenuated child credential delegated by `delegator_id`.
///
/// `allowed_reserved_prefixes` is THIS mint path's identity-namespace entitlement —
/// the reserved prefixes (see [`RESERVED_SUBJECT_ID_PREFIXES`]) it is permitted to
/// mint into. A plain, caller-driven exchange passes `&[]`; a verified-provenance
/// path passes the single prefix it earned. A `sub_agent_id` in a reserved namespace
/// the caller is not entitled to is refused here, at the funnel — closing the
/// identity forgery uniformly rather than trusting each entry point to re-check it.
pub fn exchange(
    model: &Model,
    req: &ExchangeRequest,
    issuer_key: &SigningKey,
    allowed_reserved_prefixes: &[&str],
) -> Result<Exchanged, IdentityError> {
    // Funnel guard: a caller-influenced `sub_agent_id` may not forge an identity into
    // a reserved-provenance namespace this mint path is not entitled to produce.
    if let Some(prefix) = reserved_subject_id_prefix(req.sub_agent_id)
        && !allowed_reserved_prefixes.contains(&prefix)
    {
        return Err(IdentityError::SubjectInvalid(format!(
            "sub_agent_id may not use the reserved `{prefix}` identity-namespace prefix — \
                 this mint path is not entitled to it"
        )));
    }

    // A mission binding is an accountability claim; it must be vouched by the
    // party actually delegating this token. Anyone could otherwise stamp
    // "approved by ceo" onto a token corp delegated. The legitimate mission path
    // always sets approver == delegator, so this only rejects forgeries. (Full
    // binding — that s256 names a live approved mission — needs the mission
    // registry, tracked with the mission-gated audit work.)
    if let Some(m) = &req.mission
        && m.approver != req.delegator_id
    {
        return Err(IdentityError::SubjectInvalid(format!(
            "mission approver {} does not match delegator {}: a token's mission \
                 binding must be vouched by its own delegator",
            m.approver, req.delegator_id
        )));
    }

    let (tenant, del_expiry, del_scopes) =
        delegator_attrs(model, req.delegator_id).ok_or_else(|| {
            IdentityError::SubjectInvalid(format!(
                "delegator {} is not a principal in the graph",
                req.delegator_id
            ))
        })?;

    // Attenuate by construction: only scopes the delegator holds, only as long
    // as the delegator's own authority lasts.
    let (scopes, expiry) = clamp_delegation(
        &del_scopes,
        del_expiry,
        req.requested_scopes,
        req.requested_expiry,
    );

    let badge = Badge {
        context: vec![VC_CONTEXT.to_owned()],
        id: Some(format!("urn:decern:token:{}", req.sub_agent_id)),
        types: vec!["VerifiableCredential".into(), BADGE_TYPE.into()],
        issuer: "did:decern:issuer".into(),
        valid_from: req.now,
        valid_until: expiry,
        credential_schema: None,
        mission: req.mission.clone(),
        subject: BadgeSubject {
            id: req.sub_agent_id.to_owned(),
            kind: "Agent".into(),
            tenant,
            scopes,
            delegator: Some(req.delegator_id.to_owned()),
            expiry,
            aud: req.aud.clone(),
        },
    };

    let token = issue(&badge, issuer_key)?;
    // The proof gate: admit runs the kernel's load-time attenuation validator.
    // If by-construction attenuation ever regressed, this refuses the token.
    let (new_model, verified) = admit(model, &token, &issuer_key.verifying_key(), req.now)?;
    Ok(Exchanged {
        token,
        badge: verified,
        model: new_model,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use decern_kernel::{EntityRef, Kernel};

    fn scopes(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // `corp` is a builtin principal holding read + move_money.
    fn req<'a>(sub: &'a str, want: &'a [String], expiry: u64, now: u64) -> ExchangeRequest<'a> {
        ExchangeRequest {
            delegator_id: "corp",
            sub_agent_id: sub,
            requested_scopes: want,
            requested_expiry: expiry,
            now,
            mission: None,
            aud: None,
        }
    }

    #[test]
    fn narrows_to_delegator_held_scopes() {
        let key = decern_crypto::generate().unwrap();
        // ask for a scope corp does NOT hold — it is silently dropped.
        let want = scopes(&["read", "root_everything"]);
        let out = exchange(
            &Model::builtin(),
            &req("agentX", &want, 300, 100),
            &key,
            &[],
        )
        .unwrap();
        assert_eq!(out.badge.subject.scopes, vec!["read".to_string()]);
        assert!(
            !out.badge
                .subject
                .scopes
                .contains(&"root_everything".to_string())
        );
    }

    #[test]
    fn clamps_expiry_to_delegator() {
        let key = decern_crypto::generate().unwrap();
        let want = scopes(&["read"]);
        // request a far-future expiry; child is clamped to corp's own expiry.
        let out = exchange(
            &Model::builtin(),
            &req("agentY", &want, u64::MAX, 100),
            &key,
            &[],
        )
        .unwrap();
        let (_, corp_expiry, _) = delegator_attrs(&Model::builtin(), "corp").unwrap();
        assert_eq!(out.badge.subject.expiry, corp_expiry);
        assert!(out.badge.valid_until <= corp_expiry);
    }

    #[test]
    fn issued_child_is_a_proven_node_that_can_act() {
        let key = decern_crypto::generate().unwrap();
        let want = scopes(&["read"]);
        let out = exchange(
            &Model::builtin(),
            &req("agentZ", &want, 300, 100),
            &key,
            &[],
        )
        .unwrap();
        // the returned model has the child admitted — it decides like any node.
        let k = Kernel::new(&out.model).unwrap();
        let r = k.check(
            &EntityRef {
                ty: "Principal".into(),
                id: "agentZ".into(),
            },
            "Read",
            &EntityRef {
                ty: "Resource".into(),
                id: "claim1".into(),
            },
            &serde_json::json!({"now": 100}),
        );
        assert!(r.decision, "{r:?}");
    }

    #[test]
    fn unknown_delegator_refused() {
        let key = decern_crypto::generate().unwrap();
        let want = scopes(&["read"]);
        let r = exchange(
            &Model::builtin(),
            &ExchangeRequest {
                delegator_id: "ghost",
                sub_agent_id: "agentG",
                requested_scopes: &want,
                requested_expiry: 300,
                now: 100,
                mission: None,
                aud: None,
            },
            &key,
            &[],
        );
        assert!(matches!(r, Err(IdentityError::SubjectInvalid(_))));
    }

    #[test]
    fn forged_mission_binding_refused() {
        let key = decern_crypto::generate().unwrap();
        let want = scopes(&["read"]);
        // corp delegates the token, but the caller claims "ceo approved" it.
        let r = exchange(
            &Model::builtin(),
            &ExchangeRequest {
                delegator_id: "corp",
                sub_agent_id: "agentF",
                requested_scopes: &want,
                requested_expiry: 200,
                now: 100,
                mission: Some(crate::MissionRef {
                    approver: "ceo".into(),
                    s256: "deadbeef".into(),
                }),
                aud: None,
            },
            &key,
            &[],
        );
        assert!(matches!(r, Err(IdentityError::SubjectInvalid(_))));
    }

    #[test]
    fn child_cannot_out_scope_delegator_even_if_all_requested() {
        let key = decern_crypto::generate().unwrap();
        // request EVERYTHING corp has plus more; result is exactly corp's set,
        // and the admit proof gate confirms child ⊆ delegator.
        let want = scopes(&["read", "move_money", "root_everything", "delete_all"]);
        let out = exchange(
            &Model::builtin(),
            &req("agentM", &want, 200, 100),
            &key,
            &[],
        )
        .unwrap();
        for s in &out.badge.subject.scopes {
            assert!(
                matches!(s.as_str(), "read" | "move_money"),
                "leaked scope {s}"
            );
        }
    }

    #[test]
    fn plain_exchange_refuses_a_reserved_identity_namespace() {
        // A caller-driven exchange entitled to NO reserved namespace (`&[]`) must not
        // let `sub_agent_id` forge an identity into one — the funnel guard the whole
        // reserved-prefix list exists for. Verified for every reserved prefix.
        let key = decern_crypto::generate().unwrap();
        let want = scopes(&["read"]);
        for forged in [
            "fed:native:acme:victim",
            "id-jag:corp:client-x",
            "spiffe://acme/x",
        ] {
            let err = exchange(&Model::builtin(), &req(forged, &want, 200, 100), &key, &[])
                .err()
                .expect("a reserved-prefix sub_agent_id must be refused");
            assert!(
                matches!(&err, IdentityError::SubjectInvalid(msg) if msg.contains("reserved")),
                "{err}"
            );
        }
    }

    #[test]
    fn an_entitled_mint_path_may_produce_its_reserved_namespace() {
        // The escape hatch that keeps the guard above non-vacuous: a mint path entitled
        // to `fed:` may mint a `fed:` subject id, while still being refused a namespace
        // it did not earn (`id-jag:`). The child is delegated by corp and admitted under
        // corp's scopes — the reserved prefix governs only the child's identity namespace.
        let key = decern_crypto::generate().unwrap();
        let want = scopes(&["read"]);
        let out = exchange(
            &Model::builtin(),
            &req("fed:native:acme:svc", &want, 200, 100),
            &key,
            &["fed:"],
        )
        .expect("an entitled fed: mint path is allowed its own namespace");
        assert_eq!(out.badge.subject.id, "fed:native:acme:svc");
        // …but the same entitlement does not extend to a different reserved namespace.
        let err = exchange(
            &Model::builtin(),
            &req("id-jag:corp:client", &want, 200, 100),
            &key,
            &["fed:"],
        )
        .err()
        .expect("an id-jag: id is refused to a fed:-only mint path");
        assert!(
            matches!(&err, IdentityError::SubjectInvalid(msg) if msg.contains("reserved")),
            "{err}"
        );
    }
}
