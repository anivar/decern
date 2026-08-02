// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! decern-identity::mission — the person-centred ISSUE mode: an approval-backed
//! authorization context.
//!
//! A Mission is a scoped authorization context an APPROVER (a human / delegating
//! principal) grants to an AGENT: an explicit, hashed, referenceable record of
//! "these tools, for this purpose, until this time." Its reference is
//! `(approver, s256)`; it has exactly two states (active | terminated) and carries
//! `approved_tools` and `capabilities`.
//!
//! **Attenuation is ALWAYS on**: a Mission's `approved_tools` must be a subset of
//! what the approver actually holds in the graph — an approver cannot approve
//! authority they do not have — and its expiry cannot outlive theirs. Every Mission
//! is therefore provably bounded. Tokens minted under a Mission are further
//! attenuated to `approved_tools` and re-read the approver's CURRENT graph node on
//! every mint — so renewal is re-evaluation, and there is no refresh token to revoke.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use decern_crypto::SigningKey;
use decern_kernel::Model;
use decern_store::{MissionEntry, MissionRegistry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::IdentityError;
use crate::exchange::{
    ExchangeRequest, Exchanged, delegator_attrs, exchange, reserved_subject_id_prefix,
};

/// The approved blob: exactly what an approver authorizes. Its canonical
/// serialization is hashed into the Mission reference `s256`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Mission {
    /// Principal id that authorized the mission (the delegator / person).
    pub approver: String,
    /// Principal id the mission authorizes to act.
    pub agent: String,
    /// When it was approved (epoch secs). A recorded FACT about the approval, NOT part
    /// of the authority: `#[serde(skip)]` keeps it out of the hashed blob so the mission
    /// reference `s256` is a pure function of the authority (approver, agent, description,
    /// approved_tools, capabilities, expiry) and is therefore identical across a retry of
    /// the same approve request. It is recorded in the ledger context instead.
    #[serde(skip)]
    pub approved_at: u64,
    /// Human-readable purpose.
    pub description: String,
    /// The tools/scopes approved — MUST be ⊆ the approver's own scopes.
    pub approved_tools: Vec<String>,
    /// Free-form capability tags (informational; not a policy input).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Mission authority expiry (epoch secs); cannot outlive the approver's.
    pub expiry: u64,
}

/// A Mission has exactly two states: `active`, and `terminated` (the state termination
/// transitions it into, and which it can never revert from).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MissionState {
    Active,
    Terminated,
}

/// An approved Mission: the exact approved bytes, a parsed view, its state, and
/// its `(approver, s256)` reference. `s256` is the base64url-no-pad SHA-256 of the
/// **exact approved-blob bytes, captured once** — so the bytes are stored and never
/// re-derived from the struct (serde ordering/escaping is not a guaranteed-stable
/// canonicalization; re-serializing could silently break the reference). `mission`
/// is a parsed view over those same bytes.
#[derive(Debug, Clone)]
pub struct ApprovedMission {
    pub mission: Mission,
    pub state: MissionState,
    /// base64url-no-pad SHA-256 of `blob` — the `s256` half of the mission reference.
    pub s256: String,
    /// The exact bytes `s256` is over. The approver's approval is over these.
    blob: Vec<u8>,
}

impl ApprovedMission {
    /// The mission reference: `(approver, s256)`.
    pub fn reference(&self) -> (&str, &str) {
        (&self.mission.approver, &self.s256)
    }

    /// The exact approved-blob bytes `s256` is computed over.
    pub fn approved_blob(&self) -> &[u8] {
        &self.blob
    }

    /// Transition to terminated. A terminated Mission mints no further tokens.
    ///
    /// The in-memory flip alone is not authoritative — a token minted from a stale
    /// or reconstructed handle would not see it. Pass the [`MissionRegistry`] the
    /// mission was approved into so the termination is PERSISTED and propagates:
    /// [`issue_under_mission`] then refuses to mint under it, across handles and
    /// processes. `None` flips only the in-memory state (test/library convenience).
    pub fn terminate(
        &mut self,
        registry: Option<&dyn MissionRegistry>,
        now: u64,
    ) -> Result<(), IdentityError> {
        self.state = MissionState::Terminated;
        if let Some(reg) = registry {
            reg.terminate(&self.s256, now)?;
        }
        Ok(())
    }
}

/// Approve a Mission against the graph. Fail-closed: every approved tool must be
/// one the approver actually holds, and the mission cannot outlive the approver's
/// authority. The returned Mission is therefore provably bounded.
///
/// When a [`MissionRegistry`] is supplied the approval is RECORDED (active, keyed by
/// its `s256`) so that a later mint can verify the mission reference names a real,
/// live approval — and so a termination is effective beyond this handle. Registering
/// an `s256` already present as terminated is refused by the registry, and an
/// already-expired mission is refused outright — so a terminated grant cannot revive,
/// even after its tombstone is GC-evicted at expiry.
pub fn approve(
    model: &Model,
    mission: Mission,
    now: u64,
    registry: Option<&dyn MissionRegistry>,
) -> Result<ApprovedMission, IdentityError> {
    let (_, expiry, scopes) = delegator_attrs(model, &mission.approver).ok_or_else(|| {
        IdentityError::SubjectInvalid(format!(
            "approver {} is not a principal in the graph",
            mission.approver
        ))
    })?;

    // Attenuation, fail-closed — the approver cannot approve authority they lack.
    for t in &mission.approved_tools {
        if !scopes.contains(t) {
            return Err(IdentityError::SubjectInvalid(format!(
                "mission approves `{t}`, which approver {} does not hold",
                mission.approver
            )));
        }
    }
    if mission.expiry > expiry {
        return Err(IdentityError::SubjectInvalid(format!(
            "mission expiry {} outlives approver {} authority ({expiry})",
            mission.expiry, mission.approver
        )));
    }
    // An already-expired mission must never be approved. `now` is authoritative
    // (server-set). Without this guard, a terminated mission whose registry tombstone
    // has been GC-evicted after its own expiry could be re-approved with the identical
    // blob and re-registered as Active — a revival. Refusing a dead mission at the
    // source makes termination and expiry jointly monotone (see decern-store's
    // terminated-tombstone retention for the store-layer half of the same guarantee).
    if mission.expiry <= now {
        return Err(IdentityError::SubjectInvalid(format!(
            "mission expiry {} is not in the future (now {now}); an expired mission cannot be approved",
            mission.expiry
        )));
    }

    // Capture the approved bytes ONCE, hash those exact bytes, and keep them.
    // The stored blob — not the struct — is the thing `s256` commits to.
    let blob = serde_json::to_vec(&mission).map_err(|e| IdentityError::Malformed(e.to_string()))?;
    let s256 = B64URL.encode(Sha256::digest(&blob));

    if let Some(reg) = registry {
        reg.register(
            &s256,
            MissionEntry {
                approver: mission.approver.clone(),
                expiry: mission.expiry,
                terminated: false,
            },
            now,
        )?;
    }

    Ok(ApprovedMission {
        mission,
        state: MissionState::Active,
        s256,
        blob,
    })
}

/// Mint a token under a Mission: attenuated to `approved_tools` (themselves ⊆ the
/// approver's authority), re-reading the approver's CURRENT graph node — so a
/// renewal reflects any revocation or decay applied to the approver since
/// approval. Refused once the Mission is completed.
///
/// When a [`MissionRegistry`] is supplied it is the AUTHORITATIVE liveness check:
/// the mission reference (`s256`) must resolve to a registered, non-terminated
/// approval whose approver matches. This is what stops a forged/stale reference
/// (or a mission terminated in another process) from riding into a minted token and
/// its audit trail. Without a registry only the in-memory `state` is consulted
/// (test/library convenience) — a live minting deployment MUST pass the registry.
pub fn issue_under_mission(
    model: &Model,
    m: &ApprovedMission,
    sub_agent_id: &str,
    requested_scopes: &[String],
    now: u64,
    issuer_key: &SigningKey,
    registry: Option<&dyn MissionRegistry>,
) -> Result<Exchanged, IdentityError> {
    // `sub_agent_id` is exactly as caller-influenced as plain token-exchange's
    // `sub_agent` (this function's own signature takes it as a bare `&str`, no
    // provenance marker), so the reserved-prefix guard that closes the equivalent
    // forgery in `decern-server::issuance::token_exchange` MUST apply here too:
    // without it, the same identity-namespace forgery
    // (`sub_agent_id="fed:native:<domain>:<victim>"`) would reopen the instant a
    // Mission-grant HTTP endpoint lets a caller choose it. It is enforced here, at
    // the actual choke point every Mission-grant caller passes through, rather than
    // trusted to be re-implemented correctly by every future handler.
    if let Some(prefix) = reserved_subject_id_prefix(sub_agent_id) {
        return Err(IdentityError::SubjectInvalid(format!(
            "sub_agent_id may not use the reserved `{prefix}` identity-namespace prefix — that \
             namespace is minted exclusively by federation/native-login or ID-JAG redemption; a \
             Mission-grant delegation must not be able to forge an identity into it"
        )));
    }
    if m.state != MissionState::Active {
        return Err(IdentityError::SubjectInvalid(
            "mission is terminated; it mints no further tokens".into(),
        ));
    }
    if let Some(reg) = registry {
        // The reference must name a live registered approval. An unknown s256 is a
        // forged/never-approved reference; a terminated one is a killed mission; an
        // approver mismatch is a reference stitched onto the wrong principal. (An
        // expired mission has been GC'd from the registry, so it reads as unknown.)
        match reg.status(&m.s256)? {
            None => {
                return Err(IdentityError::SubjectInvalid(format!(
                    "mission reference {} names no registered approval",
                    m.s256
                )));
            }
            Some(entry) if entry.terminated => {
                return Err(IdentityError::SubjectInvalid(format!(
                    "mission {} is terminated in the registry; it mints no further tokens",
                    m.s256
                )));
            }
            Some(entry) if entry.approver != m.mission.approver => {
                return Err(IdentityError::SubjectInvalid(format!(
                    "mission {} registered approver {} does not match {}",
                    m.s256, entry.approver, m.mission.approver
                )));
            }
            Some(_) => {}
        }
    }
    // Ceiling is the mission's approved_tools ∩ what was requested. exchange()
    // then re-narrows to the approver's live scopes (a no-op here, since
    // approved_tools ⊆ approver at approval) and clamps expiry — belt and braces.
    let scoped: Vec<String> = requested_scopes
        .iter()
        .filter(|s| m.mission.approved_tools.contains(s))
        .cloned()
        .collect();
    exchange(
        model,
        &ExchangeRequest {
            delegator_id: &m.mission.approver,
            sub_agent_id,
            requested_scopes: &scoped,
            requested_expiry: m.mission.expiry,
            now,
            // Bind the token to the Mission that authorized it.
            mission: Some(crate::MissionRef {
                approver: m.mission.approver.clone(),
                s256: m.s256.clone(),
            }),
            aud: None,
        },
        issuer_key,
        // A Mission grant is entitled to NO reserved namespace — it already refused
        // any reserved-prefix `sub_agent_id` above; the funnel's own guard is the backstop.
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // corp holds read + move_money in the builtin graph.
    fn corp_expiry() -> u64 {
        delegator_attrs(&Model::builtin(), "corp").unwrap().1
    }

    fn mission(tools: &[&str], expiry: u64) -> Mission {
        Mission {
            approver: "corp".into(),
            agent: "agent-mission".into(),
            approved_at: 100,
            description: "reconcile Q3 invoices".into(),
            approved_tools: scopes(tools),
            capabilities: vec![],
            expiry,
        }
    }

    #[test]
    fn approve_rejects_tool_the_approver_lacks() {
        let m = mission(&["read", "root_everything"], corp_expiry());
        let err = approve(&Model::builtin(), m, 100, None).unwrap_err();
        assert!(matches!(err, IdentityError::SubjectInvalid(_)));
        assert!(err.to_string().contains("root_everything"), "{err}");
    }

    #[test]
    fn approve_rejects_expiry_beyond_approver() {
        let m = mission(&["read"], corp_expiry() + 1);
        assert!(matches!(
            approve(&Model::builtin(), m, 100, None).unwrap_err(),
            IdentityError::SubjectInvalid(_)
        ));
    }

    #[test]
    fn approve_refuses_an_already_expired_mission() {
        // Guard: an expiry at-or-before `now` is a dead mission and must be refused.
        // Identity-layer half of closing the terminated-grant revival — a terminated
        // mission whose registry tombstone is GC-evicted after its own expiry can never
        // be re-approved back into Active.
        let err = approve(&Model::builtin(), mission(&["read"], 1_000), 1_000, None).unwrap_err();
        assert!(
            matches!(err, IdentityError::SubjectInvalid(_)),
            "expiry == now: {err}"
        );
        let err = approve(&Model::builtin(), mission(&["read"], 1_000), 5_000, None).unwrap_err();
        assert!(
            matches!(err, IdentityError::SubjectInvalid(_)),
            "expiry < now: {err}"
        );
    }

    #[test]
    fn no_post_expiry_revival_of_a_terminated_mission() {
        // approve (future expiry) → terminate → advance past expiry → an identical
        // re-approval must be refused, not re-registered as Active.
        let reg = decern_store::MemoryMissionRegistry::new();
        let mut m = approve(
            &Model::builtin(),
            mission(&["read"], 1_000),
            100,
            Some(&reg),
        )
        .unwrap();
        m.terminate(Some(&reg), 100).unwrap();
        let err = approve(
            &Model::builtin(),
            mission(&["read"], 1_000),
            5_000,
            Some(&reg),
        )
        .unwrap_err();
        assert!(
            matches!(err, IdentityError::SubjectInvalid(_)),
            "an identical, now-expired grant must not revive to Active: {err}"
        );
    }

    #[test]
    fn approve_ok_and_reference_is_stable() {
        let a = approve(
            &Model::builtin(),
            mission(&["read"], corp_expiry()),
            100,
            None,
        )
        .unwrap();
        assert_eq!(a.state, MissionState::Active);
        let (approver, s256) = a.reference();
        assert_eq!(approver, "corp");
        assert!(!s256.is_empty());
        // deterministic: same authority → same reference
        let b = approve(
            &Model::builtin(),
            mission(&["read"], corp_expiry()),
            100,
            None,
        )
        .unwrap();
        assert_eq!(a.s256, b.s256);

        // B2 property (a): the reference is a pure function of the AUTHORITY, not of
        // approval time. The same approve request at a LATER wall-clock second (a 503
        // retry crossing a second boundary) carries a different `approved_at` and a
        // different `now`, yet MUST produce the SAME `s256` — otherwise a retry would
        // mint a second live mission while the first stays active-but-unrecorded.
        let mut later = mission(&["read"], corp_expiry());
        later.approved_at = 999_999;
        let c = approve(&Model::builtin(), later, 999_999, None).unwrap();
        assert_eq!(
            a.s256, c.s256,
            "s256 must be invariant to approved_at / now (retry idempotence)"
        );
    }

    #[test]
    fn token_is_bounded_by_approved_tools_even_when_approver_holds_more() {
        // corp holds move_money, but the mission approved only read.
        let m = approve(
            &Model::builtin(),
            mission(&["read"], corp_expiry()),
            100,
            None,
        )
        .unwrap();
        let out = issue_under_mission(
            &Model::builtin(),
            &m,
            "sub-agent-1",
            &scopes(&["read", "move_money"]),
            100,
            &decern_crypto::generate().unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(out.badge.subject.scopes, vec!["read".to_string()]);
        // the minted token is bound to its Mission (the mission reference).
        let mref = out
            .badge
            .mission
            .as_ref()
            .expect("token carries mission ref");
        assert_eq!(mref.approver, "corp");
        assert_eq!(mref.s256, m.s256);
    }

    /// Regression test: the reserved identity-namespace check closing `decern-server`'s
    /// token-exchange forgery path was NOT mirrored here, so `issue_under_mission` —
    /// reachable via the Mission grant path the moment a Mission-grant HTTP endpoint is
    /// wired up — would silently reopen the exact same forgery
    /// (`sub_agent_id="fed:native:<domain>:<victim>"`). Verified at the actual
    /// choke point, not merely at one HTTP handler.
    #[test]
    fn issue_under_mission_refuses_a_reserved_identity_namespace() {
        let m = approve(
            &Model::builtin(),
            mission(&["read"], corp_expiry()),
            100,
            None,
        )
        .unwrap();
        for forged in ["fed:native:acme:victim", "id-jag:corp:client-x"] {
            let err = match issue_under_mission(
                &Model::builtin(),
                &m,
                forged,
                &scopes(&["read"]),
                100,
                &decern_crypto::generate().unwrap(),
                None,
            ) {
                Ok(_) => panic!("sub_agent_id={forged} must be refused"),
                Err(e) => e,
            };
            assert!(
                matches!(&err, IdentityError::SubjectInvalid(msg) if msg.contains("reserved")),
                "{err}"
            );
        }
    }

    #[test]
    fn terminated_mission_mints_nothing() {
        let mut m = approve(
            &Model::builtin(),
            mission(&["read"], corp_expiry()),
            100,
            None,
        )
        .unwrap();
        m.terminate(None, 100).unwrap();
        let r = issue_under_mission(
            &Model::builtin(),
            &m,
            "sub-agent-2",
            &scopes(&["read"]),
            100,
            &decern_crypto::generate().unwrap(),
            None,
        );
        assert!(matches!(r, Err(IdentityError::SubjectInvalid(_))));
    }

    // --------------------- registry-backed mission binding ---------------------

    fn mint_once(
        m: &ApprovedMission,
        reg: Option<&dyn MissionRegistry>,
    ) -> Result<Exchanged, IdentityError> {
        issue_under_mission(
            &Model::builtin(),
            m,
            "sub-agent",
            &scopes(&["read"]),
            100,
            &decern_crypto::generate().unwrap(),
            reg,
        )
    }

    // `Exchanged` is not `Debug`, so `.unwrap_err()` won't compile — extract by match.
    fn mint_err(m: &ApprovedMission, reg: Option<&dyn MissionRegistry>) -> IdentityError {
        match mint_once(m, reg) {
            Ok(_) => panic!("expected the mint to be refused"),
            Err(e) => e,
        }
    }

    #[test]
    fn registry_backed_mission_mints_then_termination_stops_it() {
        let reg = decern_store::MemoryMissionRegistry::new();
        let mut m = approve(
            &Model::builtin(),
            mission(&["read"], corp_expiry()),
            100,
            Some(&reg),
        )
        .unwrap();
        // active + registered → mints
        assert!(
            mint_once(&m, Some(&reg)).is_ok(),
            "active registered mission mints"
        );

        // terminate through the registry — now the AUTHORITATIVE state says no.
        m.terminate(Some(&reg), 100).unwrap();
        let err = mint_err(&m, Some(&reg));
        assert!(matches!(err, IdentityError::SubjectInvalid(_)), "{err}");
    }

    #[test]
    fn registry_termination_stops_mint_even_from_a_stale_active_handle() {
        // The core guarantee: a fresh handle that still THINKS it is active must
        // not mint once the mission is terminated in the shared registry.
        let reg = decern_store::MemoryMissionRegistry::new();
        let m = approve(
            &Model::builtin(),
            mission(&["read"], corp_expiry()),
            100,
            Some(&reg),
        )
        .unwrap();
        assert_eq!(
            m.state,
            MissionState::Active,
            "this handle still reads active"
        );
        // someone else terminates it in the registry (no access to this handle)
        reg.terminate(&m.s256, 100).unwrap();
        let err = mint_err(&m, Some(&reg));
        assert!(
            matches!(err, IdentityError::SubjectInvalid(_)),
            "a stale active handle must not out-vote the registry: {err}"
        );
    }

    #[test]
    fn forged_mission_reference_names_no_approval_and_is_refused() {
        // A well-formed ApprovedMission whose s256 was never registered — the exact
        // "hand-built reference" case. With a registry present, it must be refused.
        let reg = decern_store::MemoryMissionRegistry::new();
        // approve WITHOUT registering (registry = None), then mint WITH the registry.
        let m = approve(
            &Model::builtin(),
            mission(&["read"], corp_expiry()),
            100,
            None,
        )
        .unwrap();
        let err = mint_err(&m, Some(&reg));
        assert!(
            matches!(err, IdentityError::SubjectInvalid(_)),
            "an unregistered mission reference must be refused: {err}"
        );
        assert!(err.to_string().contains("no registered approval"), "{err}");
    }
}
