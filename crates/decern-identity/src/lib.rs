// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
#![forbid(unsafe_code)]
//! decern-identity — agent identity intake.
//!
//! An agent principal enters the authority graph by presenting an **Agent
//! Badge**: a W3C VC 2.0-shaped credential carried in a JWS compact
//! serialization (JOSE enveloped proof), signed by a pinned issuer, EdDSA
//! only. Admission then runs the SAME load-time attenuation validation as
//! every other graph change — an agent can only enter by delegation, strictly
//! inside its delegator's authority (tenant, expiry, scopes).
//!
//! Verification order (all fail-closed):
//!   structure → alg allowlist (EdDSA, nothing else — no `none`, no HMAC
//!   confusion) → issuer pin → `verify_strict` over the exact JWS signing input →
//!   only then parse the payload → time window → subject shape.
//!
//! Time is injected (`now`, epoch seconds) — never read from a clock here.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use decern_crypto::{Signer, SigningKey, VerifyingKey};
use decern_kernel::{Kernel, KernelError, Model};
use serde::{Deserialize, Serialize};

/// The native ISSUE side: RFC 8693 token-exchange minting attenuated tokens.
pub mod exchange;
/// The person-centred ISSUE side: approval-backed, attenuation-bound Missions.
pub mod mission;

pub const JWS_ALG: &str = "EdDSA";
pub const JWS_TYP: &str = "vc+jwt";
pub const VC_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
pub const BADGE_TYPE: &str = "AgentBadge";

#[derive(Debug, Serialize, Deserialize)]
pub struct JwsHeader {
    pub alg: String,
    pub typ: String,
    /// Issuer key id: hex of the Ed25519 verifying key. Informational —
    /// the PIN decides trust, but a mismatch is rejected early.
    pub kid: String,
}

/// A Mission reference `(approver, s256)` — carried in a minted token so a
/// mission-issued credential is bindable to, and auditable against, the Mission
/// that authorized it. Absent for plain issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionRef {
    pub approver: String,
    pub s256: String,
}

/// The badge payload: a minimal W3C VC 2.0 Agent Badge.
/// Times are epoch seconds for kernel determinism (the VC datetime strings
/// are a rendering concern, not a kernel one).
///
/// AGNTCY alignment: type includes "AgentBadge", the JWS carrier maps to
/// their CREDENTIAL_ENVELOPE_TYPE_JOSE, and subject ids are free-form (they
/// explicitly allow non-DID ids). Our credentialSubject carries the authority
/// grammar directly (tenant/scopes/delegator/expiry) rather than an OASF
/// definition string; credentialStatus/revocation is v0.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Badge {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    pub issuer: String,
    #[serde(rename = "validFrom")]
    pub valid_from: u64,
    #[serde(rename = "validUntil")]
    pub valid_until: u64,
    #[serde(rename = "credentialSubject")]
    pub subject: BadgeSubject,
    #[serde(
        rename = "credentialSchema",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_schema: Option<Vec<CredentialSchema>>,
    /// The Mission this credential was minted under, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mission: Option<MissionRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSchema {
    pub id: String,
    #[serde(rename = "type")]
    pub schema_type: String,
}

/// The claims that become the Principal's attributes. Same shape as the
/// graph — a badge is a signed, portable delegation grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadgeSubject {
    pub id: String,
    pub kind: String,
    pub tenant: String,
    pub scopes: Vec<String>,
    pub delegator: Option<String>,
    /// The principal's authority expiry (epoch seconds); decays as usual.
    pub expiry: u64,
    /// Downstream binding for an EGRESS credential (the target service id). `None`
    /// on a general-purpose decern token; `Some` restricts the token to one downstream
    /// so a consumer can (and should) enforce it. Backward-compatible: absent on
    /// pre-egress tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("malformed badge: {0}")]
    Malformed(String),
    #[error("algorithm rejected: {0} (only EdDSA is accepted)")]
    AlgRejected(String),
    #[error("issuer key does not match the pinned key")]
    PubkeyMismatch,
    #[error("badge signature invalid")]
    BadSignature,
    #[error("badge not yet valid: now {now} < validFrom {valid_from}")]
    NotYetValid { now: u64, valid_from: u64 },
    #[error("badge expired: now {now} > validUntil {valid_until}")]
    Expired { now: u64, valid_until: u64 },
    #[error("badge subject invalid: {0}")]
    SubjectInvalid(String),
    #[error("principal {0} already exists in the graph (badges never overwrite)")]
    AlreadyExists(String),
    #[error("admission rejected by graph validation:\n{0}")]
    Admission(String),
    #[error("model error during admission: {0}")]
    Model(String),
    /// Carries the underlying [`decern_store::StoreError`] by value (not flattened
    /// to a string) so a caller can tell a client-side conflict — a terminated
    /// mission refusing re-registration ([`decern_store::StoreError::Invalid`]) —
    /// apart from an infrastructure failure ([`decern_store::StoreError::Io`] /
    /// [`decern_store::StoreError::Serde`]) and map them to different HTTP statuses.
    #[error("mission registry error: {0}")]
    Registry(#[from] decern_store::StoreError),
}

/// The one EdDSA compact-JWS signing path behind every decern credential ([`issue`]):
/// build the fixed-shape JOSE header (`alg = EdDSA`,
/// the given `typ` and `kid`), base64url the header and the already-serialized `payload`,
/// sign `header.payload`, and return `header.payload.signature`. The header is a fixed
/// three-string struct, so its serialization is infallible; a caller whose PAYLOAD
/// serialization is fallible (e.g. [`issue`]) serializes it and handles the error first.
fn sign_compact(typ: &str, kid: String, payload: &[u8], key: &SigningKey) -> String {
    let header = JwsHeader {
        alg: JWS_ALG.to_owned(),
        typ: typ.to_owned(),
        kid,
    };
    let h64 = B64URL.encode(serde_json::to_vec(&header).expect("JwsHeader serializes"));
    let p64 = B64URL.encode(payload);
    let signing_input = format!("{h64}.{p64}");
    let sig = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64URL.encode(sig.to_bytes()))
}

/// Sign a badge into a JWS compact serialization (header.payload.signature).
pub fn issue(badge: &Badge, key: &SigningKey) -> Result<String, IdentityError> {
    let payload = serde_json::to_vec(badge).map_err(|e| IdentityError::Malformed(e.to_string()))?;
    Ok(sign_compact(
        JWS_TYP,
        hex_encode(&key.verifying_key()),
        &payload,
        key,
    ))
}

/// Decode a badge's header + payload for OFFLINE INTROSPECTION / DISPLAY only — the
/// signature is NOT checked and the validity window is NOT enforced, so this must NEVER
/// gate a trust decision (use [`verify`] for that). The alg allowlist and typ are still
/// enforced, so an `alg:none`/HMAC/other-typ token is refused rather than shown as a decern
/// badge. Returns `(header, badge)`; `decern introspect` reports expiry/signature itself.
pub fn peek_unverified(jws: &str) -> Result<(JwsHeader, Badge), IdentityError> {
    let parts: Vec<&str> = jws.trim().split('.').collect();
    let [h64, p64, _s64] = parts.as_slice() else {
        return Err(IdentityError::Malformed(
            "expected 3 dot-separated JWS segments".into(),
        ));
    };
    let header_bytes = B64URL
        .decode(h64)
        .map_err(|e| IdentityError::Malformed(format!("header b64: {e}")))?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| IdentityError::Malformed(format!("header: {e}")))?;
    if header.alg != JWS_ALG {
        return Err(IdentityError::AlgRejected(header.alg));
    }
    if header.typ != JWS_TYP {
        return Err(IdentityError::Malformed(format!(
            "unexpected typ {}",
            header.typ
        )));
    }
    let payload_bytes = B64URL
        .decode(p64)
        .map_err(|e| IdentityError::Malformed(format!("payload b64: {e}")))?;
    let badge: Badge = serde_json::from_slice(&payload_bytes)
        .map_err(|e| IdentityError::Malformed(format!("payload: {e}")))?;
    if !badge.types.iter().any(|t| t == BADGE_TYPE) {
        return Err(IdentityError::Malformed(format!(
            "credential type must include {BADGE_TYPE}"
        )));
    }
    Ok((header, badge))
}

/// Verify a badge's ISSUER SIGNATURE against a pinned key — the TIME-INDEPENDENT half of
/// [`verify`]: alg allowlist, typ, kid pin, the Ed25519 signature over the signing input,
/// and a well-formed AgentBadge payload, but NOT the validity window. Split out so
/// `decern introspect` can report the signature verdict SEPARATELY from expiry (an
/// expired-but-authentic badge is a different answer from a forged one). `verify` is
/// exactly this plus the validFrom/validUntil/subject checks — same checks, same order.
pub fn verify_signature(jws: &str, pinned: &VerifyingKey) -> Result<Badge, IdentityError> {
    let parts: Vec<&str> = jws.trim().split('.').collect();
    let [h64, p64, s64] = parts.as_slice() else {
        return Err(IdentityError::Malformed(
            "expected 3 dot-separated JWS segments".into(),
        ));
    };

    let header_bytes = B64URL
        .decode(h64)
        .map_err(|e| IdentityError::Malformed(format!("header b64: {e}")))?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| IdentityError::Malformed(format!("header: {e}")))?;

    // Alg allowlist FIRST: `none`, HMAC and everything else die here,
    // before any byte of the payload is interpreted.
    if header.alg != JWS_ALG {
        return Err(IdentityError::AlgRejected(header.alg));
    }
    if header.typ != JWS_TYP {
        return Err(IdentityError::Malformed(format!(
            "unexpected typ {}",
            header.typ
        )));
    }
    if header.kid != hex_encode(pinned) {
        return Err(IdentityError::PubkeyMismatch);
    }

    let sig_bytes: [u8; 64] = B64URL
        .decode(s64)
        .map_err(|e| IdentityError::Malformed(format!("signature b64: {e}")))?
        .try_into()
        .map_err(|_| IdentityError::Malformed("signature length".into()))?;
    let sig = decern_crypto::Signature::from_bytes(&sig_bytes);

    let signing_input = format!("{h64}.{p64}");
    pinned
        .verify_strict(signing_input.as_bytes(), &sig)
        .map_err(|_| IdentityError::BadSignature)?;

    // Only now is the payload authenticated — parse it.
    let payload_bytes = B64URL
        .decode(p64)
        .map_err(|e| IdentityError::Malformed(format!("payload b64: {e}")))?;
    let badge: Badge = serde_json::from_slice(&payload_bytes)
        .map_err(|e| IdentityError::Malformed(format!("payload: {e}")))?;

    if !badge.types.iter().any(|t| t == BADGE_TYPE) {
        return Err(IdentityError::Malformed(format!(
            "credential type must include {BADGE_TYPE}"
        )));
    }
    Ok(badge)
}

/// Verify a JWS badge against a pinned issuer key at injected time `now`.
pub fn verify(jws: &str, pinned: &VerifyingKey, now: u64) -> Result<Badge, IdentityError> {
    let badge = verify_signature(jws, pinned)?;

    if now < badge.valid_from {
        return Err(IdentityError::NotYetValid {
            now,
            valid_from: badge.valid_from,
        });
    }
    if now > badge.valid_until {
        return Err(IdentityError::Expired {
            now,
            valid_until: badge.valid_until,
        });
    }
    // Delegated authority cannot outlive the credential that grants it.
    if badge.subject.expiry > badge.valid_until {
        return Err(IdentityError::SubjectInvalid(format!(
            "subject expiry {} outlives the badge validUntil {}",
            badge.subject.expiry, badge.valid_until
        )));
    }
    // The kernel graph stores expiry as i64; a u64 above i64::MAX would be read
    // there as negative and rejected at admission with a misleading "missing or
    // negative expiry". Reject it here so verify() and admit() agree on range.
    if badge.subject.expiry > i64::MAX as u64 {
        return Err(IdentityError::SubjectInvalid(format!(
            "subject expiry {} exceeds the maximum representable value {}",
            badge.subject.expiry,
            i64::MAX
        )));
    }

    Ok(badge)
}

/// Verify a badge and admit its subject into the model's authority graph.
/// Returns the new model (the old one is untouched) plus the verified badge.
/// Admission = the same fail-closed validation as any model load: the agent
/// must enter by delegation, strictly inside its delegator's authority.
pub fn admit(
    model: &Model,
    jws: &str,
    pinned: &VerifyingKey,
    now: u64,
) -> Result<(Model, Badge), IdentityError> {
    let badge = verify(jws, pinned, now)?;
    let s = &badge.subject;

    if s.kind != "Agent" {
        return Err(IdentityError::SubjectInvalid(format!(
            "only Agent badges are admissible, got kind {}",
            s.kind
        )));
    }
    let Some(delegator) = &s.delegator else {
        return Err(IdentityError::SubjectInvalid(
            "an agent enters the graph only by delegation (no delegator claim)".into(),
        ));
    };

    let mut new_model = model.clone();
    let entities = new_model
        .entities
        .as_array_mut()
        .ok_or_else(|| IdentityError::Model("entities is not a JSON array".into()))?;

    let exists = entities.iter().any(|e| {
        e.get("uid")
            .map(|u| {
                u.get("type") == Some(&"Principal".into())
                    && u.get("id") == Some(&s.id.clone().into())
            })
            .unwrap_or(false)
    });
    if exists {
        return Err(IdentityError::AlreadyExists(s.id.clone()));
    }

    entities.push(serde_json::json!({
        "uid": {"type": "Principal", "id": s.id},
        "attrs": {
            "kind": s.kind,
            "tenant": s.tenant,
            "expiry": s.expiry,
            "scopes": s.scopes,
            "delegator": {"__entity": {"type": "Principal", "id": delegator}},
        },
        "parents": [],
    }));

    // The gate: full kernel load, including the attenuation validator.
    match Kernel::new(&new_model) {
        Ok(_) => Ok((new_model, badge)),
        Err(KernelError::Graph(v)) => Err(IdentityError::Admission(v)),
        Err(e) => Err(IdentityError::Model(e.to_string())),
    }
}

fn hex_encode(key: &VerifyingKey) -> String {
    key.to_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use decern_kernel::EntityRef;
    use serde_json::json;

    fn issuer() -> SigningKey {
        decern_crypto::generate().expect("keygen")
    }

    fn badge(id: &str, scopes: &[&str], expiry: u64) -> Badge {
        Badge {
            context: vec![VC_CONTEXT.to_owned()],
            id: Some(format!("urn:decern:badge:{id}")),
            types: vec!["VerifiableCredential".into(), BADGE_TYPE.into()],
            issuer: "did:decern:issuer".into(),
            valid_from: 50,
            valid_until: 10_000,
            credential_schema: None,
            mission: None,
            subject: BadgeSubject {
                id: id.into(),
                kind: "Agent".into(),
                tenant: "A".into(),
                scopes: scopes.iter().map(|s| s.to_string()).collect(),
                delegator: Some("corp".into()),
                expiry,
                aud: None,
            },
        }
    }

    /// The Ed25519 identity point plus `R = identity, S = 0` satisfies the
    /// cofactorless equation for every message. `verify` accepts that pair;
    /// `verify_strict` does not. This is the one path that admits a principal
    /// into the graph, so it must use the stricter check — the same one the
    /// ledger already uses.
    #[test]
    fn a_small_order_key_cannot_authenticate_a_badge() {
        use decern_crypto::Verifier;

        let mut identity = [0u8; 32];
        identity[0] = 1;
        let key = VerifyingKey::from_bytes(&identity).expect("identity is a valid encoding");
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 1;
        let sig = decern_crypto::Signature::from_bytes(&sig_bytes);

        let payload = serde_json::to_vec(&badge("forged", &["read", "move_money"], 200)).unwrap();
        let header = json!({
            "alg": JWS_ALG,
            "typ": JWS_TYP,
            "kid": hex_encode(&key),
        });
        let h64 = B64URL.encode(serde_json::to_vec(&header).unwrap());
        let p64 = B64URL.encode(payload);
        let signing_input = format!("{h64}.{p64}");
        assert!(
            key.verify(signing_input.as_bytes(), &sig).is_ok(),
            "the forgery must pass the cofactorless check, or this test proves nothing"
        );
        let jws = format!("{signing_input}.{}", B64URL.encode(sig_bytes));
        assert!(
            matches!(
                verify(&jws, &key, 100).unwrap_err(),
                IdentityError::BadSignature
            ),
            "a small-order key must not admit a badge"
        );
    }

    #[test]
    fn roundtrip_verifies() {
        let key = issuer();
        let jws = issue(&badge("agent9", &["read"], 200), &key).unwrap();
        let b = verify(&jws, &key.verifying_key(), 100).unwrap();
        assert_eq!(b.subject.id, "agent9");
    }

    #[test]
    fn tampered_payload_rejected() {
        let key = issuer();
        let jws = issue(&badge("agent9", &["read"], 200), &key).unwrap();
        let mut parts: Vec<String> = jws.split('.').map(str::to_owned).collect();
        // swap in an escalated payload without re-signing
        let mut b = badge("agent9", &["read", "move_money"], 200);
        b.subject.tenant = "A".into();
        parts[1] = B64URL.encode(serde_json::to_vec(&b).unwrap());
        let forged = parts.join(".");
        assert!(matches!(
            verify(&forged, &key.verifying_key(), 100).unwrap_err(),
            IdentityError::BadSignature
        ));
    }

    #[test]
    fn alg_none_and_hmac_rejected_before_signature_check() {
        let key = issuer();
        let jws = issue(&badge("agent9", &["read"], 200), &key).unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        for alg in ["none", "HS256", "ES256"] {
            let hdr = json!({"alg": alg, "typ": JWS_TYP,
                             "kid": super::hex_encode(&key.verifying_key())});
            let h64 = B64URL.encode(serde_json::to_vec(&hdr).unwrap());
            let forged = format!("{h64}.{}.{}", parts[1], parts[2]);
            assert!(matches!(
                verify(&forged, &key.verifying_key(), 100).unwrap_err(),
                IdentityError::AlgRejected(_)
            ));
        }
    }

    #[test]
    fn wrong_issuer_rejected() {
        let key = issuer();
        let attacker = issuer();
        let jws = issue(&badge("agent9", &["read"], 200), &attacker).unwrap();
        assert!(matches!(
            verify(&jws, &key.verifying_key(), 100).unwrap_err(),
            IdentityError::PubkeyMismatch
        ));
    }

    #[test]
    fn time_window_enforced() {
        let key = issuer();
        let jws = issue(&badge("agent9", &["read"], 200), &key).unwrap();
        assert!(matches!(
            verify(&jws, &key.verifying_key(), 10).unwrap_err(),
            IdentityError::NotYetValid { .. }
        ));
        assert!(matches!(
            verify(&jws, &key.verifying_key(), 20_000).unwrap_err(),
            IdentityError::Expired { .. }
        ));
    }

    #[test]
    fn subject_outliving_credential_rejected() {
        let key = issuer();
        let mut b = badge("agent9", &["read"], 200);
        b.subject.expiry = 99_999; // > valid_until 10_000
        let jws = issue(&b, &key).unwrap();
        assert!(matches!(
            verify(&jws, &key.verifying_key(), 100).unwrap_err(),
            IdentityError::SubjectInvalid(_)
        ));
    }

    #[test]
    fn expiry_beyond_i64_max_rejected() {
        let key = issuer();
        // A u64 expiry above i64::MAX: verify() must reject it (aligning with the
        // kernel's i64 graph domain) rather than pass and let admit() fail.
        let mut b = badge("agent9", &["read"], u64::MAX);
        b.valid_until = u64::MAX; // pass the "outlives" and Expired checks first
        let jws = issue(&b, &key).unwrap();
        let err = verify(&jws, &key.verifying_key(), 100).unwrap_err();
        assert!(matches!(err, IdentityError::SubjectInvalid(_)));
        assert!(err.to_string().contains("representable"), "{err}");
    }

    #[test]
    fn admitted_agent_can_act_within_grant() {
        let key = issuer();
        let jws = issue(&badge("agent9", &["read"], 200), &key).unwrap();
        let (model, _) = admit(&Model::builtin(), &jws, &key.verifying_key(), 100).unwrap();
        let k = Kernel::new(&model).unwrap();
        let r = k.check(
            &EntityRef {
                ty: "Principal".into(),
                id: "agent9".into(),
            },
            "Read",
            &EntityRef {
                ty: "Resource".into(),
                id: "claim1".into(),
            },
            &json!({"now": 100}),
        );
        assert!(r.decision, "{r:?}");
        // and its grant decays like any authority
        let r = k.check(
            &EntityRef {
                ty: "Principal".into(),
                id: "agent9".into(),
            },
            "Read",
            &EntityRef {
                ty: "Resource".into(),
                id: "claim1".into(),
            },
            &json!({"now": 500}),
        );
        assert!(!r.decision);
    }

    #[test]
    fn escalating_badge_refused_at_admission() {
        let key = issuer();
        // corp (delegator) has read+move_money; try to mint MORE
        let mut b = badge("agent9", &["read", "move_money", "root_everything"], 200);
        b.subject.expiry = 200;
        let jws = issue(&b, &key).unwrap();
        let err = admit(&Model::builtin(), &jws, &key.verifying_key(), 100).unwrap_err();
        assert!(matches!(err, IdentityError::Admission(_)), "{err}");
        assert!(err.to_string().contains("exceed"), "{err}");
    }

    #[test]
    fn badge_for_existing_principal_refused() {
        let key = issuer();
        let jws = issue(&badge("agent1", &["read"], 200), &key).unwrap();
        assert!(matches!(
            admit(&Model::builtin(), &jws, &key.verifying_key(), 100).unwrap_err(),
            IdentityError::AlreadyExists(_)
        ));
    }

    #[test]
    fn badge_without_delegation_refused() {
        let key = issuer();
        let mut b = badge("agent9", &["read"], 200);
        b.subject.delegator = None;
        let jws = issue(&b, &key).unwrap();
        assert!(matches!(
            admit(&Model::builtin(), &jws, &key.verifying_key(), 100).unwrap_err(),
            IdentityError::SubjectInvalid(_)
        ));
    }
}
