// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! A challenge from the party a decision was made about.
//!
//! Recording who a decision affected gives that party a name on the record and nothing
//! else. This is the other half: they can say the decision was wrong, and be answered.
//!
//! The whole surface is descriptive. A challenge is evaluated and answered, and it never
//! becomes an input to whether something is permitted — that separation is why a forged
//! challenge cannot escalate anything, and it is enforced by taking the challenge out of
//! the context before the kernel is called rather than by remembering not to read it.
//!
//! Standing is proved with a signed token, verified against issuer keys the operator
//! configured. Fetching them from an issuer at request time would mean an outbound call and
//! a TLS stack, neither of which this binary carries, and would make every decision depend
//! on a third party being reachable. A deployment that cannot phone home can still tell
//! whether a token was signed by an issuer it already trusts.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Why a challenge could not be considered. Each one is a refusal to answer, never a
/// decision about the underlying request: a malformed challenge leaves the decision it
/// names exactly as it was.
#[derive(Debug, PartialEq, Eq)]
pub enum ChallengeError {
    Malformed(String),
    StandingNotProved(String),
    NotBound(String),
}

impl ChallengeError {
    pub fn detail(&self) -> &str {
        match self {
            Self::Malformed(d) | Self::StandingNotProved(d) | Self::NotBound(d) => d,
        }
    }

    /// The short, stable label a caller can branch on.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed_challenge",
            Self::StandingNotProved(_) => "standing_not_proved",
            Self::NotBound(_) => "challenge_not_bound_to_decision",
        }
    }
}

/// What a standing token asserts: this bearer is the party a particular decision was about.
/// It grants nothing — the authority to have a decision looked at again lives in the answer
/// this server gives, not in the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Standing {
    /// The decision this standing is for. A token is good for one decision, not for a role.
    pub decision_ref: String,
    /// The pseudonymous handle of the party, matched against what the record already says.
    pub decision_subject: String,
    /// Expiry, epoch seconds.
    pub exp: u64,
    /// The capacity the party holds standing in, recorded but not interpreted here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_party_role: Option<String>,
}

/// A challenge as it arrives in the decision context.
#[derive(Debug, Clone)]
pub struct Challenge {
    pub standing: Standing,
    pub decision_ref: String,
    pub basis: Vec<String>,
    pub evidence: Option<Value>,
    pub requested_effect: String,
}

/// How the challenge was answered.
///
/// Two of these are produced here. Handing a challenge to a human approver is the third
/// shape the surface can take, and it needs an approver service this server does not have;
/// a deployment that has one says so in its disclosure. Claiming it while routing nowhere
/// would be worse than not offering it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The decision stands, and the reason it stands is stated.
    AffirmPriorDecision { affirm_basis: String },
    /// The decision was made again with the challenge in front of it, and the answer that
    /// came back governs — whether or not it changed.
    ReevaluateWithSubjectContext { reevaluation_basis: String },
}

/// Take the challenge out of the context, if one is there.
///
/// Removal is unconditional and happens before anything else looks at it, so a request
/// carrying a challenge is evaluated exactly as the same request without one. A challenge
/// that could reach the kernel would be an authorization input by accident, which is the
/// one thing this must never be.
pub fn take_raw(ctx: &mut Value) -> Option<Value> {
    ctx.as_object_mut()
        .and_then(|o| o.remove("subject_side_challenge"))
        .filter(|v| !v.is_null())
}

/// Parse a challenge and prove the standing it claims.
///
/// Order matters and is fail-closed at every step: shape, then the token's signature under
/// a key the operator already trusts, then expiry, then that the token and the challenge
/// name the same decision. A token that proves standing for one decision must not answer
/// for another.
pub fn parse(
    raw: &Value,
    issuer_keys: &[VerifyingKey],
    now: u64,
) -> Result<Challenge, ChallengeError> {
    let obj = raw
        .as_object()
        .ok_or_else(|| ChallengeError::Malformed("challenge must be an object".into()))?;

    let token = obj
        .get("standing_token")
        .and_then(Value::as_str)
        .ok_or_else(|| ChallengeError::Malformed("standing_token is required".into()))?;
    let decision_ref = obj
        .get("decision_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| ChallengeError::Malformed("decision_ref is required".into()))?
        .to_owned();
    let basis: Vec<String> = match obj.get("challenge_basis") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => {
            return Err(ChallengeError::Malformed(
                "challenge_basis is required".into(),
            ));
        }
    };
    if basis.is_empty() {
        return Err(ChallengeError::Malformed(
            "challenge_basis must name at least one basis".into(),
        ));
    }
    let requested_effect = obj
        .get("requested_effect")
        .and_then(Value::as_str)
        .ok_or_else(|| ChallengeError::Malformed("requested_effect is required".into()))?
        .to_owned();

    let standing = verify_standing(token, issuer_keys, now)?;
    if standing.decision_ref != decision_ref {
        return Err(ChallengeError::NotBound(format!(
            "standing proves the party for decision {}, the challenge names {decision_ref}",
            standing.decision_ref
        )));
    }

    Ok(Challenge {
        standing,
        decision_ref,
        basis,
        evidence: obj.get("challenge_evidence").cloned(),
        requested_effect,
    })
}

/// Verify a compact JWS carrying a standing token, against keys the operator configured.
///
/// Written out rather than delegated because the alternative is a JWT library and, for key
/// discovery, an HTTP client and a TLS stack — three dependencies in the trusted path of a
/// binary whose whole claim is that it is auditable. The accepted algorithm is exactly one,
/// checked before anything else: a token declaring some other algorithm, or none, is
/// refused rather than verified under an assumption about what it meant.
fn verify_standing(
    token: &str,
    issuer_keys: &[VerifyingKey],
    now: u64,
) -> Result<Standing, ChallengeError> {
    if issuer_keys.is_empty() {
        return Err(ChallengeError::StandingNotProved(
            "this deployment accepts no standing issuers, so standing cannot be proved".into(),
        ));
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ChallengeError::StandingNotProved(
            "standing_token is not a compact JWS".into(),
        ));
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    let header: BTreeMap<String, Value> = decode_json(header_b64, "header")?;
    match header.get("alg").and_then(Value::as_str) {
        Some("EdDSA") => {}
        Some(other) => {
            return Err(ChallengeError::StandingNotProved(format!(
                "standing_token algorithm {other} is not accepted here"
            )));
        }
        None => {
            return Err(ChallengeError::StandingNotProved(
                "standing_token names no algorithm".into(),
            ));
        }
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| ChallengeError::StandingNotProved("signature is not base64url".into()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| ChallengeError::StandingNotProved("signature is not 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_arr);
    let signed = format!("{header_b64}.{payload_b64}");

    if !issuer_keys
        .iter()
        .any(|k| k.verify_strict(signed.as_bytes(), &signature).is_ok())
    {
        return Err(ChallengeError::StandingNotProved(
            "standing_token is not signed by an issuer this deployment trusts".into(),
        ));
    }

    let claims: BTreeMap<String, Value> = decode_json(payload_b64, "claims")?;
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| ChallengeError::StandingNotProved("standing_token has no exp".into()))?;
    if exp <= now {
        return Err(ChallengeError::StandingNotProved(format!(
            "standing_token expired at {exp}"
        )));
    }

    Ok(Standing {
        decision_ref: string_claim(&claims, "decision_ref")?,
        decision_subject: string_claim(&claims, "decision_subject")?,
        exp,
        affected_party_role: claims
            .get("affected_party_role")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn decode_json<T: for<'de> Deserialize<'de>>(part: &str, what: &str) -> Result<T, ChallengeError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| ChallengeError::StandingNotProved(format!("{what} is not base64url")))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ChallengeError::StandingNotProved(format!("{what} is not JSON")))
}

fn string_claim(claims: &BTreeMap<String, Value>, name: &str) -> Result<String, ChallengeError> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ChallengeError::StandingNotProved(format!("standing_token has no {name}")))
}

/// Answer a challenge against the decision it names.
///
/// A challenge that offers something the decision could be made differently on gets the
/// decision made again; one that does not gets the prior answer and the reason it stands.
/// Both are answers. Neither is a promise that the outcome will change, and re-evaluation
/// governs whether or not it does.
///
/// `subject_matches` is whether the record's own decision subject is the party the standing
/// names. A challenge from someone the record was not about is answered, not obeyed: it
/// affirms, because there is nothing here to reconsider on their behalf.
pub fn answer(challenge: &Challenge, subject_matches: bool) -> Outcome {
    if !subject_matches {
        return Outcome::AffirmPriorDecision {
            affirm_basis: "the challenged decision does not name this party as its subject".into(),
        };
    }
    // Only a basis that puts something new in front of the decision can change it. The
    // rest are disagreements with the outcome rather than with what it was made from.
    let reconsiderable = [
        "factual-error",
        "category-mismatch",
        "change-in-circumstances",
    ];
    match challenge
        .basis
        .iter()
        .find(|b| reconsiderable.contains(&b.as_str()))
    {
        Some(b) => Outcome::ReevaluateWithSubjectContext {
            reevaluation_basis: b.clone(),
        },
        None => Outcome::AffirmPriorDecision {
            affirm_basis: format!(
                "no basis given ({}) bears on the facts the decision was made from",
                challenge.basis.join(", ")
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decern_crypto::generate;

    fn sign(claims: Value, key: &decern_crypto::SigningKey) -> String {
        use ed25519_dalek::Signer as _;
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let s = URL_SAFE_NO_PAD.encode(key.sign(format!("{h}.{p}").as_bytes()).to_bytes());
        format!("{h}.{p}.{s}")
    }

    fn claims(decision_ref: &str, exp: u64) -> Value {
        serde_json::json!({
            "decision_ref": decision_ref,
            "decision_subject": "ppid:carol",
            "exp": exp,
            "affected_party_role": "applicant",
        })
    }

    fn challenge_json(token: &str, decision_ref: &str, basis: &str) -> Value {
        serde_json::json!({
            "standing_token": token,
            "decision_ref": decision_ref,
            "challenge_basis": [basis],
            "requested_effect": "mark-for-human-review",
        })
    }

    #[test]
    fn a_well_formed_challenge_with_proved_standing_parses() {
        let key = generate().unwrap();
        let token = sign(claims("dec-1", 2_000), &key);
        let c = parse(
            &challenge_json(&token, "dec-1", "factual-error"),
            &[key.verifying_key()],
            1_000,
        )
        .unwrap();
        assert_eq!(c.standing.decision_subject, "ppid:carol");
        assert_eq!(c.decision_ref, "dec-1");
    }

    /// Standing for one decision must not answer for another, or a token issued over any
    /// decision would be a token over all of them.
    #[test]
    fn standing_for_one_decision_does_not_carry_to_another() {
        let key = generate().unwrap();
        let token = sign(claims("dec-1", 2_000), &key);
        let err = parse(
            &challenge_json(&token, "dec-2", "factual-error"),
            &[key.verifying_key()],
            1_000,
        )
        .unwrap_err();
        assert_eq!(err.kind(), "challenge_not_bound_to_decision");
    }

    #[test]
    fn a_token_from_an_untrusted_issuer_proves_nothing() {
        let issuer = generate().unwrap();
        let stranger = generate().unwrap();
        let token = sign(claims("dec-1", 2_000), &stranger);
        let err = parse(
            &challenge_json(&token, "dec-1", "factual-error"),
            &[issuer.verifying_key()],
            1_000,
        )
        .unwrap_err();
        assert_eq!(err.kind(), "standing_not_proved");
    }

    #[test]
    fn an_expired_token_proves_nothing() {
        let key = generate().unwrap();
        let token = sign(claims("dec-1", 500), &key);
        let err = parse(
            &challenge_json(&token, "dec-1", "factual-error"),
            &[key.verifying_key()],
            1_000,
        )
        .unwrap_err();
        assert_eq!(err.kind(), "standing_not_proved");
        assert!(err.detail().contains("expired"));
    }

    /// The signature is over the exact header and payload sent. Swapping the header for one
    /// that names a weaker algorithm must not verify — and must be refused before the
    /// signature is examined at all.
    #[test]
    fn an_algorithm_this_deployment_does_not_accept_is_refused() {
        let key = generate().unwrap();
        let token = sign(claims("dec-1", 2_000), &key);
        let payload = token.split('.').nth(1).unwrap();
        let sig = token.split('.').nth(2).unwrap();
        let forged_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let forged = format!("{forged_header}.{payload}.{sig}");

        let err = parse(
            &challenge_json(&forged, "dec-1", "factual-error"),
            &[key.verifying_key()],
            1_000,
        )
        .unwrap_err();
        assert_eq!(err.kind(), "standing_not_proved");
        assert!(err.detail().contains("not accepted"));
    }

    /// A deployment that trusts no issuer cannot have standing proved to it, and says so
    /// rather than accepting a token it cannot check.
    #[test]
    fn with_no_configured_issuers_standing_cannot_be_proved() {
        let key = generate().unwrap();
        let token = sign(claims("dec-1", 2_000), &key);
        let err = parse(
            &challenge_json(&token, "dec-1", "factual-error"),
            &[],
            1_000,
        )
        .unwrap_err();
        assert_eq!(err.kind(), "standing_not_proved");
    }

    #[test]
    fn a_basis_bearing_on_the_facts_reopens_the_decision() {
        let key = generate().unwrap();
        let token = sign(claims("dec-1", 2_000), &key);
        let c = parse(
            &challenge_json(&token, "dec-1", "factual-error"),
            &[key.verifying_key()],
            1_000,
        )
        .unwrap();
        assert!(matches!(
            answer(&c, true),
            Outcome::ReevaluateWithSubjectContext { .. }
        ));
    }

    #[test]
    fn a_basis_that_only_disputes_the_outcome_gets_an_answer_and_the_prior_decision() {
        let key = generate().unwrap();
        let token = sign(claims("dec-1", 2_000), &key);
        let c = parse(
            &challenge_json(&token, "dec-1", "regulatory-objection"),
            &[key.verifying_key()],
            1_000,
        )
        .unwrap();
        assert!(matches!(
            answer(&c, true),
            Outcome::AffirmPriorDecision { .. }
        ));
    }

    /// Proved standing over a decision that was not about you is still standing over
    /// nothing: it is answered rather than acted on.
    #[test]
    fn standing_over_a_decision_about_someone_else_affirms() {
        let key = generate().unwrap();
        let token = sign(claims("dec-1", 2_000), &key);
        let c = parse(
            &challenge_json(&token, "dec-1", "factual-error"),
            &[key.verifying_key()],
            1_000,
        )
        .unwrap();
        assert!(matches!(
            answer(&c, false),
            Outcome::AffirmPriorDecision { .. }
        ));
    }

    #[test]
    fn take_raw_removes_the_challenge_whatever_it_contains() {
        let mut ctx = serde_json::json!({ "now": 1, "subject_side_challenge": "anything" });
        assert!(take_raw(&mut ctx).is_some());
        assert!(
            ctx.get("subject_side_challenge").is_none(),
            "removal must not depend on the challenge being valid"
        );
    }
}
