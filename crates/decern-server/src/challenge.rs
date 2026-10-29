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
pub(crate) enum ChallengeError {
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
pub(crate) struct Standing {
    /// The decision this standing is for. A token is good for one decision, not for a role.
    pub(crate) decision_ref: String,
    /// The pseudonymous handle of the party, matched against the parties the decision's record
    /// is about.
    pub(crate) decision_subject: String,
    /// Expiry in whole epoch seconds. The check uses `exp` as sent, fraction included; what is
    /// kept is truncated, and an `exp` past `u64::MAX` is kept as `u64::MAX`.
    pub(crate) exp: u64,
    /// The capacity the party holds standing in, recorded but not interpreted here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) affected_party_role: Option<String>,
}

/// A challenge as it arrives in the decision context.
#[derive(Debug, Clone)]
pub(crate) struct Challenge {
    pub(crate) standing: Standing,
    pub(crate) decision_ref: String,
    pub(crate) basis: Vec<String>,
    pub(crate) evidence: Option<Value>,
    pub(crate) requested_effect: String,
}

/// How the challenge was answered. Neither outcome evaluates the decision again: the
/// kernel ran once, without the challenge, and the decision stands as recorded. A challenge
/// is classified only when its standing names a party the decision's record is about and a
/// basis it gives bears on the facts the decision was made from; any other is affirmed, with
/// the reason. The record `decision_ref` names is not read.
///
/// Two of these are produced here. Handing a challenge to a human approver is the third
/// shape the surface can take, and it needs an approver service this server does not have;
/// a deployment that has one says so in its disclosure. Claiming it while routing nowhere
/// would be worse than not offering it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The standing names no party the decision's record is about, or no basis given bears
    /// on the facts the decision was made from; which of the two is stated.
    AffirmPriorDecision { affirm_basis: String },
    /// The standing names a party the decision's record is about, and a basis given bears on
    /// the facts the decision was made from; that basis is named. The decision is not
    /// made again here; acting on the challenge falls to whoever reads it.
    ChallengeClassified { classified_basis: String },
}

impl Outcome {
    const AFFIRM: &'static str = "affirm_prior_decision";
    const CLASSIFIED: &'static str = "challenge_classified";
    /// Every outcome's name as its record carries it, for the disclosure to list.
    pub(crate) const NAMES: [&'static str; 2] = [Self::AFFIRM, Self::CLASSIFIED];

    /// The outcome's name as its record carries it, and the basis it states.
    pub(crate) fn into_record(self) -> (&'static str, String) {
        match self {
            Outcome::AffirmPriorDecision { affirm_basis } => (Self::AFFIRM, affirm_basis),
            Outcome::ChallengeClassified { classified_basis } => {
                (Self::CLASSIFIED, classified_basis)
            }
        }
    }
}

/// The challenge bases that bear on the facts a decision was made from. Any other basis
/// disagrees with the outcome rather than with what it was made from.
pub(crate) const BASES_ON_THE_FACTS: [&str; 3] = [
    "factual-error",
    "category-mismatch",
    "change-in-circumstances",
];

/// Take the challenge out of the context, if one is there.
///
/// Removal is unconditional and happens before anything else looks at it, so a request
/// carrying a challenge is evaluated exactly as the same request without one. A challenge
/// that could reach the kernel would be an authorization input by accident, which is the
/// one thing this must never be.
pub(crate) fn take_raw(ctx: &mut Value) -> Option<Value> {
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
pub(crate) fn parse(
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
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                ChallengeError::Malformed("challenge_basis items must be strings".into())
            })?,
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

    let header: BTreeMap<String, Value> = crate::jose::decode_json(header_b64, "header")
        .map_err(ChallengeError::StandingNotProved)?;
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
    // An access token is not proof of standing. Where one issuer key signs both, a bearer
    // token replayed here would otherwise verify — same algorithm, same key — and turn
    // "may call this server" into "is the party this decision was about".
    if let Some(typ) = header.get("typ").and_then(Value::as_str)
        && (typ.eq_ignore_ascii_case("at+jwt") || typ.eq_ignore_ascii_case("application/at+jwt"))
    {
        return Err(ChallengeError::StandingNotProved(
            "an access token is not a standing token".into(),
        ));
    }
    crate::jose::refuse_crit(&header, "standing_token")
        .map_err(ChallengeError::StandingNotProved)?;

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

    let claims: BTreeMap<String, Value> = crate::jose::decode_json(payload_b64, "claims")
        .map_err(ChallengeError::StandingNotProved)?;
    // NumericDates (RFC 7519 §2), so a fractional `exp` is an expiry, not a missing one, and
    // an `nbf` that is present gates (§4.1.5).
    let exp = crate::jose::numeric_date(&claims, "exp", "standing_token")
        .map_err(ChallengeError::StandingNotProved)?
        .ok_or_else(|| ChallengeError::StandingNotProved("standing_token has no exp".into()))?;
    if now as f64 >= exp {
        return Err(ChallengeError::StandingNotProved(format!(
            "standing_token expired at {exp}"
        )));
    }
    if let Some(nbf) = crate::jose::numeric_date(&claims, "nbf", "standing_token")
        .map_err(ChallengeError::StandingNotProved)?
        && (now as f64) < nbf
    {
        return Err(ChallengeError::StandingNotProved(format!(
            "standing_token is not valid before {nbf}"
        )));
    }

    Ok(Standing {
        decision_ref: string_claim(&claims, "decision_ref")?,
        decision_subject: string_claim(&claims, "decision_subject")?,
        exp: exp as u64,
        affected_party_role: claims
            .get("affected_party_role")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn string_claim(claims: &BTreeMap<String, Value>, name: &str) -> Result<String, ChallengeError> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ChallengeError::StandingNotProved(format!("standing_token has no {name}")))
}

/// Answer a challenge against the decision it names, by classifying its basis.
///
/// A challenge whose basis bears on the facts the decision was made from is classified as
/// such; one whose basis does not gets the prior answer and the reason it stands. Both are
/// answers, and neither changes the decision.
///
/// `about` is the parties the decision's record is about: the third party it keeps as its
/// decision subject, or, when it keeps none, its requester and its resource's owner. A
/// challenge from anyone else is answered, not obeyed: it affirms, because there is nothing
/// here to reconsider on their behalf.
pub(crate) fn answer(challenge: &Challenge, about: &[&str]) -> Outcome {
    if !about.contains(&challenge.standing.decision_subject.as_str()) {
        return Outcome::AffirmPriorDecision {
            affirm_basis: "the challenge's standing names no party the decision's record is \
                           about"
                .into(),
        };
    }
    match challenge
        .basis
        .iter()
        .find(|b| BASES_ON_THE_FACTS.contains(&b.as_str()))
    {
        Some(b) => Outcome::ChallengeClassified {
            classified_basis: b.clone(),
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
        sign_with(r#"{"alg":"EdDSA","typ":"JWT"}"#, claims, key)
    }

    /// A validly signed token under any header, so a refusal is the header's doing.
    fn sign_with(header: &str, claims: Value, key: &decern_crypto::SigningKey) -> String {
        use ed25519_dalek::Signer as _;
        let h = URL_SAFE_NO_PAD.encode(header);
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let s = URL_SAFE_NO_PAD.encode(key.sign(format!("{h}.{p}").as_bytes()).to_bytes());
        format!("{h}.{p}.{s}")
    }

    fn parse_at_1000(
        token: &str,
        key: &decern_crypto::SigningKey,
    ) -> Result<Challenge, ChallengeError> {
        parse(
            &challenge_json(token, "dec-1", "factual-error"),
            &[key.verifying_key()],
            1_000,
        )
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

    /// A `challenge_basis` array with an item that is not a string is malformed, not a shorter
    /// list: a challenge that is not well formed is refused as such, never classified.
    #[test]
    fn a_basis_array_with_a_non_string_item_is_malformed() {
        let key = generate().unwrap();
        let token = sign(claims("dec-1", 2_000), &key);
        let mut raw = challenge_json(&token, "dec-1", "factual-error");
        raw["challenge_basis"] = serde_json::json!(["factual-error", 5]);
        let e = parse(&raw, &[key.verifying_key()], 1_000).unwrap_err();
        assert!(
            matches!(e, ChallengeError::Malformed(_)) && e.detail().contains("challenge_basis"),
            "{}",
            e.detail()
        );
    }

    /// Same key, same algorithm, different contract: a bearer access token replayed as a
    /// standing token must fail on its `typ`, not verify on its signature.
    #[test]
    fn an_access_token_does_not_prove_standing() {
        let key = generate().unwrap();
        let token = sign_with(
            r#"{"alg":"EdDSA","typ":"at+jwt"}"#,
            claims("dec-1", 2_000),
            &key,
        );
        let e = parse_at_1000(&token, &key).unwrap_err();
        assert!(
            e.detail().contains("access token"),
            "refusal must name the confusion: {}",
            e.detail()
        );
    }

    /// RFC 7515 Appendix E, with `EdDSA` for its `none` (which is refused earlier, on the
    /// algorithm): a JWS naming an extension the recipient does not understand is invalid,
    /// however well signed.
    #[test]
    fn a_token_naming_a_critical_extension_is_refused() {
        let key = generate().unwrap();
        let token = sign_with(
            r#"{"alg":"EdDSA","crit":["http://example.invalid/UNDEFINED"],"http://example.invalid/UNDEFINED":true}"#,
            claims("dec-1", 2_000),
            &key,
        );
        let e = parse_at_1000(&token, &key).unwrap_err();
        assert_eq!(e.kind(), "standing_not_proved");
        assert!(
            e.detail().contains("critical header extension"),
            "{}",
            e.detail()
        );
    }

    /// RFC 7515 §4: a header parameter that is not critical and not understood is ignored,
    /// so the header set stays open.
    #[test]
    fn a_header_parameter_that_is_not_critical_is_ignored() {
        let key = generate().unwrap();
        let token = sign_with(
            r#"{"alg":"EdDSA","typ":"JWT","kid":"k1","x-issuer-note":"anything"}"#,
            claims("dec-1", 2_000),
            &key,
        );
        assert!(parse_at_1000(&token, &key).is_ok());
    }

    /// RFC 7519 §4.1.5: an `nbf` that is present gates; one in the past does not.
    #[test]
    fn a_token_not_yet_valid_proves_nothing() {
        let key = generate().unwrap();
        let mut early = claims("dec-1", 2_000);
        early["nbf"] = serde_json::json!(1_500);
        let e = parse_at_1000(&sign(early, &key), &key).unwrap_err();
        assert!(e.detail().contains("not valid before"), "{}", e.detail());

        let mut ready = claims("dec-1", 2_000);
        ready["nbf"] = serde_json::json!(999.5);
        assert!(parse_at_1000(&sign(ready, &key), &key).is_ok());
    }

    /// RFC 7519 §4.1.4 and §4.1.5 at the instant itself: a token is refused at its `exp`,
    /// and accepted at its `nbf`.
    #[test]
    fn exp_and_nbf_hold_at_their_own_instant() {
        let key = generate().unwrap();
        let mut at_exp = claims("dec-1", 1_000);
        at_exp["nbf"] = serde_json::json!(900);
        let e = parse_at_1000(&sign(at_exp, &key), &key).unwrap_err();
        assert!(e.detail().contains("expired"), "{}", e.detail());

        let mut at_nbf = claims("dec-1", 2_000);
        at_nbf["nbf"] = serde_json::json!(1_000);
        assert!(parse_at_1000(&sign(at_nbf, &key), &key).is_ok());
    }

    /// An `exp` beyond what `u64` holds is a far expiry under RFC 7519, not a missing one.
    #[test]
    fn an_exp_past_u64_is_a_far_expiry() {
        let key = generate().unwrap();
        let mut far = claims("dec-1", 0);
        far["exp"] = serde_json::json!(1e300);
        assert_eq!(
            parse_at_1000(&sign(far, &key), &key).unwrap().standing.exp,
            u64::MAX
        );
    }

    /// RFC 7519 §2: a NumericDate may be fractional, so a fractional `exp` is an expiry to
    /// check, not a missing one.
    #[test]
    fn a_fractional_exp_is_checked_as_an_expiry() {
        let key = generate().unwrap();
        let mut live = claims("dec-1", 0);
        live["exp"] = serde_json::json!(1_999.5);
        assert_eq!(
            parse_at_1000(&sign(live, &key), &key).unwrap().standing.exp,
            1_999
        );

        let mut gone = claims("dec-1", 0);
        gone["exp"] = serde_json::json!(999.5);
        let e = parse_at_1000(&sign(gone, &key), &key).unwrap_err();
        assert!(e.detail().contains("expired"), "{}", e.detail());
    }

    #[test]
    fn an_exp_or_nbf_that_is_not_a_number_is_refused() {
        let key = generate().unwrap();
        for (claim, value) in [("exp", "soon"), ("nbf", "soon")] {
            let mut c = claims("dec-1", 2_000);
            c[claim] = serde_json::json!(value);
            let e = parse_at_1000(&sign(c, &key), &key).unwrap_err();
            assert_eq!(
                e.detail(),
                format!("standing_token {claim} is not a number"),
                "{claim}"
            );
        }
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

    /// Each basis that bears on the facts is classified as such, under its own name; the
    /// disclosure lists the same set.
    #[test]
    fn a_basis_bearing_on_the_facts_is_classified_as_such() {
        let key = generate().unwrap();
        let token = sign(claims("dec-1", 2_000), &key);
        let bases = [
            "factual-error",
            "category-mismatch",
            "change-in-circumstances",
        ];
        for basis in bases {
            let c = parse(
                &challenge_json(&token, "dec-1", basis),
                &[key.verifying_key()],
                1_000,
            )
            .unwrap();
            match answer(&c, &["ppid:carol"]) {
                Outcome::ChallengeClassified { classified_basis } => {
                    assert_eq!(classified_basis, basis);
                }
                other => panic!("{basis} was not classified: {}", other.into_record().0),
            }
        }
        assert_eq!(BASES_ON_THE_FACTS.as_slice(), bases.as_slice());
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
            answer(&c, &["ppid:carol"]),
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
        match answer(&c, &["agent1", "corp"]) {
            Outcome::AffirmPriorDecision { affirm_basis } => {
                assert!(
                    affirm_basis.contains("names no party the decision's record is about"),
                    "{affirm_basis}"
                );
            }
            other => panic!("classified: {}", other.into_record().0),
        }
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
