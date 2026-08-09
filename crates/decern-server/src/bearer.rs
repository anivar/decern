// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Who is asking. RFC 9068 JWT access-token validation for `decern-serve`.
//!
//! Every recorded decision names a subject, and the subject is what the record is *about*.
//! A decision recorded against a party the server took on trust from whoever connected is a
//! confident, permanent statement that may name the wrong person. Verifying the caller is what
//! makes the rest of the record worth keeping.
//!
//! This authenticates **the caller**, not the decision subject. Under AuthZEN the enforcement
//! point asks about a subject, so a gateway legitimately asks about parties other than itself;
//! what changes here is that the gateway must now prove it is the gateway. Binding a subject to
//! the token's own `sub` would break that and is deliberately not done.
//!
//! Applied as a layer over the protected routes rather than as a handler argument. The check is
//! the same for every one of them, and a route that needs it should not be able to acquire it by
//! omission — which is how the mission mutations would otherwise quietly ship open.
//!
//! Verification only: no issuance, no authorization-server role, no discovery. Issuer keys are
//! configured rather than fetched, for the same reason the standing-token keys are — a decision
//! must not depend on a third party being reachable, and this binary carries no outbound TLS.
//! Of RFC 9068 §2.2's required claims, `iss`, `exp`, `aud`, `sub`, `client_id`, `iat` and `jti`
//! must all be present and `iss`/`aud`/`exp` are validated against configuration; bounding token
//! lifetime and the uniqueness of `jti` remain the issuer's responsibility.

use std::collections::BTreeMap;

use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

/// A compact JWS three parts of which each fit in an HTTP header has no business being
/// larger. Enforced before anything is decoded, so an oversized token costs its sender a
/// length comparison, not this server an allocation.
const MAX_TOKEN_BYTES: usize = 8192;

/// How much of an attacker-chosen string may be echoed back in an error. Enough to
/// recognise a misconfigured issuer or algorithm name; not enough to use the error
/// channel as a reflector.
const MAX_ECHO: usize = 64;

/// How the caller is established. Chosen explicitly at startup: a server that cannot say who
/// is asking should say so in its configuration rather than discover it in an audit.
pub(crate) enum Caller {
    /// A token is required, verified, and bound to this server as audience.
    Bearer(Box<Config>),
    /// Something in front has already authenticated the caller. Named rather than defaulted,
    /// because "no token configured" and "authentication deliberately delegated" look identical
    /// from inside the process and mean very different things outside it.
    TrustedProxy,
}

pub(crate) struct Config {
    /// The `iss` a token must carry, matched exactly. §4 requires an exact match, not a
    /// prefix or a host comparison.
    pub(crate) issuer: String,
    /// This server's resource identifier, which a token's `aud` must contain (RFC 8707 §2).
    /// Without it a token minted for any other service in the estate would be accepted here.
    pub(crate) audience: String,
    /// Keys the token may be signed by. Empty is rejected at startup, never at request time.
    pub(crate) keys: Vec<VerifyingKey>,
    /// Scopes the token's `scope` claim must contain, all of them. Empty means no scope
    /// check, which is the default: a deployment that names no scopes accepts any valid
    /// token, and one that names them refuses a token that carries only some.
    pub(crate) scopes: Vec<String>,
}

/// Why a request was refused, shaped by OAuth 2.1 §5.3 (draft-ietf-oauth-v2-1-15):
/// no credentials and bad credentials are both 401 but carry different challenges, and a
/// valid token missing a required scope is 403.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Denied {
    /// No `Authorization` header at all. RFC 6750 §3: the challenge then carries no error
    /// code — there is nothing wrong with a token that was never presented.
    NoCredentials,
    /// A token that cannot be trusted. 401, `error="invalid_token"`.
    Invalid(String),
    /// A verified token that does not carry a scope this deployment requires. 403,
    /// `error="insufficient_scope"`, and the challenge names the scopes so the client
    /// knows what to ask its issuer for.
    InsufficientScope(String),
}

impl Denied {
    pub fn detail(&self) -> &str {
        match self {
            Denied::NoCredentials => "no credentials presented",
            Denied::Invalid(d) | Denied::InsufficientScope(d) => d,
        }
    }
}

/// What a verified token says about its bearer. `client_id` is required (RFC 9068 §2.2),
/// so a verified caller always names the party, the client acting for it, and the
/// issuer whose signature was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Authenticated {
    pub(crate) subject: String,
    pub(crate) client_id: String,
    pub(crate) issuer: String,
}

/// The layer over the protected routes.
///
/// Under [`Caller::TrustedProxy`] this passes everything through — the operator has said the
/// caller is established in front of this process, and re-checking here would only invent a
/// second, weaker answer. Under [`Caller::Bearer`] nothing reaches a handler unverified, and
/// the verified identity rides the request so the record can say who asserted it.
pub(crate) async fn guard(
    axum::extract::State(caller): axum::extract::State<std::sync::Arc<Caller>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let cfg = match caller.as_ref() {
        Caller::TrustedProxy => return next.run(req).await,
        Caller::Bearer(cfg) => cfg,
    };
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    match authenticate(header.as_deref(), cfg, now_secs()) {
        Ok(who) => {
            req.extensions_mut().insert(who);
            next.run(req).await
        }
        Err(denied) => denied.into_response(cfg),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Denied {
    /// RFC 6750 §3: the challenge names the scheme, this server's identity as a `realm`, an
    /// `error` code where one applies, and for a scope refusal the scopes that would have
    /// sufficed. The description says which check failed and never why it failed for this
    /// particular token — enough to fix a misconfiguration, not enough to tune one token
    /// against the guard.
    fn into_response(self, cfg: &Config) -> Response {
        let status = match self {
            Denied::InsufficientScope(_) => axum::http::StatusCode::FORBIDDEN,
            _ => axum::http::StatusCode::UNAUTHORIZED,
        };
        let (code, challenge) = self.challenge(cfg);
        let body =
            axum::Json(serde_json::json!({ "error": code, "error_description": self.detail() }));
        let mut resp = (status, body).into_response();
        // Infallible by construction: `quoted` leaves only printable ASCII, so this parse
        // cannot fail — the fallback exists so a future edit to `quoted` degrades to a
        // generic challenge instead of silently omitting a header RFC 7235 §3.1 requires.
        let value = axum::http::HeaderValue::from_str(&challenge)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("Bearer"));
        resp.headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, value);
        resp
    }

    /// The error code and the full `WWW-Authenticate` value for this refusal.
    fn challenge(&self, cfg: &Config) -> (&'static str, String) {
        let realm = quoted(&cfg.audience);
        match self {
            Denied::NoCredentials => ("invalid_token", format!("Bearer realm=\"{realm}\"")),
            Denied::Invalid(d) => (
                "invalid_token",
                format!(
                    "Bearer realm=\"{realm}\", error=\"invalid_token\", error_description=\"{}\"",
                    quoted(d)
                ),
            ),
            Denied::InsufficientScope(d) => (
                "insufficient_scope",
                format!(
                    "Bearer realm=\"{realm}\", error=\"insufficient_scope\", scope=\"{}\", \
                     error_description=\"{}\"",
                    quoted(&cfg.scopes.join(" ")),
                    quoted(d)
                ),
            ),
        }
    }
}

/// A value fit for an RFC 6750 quoted-string: printable ASCII only (control characters are
/// dropped — a stray one would make the whole header unparseable and it would be silently
/// omitted), `"` and `\` escaped as quoted-pairs rather than dropped. Bounded loosely: what
/// arrives here is this module's own sentences, whose attacker-chosen fragments [`brief`]
/// already cut to [`MAX_ECHO`] — the bound is a backstop, sized not to cut a sentence.
fn quoted(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| matches!(c, ' '..='~')).take(256) {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// An attacker-chosen string as an error may echo it: printable, bounded.
fn brief(s: &str) -> String {
    s.chars()
        .filter(|c| matches!(c, ' '..='~'))
        .take(MAX_ECHO)
        .collect()
}

#[derive(Deserialize)]
struct Header {
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    /// RFC 7515 §4.1.11: a header extension the recipient MUST understand. This
    /// implementation understands none, so a token that names any is refused rather than
    /// verified under an assumption about what the extension meant.
    #[serde(default)]
    crit: Option<Value>,
}

/// The `Authorization` header value, if it is a well-formed bearer presentation.
///
/// OAuth 2.1 §5.1.1 defines exactly one form. The scheme is matched case-insensitively because
/// the ABNF permits that; the token itself is not touched.
fn bearer_token(header: Option<&str>) -> Result<&str, Denied> {
    let raw = header.ok_or(Denied::NoCredentials)?;
    let (scheme, token) = raw.split_once(' ').ok_or_else(|| {
        Denied::Invalid("Authorization header is not a bearer presentation".into())
    })?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(Denied::Invalid(format!(
            "authorization scheme {} is not accepted here",
            brief(scheme)
        )));
    }
    let token = token.trim();
    if token.is_empty() {
        return Err(Denied::Invalid("bearer token is empty".into()));
    }
    if token.len() > MAX_TOKEN_BYTES {
        return Err(Denied::Invalid(
            "bearer token exceeds the accepted size".into(),
        ));
    }
    Ok(token)
}

/// A claim that must be a number (RFC 7519 §2 NumericDate, which JSON permits to be
/// fractional). Present-but-not-a-number is a refusal, never a skipped check.
fn numeric_date(claims: &BTreeMap<String, Value>, name: &str) -> Result<Option<f64>, Denied> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_f64()
            .map(Some)
            .ok_or_else(|| Denied::Invalid(format!("token {name} is not a number"))),
    }
}

/// Validate a JWT access token in the order RFC 9068 §4 sets out: `typ`, then issuer, then
/// audience, then the signature, then time, then what this deployment requires of the claims.
///
/// The order is not cosmetic. Everything before the signature check is a claim the token makes
/// about itself and is not yet believed; doing the cheap refusals first means a token addressed
/// to another service is rejected without a signature verification, and — more importantly —
/// `alg` is settled before any key is chosen, so a token cannot nominate how it is checked.
pub(crate) fn authenticate(
    header: Option<&str>,
    cfg: &Config,
    now_secs: u64,
) -> Result<Authenticated, Denied> {
    if cfg.keys.is_empty() {
        // Startup should have prevented this. Refusing here as well keeps a
        // misconfiguration from presenting as "every token is fine".
        return Err(Denied::Invalid("no issuer keys are configured".into()));
    }
    let token = bearer_token(header)?;

    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(Denied::Invalid("token is not a compact JWS".into())),
    };

    let header: Header = decode_json(h, "header")?;

    // 1. typ — an access token, not an ID token or anything else the issuer signs. Without
    //    this an ID token for the same audience would sail through every later check.
    //    Case-insensitively: a media type is (RFC 9110 §8.3.1).
    match header.typ.as_deref() {
        Some(t)
            if t.eq_ignore_ascii_case("at+jwt") || t.eq_ignore_ascii_case("application/at+jwt") => {
        }
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "token type {} is not an access token",
                brief(other)
            )));
        }
        None => return Err(Denied::Invalid("token names no type".into())),
    }

    // 2. alg, before a key is selected.
    match header.alg.as_deref() {
        Some("EdDSA") => {}
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "algorithm {} is not accepted here",
                brief(other)
            )));
        }
        None => return Err(Denied::Invalid("token names no algorithm".into())),
    }
    if header.crit.is_some() {
        return Err(Denied::Invalid(
            "token names a critical header extension this server does not implement".into(),
        ));
    }

    let claims: BTreeMap<String, Value> = decode_json(p, "claims")?;

    // 3. iss — exact match.
    let iss = string_claim(&claims, "iss")?;
    if iss != cfg.issuer {
        return Err(Denied::Invalid(format!(
            "issuer {} is not the configured issuer",
            brief(&iss)
        )));
    }

    // 4. aud — RFC 8707 §2. Accepts the string or array form JWT allows.
    if !audience_contains(claims.get("aud"), &cfg.audience) {
        return Err(Denied::Invalid(
            "token was not issued for this server as audience".into(),
        ));
    }

    // 5. Signature. Strict, so a small-order key cannot verify a signature nobody made.
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Denied::Invalid("signature is not base64url".into()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Denied::Invalid("signature is not 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_arr);
    let signed = format!("{h}.{p}");
    if !cfg
        .keys
        .iter()
        .any(|k| k.verify_strict(signed.as_bytes(), &signature).is_ok())
    {
        return Err(Denied::Invalid(
            "signature is not from a configured issuer key".into(),
        ));
    }

    // 6. exp, and nbf where present. Only now, because until the signature verified these
    //    were numbers an unauthenticated party chose.
    let exp = numeric_date(&claims, "exp")?
        .ok_or_else(|| Denied::Invalid("token carries no expiry".into()))?;
    if now_secs as f64 >= exp {
        return Err(Denied::Invalid("token has expired".into()));
    }
    if let Some(nbf) = numeric_date(&claims, "nbf")?
        && (now_secs as f64) < nbf
    {
        return Err(Denied::Invalid("token is not yet valid".into()));
    }

    // 7. The rest of RFC 9068 §2.2's required claims, present and typed. Nothing here is
    //    matched against configuration; requiring them keeps this deployment from accepting
    //    a token its own issuer would call malformed.
    let subject = string_claim(&claims, "sub")?;
    let client_id = string_claim(&claims, "client_id")?;
    string_claim(&claims, "jti")?;
    if numeric_date(&claims, "iat")?.is_none() {
        return Err(Denied::Invalid("token carries no iat".into()));
    }

    // 8. Scope, last: a refusal here is the one that discloses the token verified, which is
    //    only safe to say about a token that did.
    if !cfg.scopes.is_empty() {
        let held = claims.get("scope").and_then(Value::as_str).unwrap_or("");
        let held: Vec<&str> = held.split(' ').collect();
        if let Some(missing) = cfg.scopes.iter().find(|s| !held.contains(&s.as_str())) {
            return Err(Denied::InsufficientScope(format!(
                "token does not carry the {missing} scope this server requires"
            )));
        }
    }

    Ok(Authenticated {
        subject,
        client_id,
        issuer: iss,
    })
}

/// `aud` is a string or an array of strings (RFC 7519 §4.1.3). Compared exactly: a resource
/// identifier is a URI, and treating a prefix as a match is how one service ends up accepting
/// another's tokens.
fn audience_contains(aud: Option<&Value>, want: &str) -> bool {
    match aud {
        Some(Value::String(s)) => s == want,
        Some(Value::Array(xs)) => xs.iter().any(|x| x.as_str() == Some(want)),
        _ => false,
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(part: &str, what: &str) -> Result<T, Denied> {
    let raw = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| Denied::Invalid(format!("token {what} is not base64url")))?;
    serde_json::from_slice(&raw).map_err(|_| Denied::Invalid(format!("token {what} is not JSON")))
}

fn string_claim(claims: &BTreeMap<String, Value>, name: &str) -> Result<String, Denied> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Denied::Invalid(format!("token carries no {name}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use serde_json::json;

    const ISS: &str = "https://issuer.example/";
    const AUD: &str = "https://pdp.example/access/v1/evaluation";

    fn signed(key: &decern_crypto::SigningKey, header: Value, claims: Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let sig = key.sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn header() -> Value {
        json!({ "typ": "at+jwt", "alg": "EdDSA" })
    }

    fn claims() -> Value {
        json!({ "iss": ISS, "aud": AUD, "sub": "gateway-1", "exp": 200, "iat": 100,
                "client_id": "gw", "jti": "abc" })
    }

    fn cfg(key: &decern_crypto::SigningKey) -> Config {
        Config {
            issuer: ISS.into(),
            audience: AUD.into(),
            keys: vec![key.verifying_key()],
            scopes: vec![],
        }
    }

    fn auth(token: &str, cfg: &Config) -> Result<Authenticated, Denied> {
        authenticate(Some(&format!("Bearer {token}")), cfg, 150)
    }

    #[test]
    fn a_well_formed_token_for_this_server_authenticates_its_caller() {
        let k = decern_crypto::generate().unwrap();
        let who = auth(&signed(&k, header(), claims()), &cfg(&k)).unwrap();
        assert_eq!(who.subject, "gateway-1");
        assert_eq!(who.client_id, "gw");
    }

    /// The audience check is the reason this module exists rather than a signature check alone.
    /// A token minted by the same issuer for a different service is a valid token; accepting it
    /// here would let any service in the estate speak for this one.
    #[test]
    fn a_token_minted_for_another_service_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let mut c = claims();
        c["aud"] = json!("https://billing.example/");
        let e = auth(&signed(&k, header(), c), &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("audience"), "{}", e.detail());
    }

    #[test]
    fn an_audience_array_containing_this_server_is_accepted() {
        let k = decern_crypto::generate().unwrap();
        let mut c = claims();
        c["aud"] = json!(["https://billing.example/", AUD]);
        assert!(auth(&signed(&k, header(), c), &cfg(&k)).is_ok());
    }

    /// A prefix is not a match. Treating one as a match is how a server ends up accepting the
    /// tokens of anything hosted beneath it.
    #[test]
    fn an_audience_that_merely_starts_the_same_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let mut c = claims();
        c["aud"] = json!("https://pdp.example/");
        assert!(auth(&signed(&k, header(), c), &cfg(&k)).is_err());
    }

    #[test]
    fn a_token_from_an_unconfigured_issuer_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let mut c = claims();
        c["iss"] = json!("https://elsewhere.example/");
        assert!(auth(&signed(&k, header(), c), &cfg(&k)).is_err());
    }

    #[test]
    fn a_token_signed_by_a_key_this_deployment_does_not_hold_is_refused() {
        let mine = decern_crypto::generate().unwrap();
        let theirs = decern_crypto::generate().unwrap();
        let e = auth(&signed(&theirs, header(), claims()), &cfg(&mine)).unwrap_err();
        assert!(e.detail().contains("signature"), "{}", e.detail());
    }

    /// An ID token is signed by the same issuer for the same audience. Only `typ` separates it
    /// from an access token, which is why §4 checks it first.
    #[test]
    fn an_id_token_is_not_an_access_token() {
        let k = decern_crypto::generate().unwrap();
        let h = json!({ "typ": "JWT", "alg": "EdDSA" });
        let e = auth(&signed(&k, h, claims()), &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("not an access token"), "{}", e.detail());
    }

    /// Media types compare case-insensitively (RFC 9110 §8.3.1); a conformant issuer may
    /// spell the type however it likes.
    #[test]
    fn the_token_type_is_matched_case_insensitively() {
        let k = decern_crypto::generate().unwrap();
        let h = json!({ "typ": "AT+JWT", "alg": "EdDSA" });
        assert!(auth(&signed(&k, h, claims()), &cfg(&k)).is_ok());
    }

    #[test]
    fn an_algorithm_this_deployment_does_not_accept_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let h = json!({ "typ": "at+jwt", "alg": "none" });
        let e = auth(&signed(&k, h, claims()), &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("algorithm none"), "{}", e.detail());
    }

    /// The classic downgrade: take a validly signed token and swap its header for `alg:none`,
    /// keeping the original payload and signature. The algorithm check refuses it before any
    /// key is consulted; even were that check gone, the signature no longer covers the bytes
    /// presented.
    #[test]
    fn a_header_swapped_to_alg_none_after_signing_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let good = signed(&k, header(), claims());
        let (_, rest) = good.split_once('.').unwrap();
        let forged_header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"typ":"at+jwt","alg":"none"})).unwrap());
        assert!(auth(&format!("{forged_header}.{rest}"), &cfg(&k)).is_err());
    }

    #[test]
    fn an_empty_signature_segment_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let good = signed(&k, json!({"typ":"at+jwt","alg":"none"}), claims());
        let mut parts = good.splitn(3, '.');
        let (h, p) = (parts.next().unwrap(), parts.next().unwrap());
        assert!(auth(&format!("{h}.{p}."), &cfg(&k)).is_err());
    }

    /// RFC 7515 §4.1.11: `crit` names extensions the recipient must implement. None are.
    #[test]
    fn a_critical_header_extension_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let h = json!({ "typ": "at+jwt", "alg": "EdDSA", "crit": ["exp"] });
        let e = auth(&signed(&k, h, claims()), &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("critical"), "{}", e.detail());
    }

    #[test]
    fn an_expired_token_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let t = signed(&k, header(), claims());
        let e = authenticate(Some(&format!("Bearer {t}")), &cfg(&k), 500).unwrap_err();
        assert!(e.detail().contains("expired"), "{}", e.detail());
    }

    #[test]
    fn a_token_with_no_expiry_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let mut c = claims();
        c.as_object_mut().unwrap().remove("exp");
        assert!(auth(&signed(&k, header(), c), &cfg(&k)).is_err());
    }

    /// RFC 7519 NumericDate may be fractional. A fractional `nbf` must still gate — reading
    /// it with an integer accessor would skip the not-yet-valid check entirely.
    #[test]
    fn a_fractional_nbf_in_the_future_still_gates() {
        let k = decern_crypto::generate().unwrap();
        let mut c = claims();
        c["nbf"] = json!(180.5);
        let e = auth(&signed(&k, header(), c), &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("not yet valid"), "{}", e.detail());
    }

    #[test]
    fn a_non_numeric_nbf_is_refused_not_skipped() {
        let k = decern_crypto::generate().unwrap();
        let mut c = claims();
        c["nbf"] = json!("soon");
        let e = auth(&signed(&k, header(), c), &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("nbf"), "{}", e.detail());
    }

    /// §2.2 requires them; a token without them is one its own issuer would call malformed.
    #[test]
    fn a_token_missing_a_required_claim_is_refused() {
        for claim in ["sub", "client_id", "jti", "iat"] {
            let k = decern_crypto::generate().unwrap();
            let mut c = claims();
            c.as_object_mut().unwrap().remove(claim);
            let e = auth(&signed(&k, header(), c), &cfg(&k)).unwrap_err();
            assert!(e.detail().contains(claim), "{claim}: {}", e.detail());
        }
    }

    #[test]
    fn an_oversized_token_is_refused_before_decoding() {
        let k = decern_crypto::generate().unwrap();
        let t = format!(
            "{}.{}.{}",
            "a".repeat(4000),
            "b".repeat(4000),
            "c".repeat(200)
        );
        let e = auth(&t, &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("size"), "{}", e.detail());
    }

    #[test]
    fn nothing_authenticates_without_a_header() {
        let k = decern_crypto::generate().unwrap();
        let e = authenticate(None, &cfg(&k), 150).unwrap_err();
        assert_eq!(e, Denied::NoCredentials);
    }

    #[test]
    fn a_non_bearer_scheme_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let e = authenticate(Some("Basic dXNlcjpwYXNz"), &cfg(&k), 150).unwrap_err();
        assert!(e.detail().contains("Basic"), "{}", e.detail());
    }

    #[test]
    fn the_scheme_is_matched_case_insensitively() {
        let k = decern_crypto::generate().unwrap();
        let t = signed(&k, header(), claims());
        assert!(authenticate(Some(&format!("bearer {t}")), &cfg(&k), 150).is_ok());
    }

    /// With no keys there is nothing a signature could be checked against. The refusal must
    /// come from the explicit guard, not fall through to a signature check over no keys —
    /// the distinction matters because the guard is what a startup misconfiguration hits.
    #[test]
    fn with_no_configured_keys_nothing_authenticates() {
        let k = decern_crypto::generate().unwrap();
        let c = Config {
            issuer: ISS.into(),
            audience: AUD.into(),
            keys: vec![],
            scopes: vec![],
        };
        let e = auth(&signed(&k, header(), claims()), &c).unwrap_err();
        assert!(
            e.detail().contains("no issuer keys are configured"),
            "{}",
            e.detail()
        );
    }

    /// The scope refusal is the one distinction OAuth 2.1 §5.3 draws above 401: the token
    /// verified, and still does not suffice. Deleting the scope check turns this 403 into a
    /// 200, so this test is the check's negative control.
    #[test]
    fn a_verified_token_missing_a_required_scope_is_refused_as_insufficient() {
        let k = decern_crypto::generate().unwrap();
        let mut c = cfg(&k);
        c.scopes = vec!["decern.decide".into(), "decern.mission".into()];
        let mut cl = claims();
        cl["scope"] = json!("decern.decide");
        let e = auth(&signed(&k, header(), cl), &c).unwrap_err();
        assert!(matches!(e, Denied::InsufficientScope(_)), "{e:?}");
        assert!(e.detail().contains("decern.mission"), "{}", e.detail());
    }

    #[test]
    fn a_token_carrying_every_required_scope_is_accepted() {
        let k = decern_crypto::generate().unwrap();
        let mut c = cfg(&k);
        c.scopes = vec!["decern.decide".into()];
        let mut cl = claims();
        cl["scope"] = json!("decern.mission decern.decide");
        assert!(auth(&signed(&k, header(), cl), &c).is_ok());
    }

    #[test]
    fn with_no_scopes_configured_the_scope_claim_is_not_consulted() {
        let k = decern_crypto::generate().unwrap();
        // `claims()` carries no scope at all; the default config must not miss one.
        assert!(auth(&signed(&k, header(), claims()), &cfg(&k)).is_ok());
    }

    /// A control character in an attacker-chosen field must not cost the response its
    /// `WWW-Authenticate` header (RFC 7235 §3.1 requires one on every 401).
    #[test]
    fn the_challenge_survives_hostile_characters() {
        let k = decern_crypto::generate().unwrap();
        let denied = Denied::Invalid("token type \x01\"evil\\\r\n is not an access token".into());
        let (_, challenge) = denied.challenge(&cfg(&k));
        assert!(
            axum::http::HeaderValue::from_str(&challenge).is_ok(),
            "{challenge}"
        );
        assert!(challenge.contains("\\\"evil\\\\"), "{challenge}");
    }

    #[test]
    fn a_missing_header_challenges_without_an_error_code() {
        let k = decern_crypto::generate().unwrap();
        let (_, challenge) = Denied::NoCredentials.challenge(&cfg(&k));
        assert!(!challenge.contains("error"), "{challenge}");
        assert!(challenge.starts_with("Bearer realm="), "{challenge}");
    }
}
