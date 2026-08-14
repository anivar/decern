// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Who is asking, proven by a signature over the request itself rather than a bearer
//! secret. RFC 9421 HTTP Message Signatures, key material conveyed per
//! `draft-hardt-httpbis-signature-key`'s `Signature-Key` header, bound to an RFC 7800
//! `cnf` confirmation claim inside a compact JWS access token.
//!
//! This is a second credential format alongside [`crate::bearer`], not a replacement:
//! a bearer token proves the caller once held a secret at issuance time; a signature
//! over this exact request proves the caller holds the private key *now*. A leaked
//! bearer token is replayable against any request until it expires; a leaked signed
//! request cannot be replayed against a *different* request — mint one and the signature
//! no longer covers it. Verbatim replay of the exact same captured signature is not
//! separately prevented here (no nonce/`jti` cache): it verifies again within
//! [`MAX_SIGNATURE_AGE_SECS`], the same as it did the first time. What shrinks is the
//! window, from a token's full lifetime to one signature's freshness period, not the
//! possibility.
//!
//! Every principal's key is configured, not discovered. This deployment does not fetch a
//! `.well-known` document for anyone: the same reason bearer tokens name issuer keys in
//! configuration rather than fetching them applies here with more force, since there is
//! no single issuer to discover from — each principal would be its own. A principal not
//! already named in `--signed-agent-key` cannot authenticate under this mode at all; this
//! is deliberate, not a placeholder for a discovery step to be added later. decern's
//! directory is a fixed, proven graph, not an open world a stranger can join at request
//! time — accepting an unconfigured identity here would be a credential this deployment
//! cannot account for, decided about a principal the kernel has no policy for either.
//!
//! Verification only, over a fixed, small shape rather than RFC 9421's full generality:
//! exactly one signature, exactly the covered components named below, `ed25519` only. A
//! request naming a different component set, a different algorithm, or more than one
//! signature is refused rather than accepted under a shape this module does not enforce
//! everywhere else.

use std::collections::BTreeMap;

use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::caller::{Authenticated, CallerAuth, Denied};

/// The exact, ordered component list this deployment requires. RFC 9421 lets a signer
/// name any subset; decern accepts precisely this one, in this order, or refuses —
/// the same reasoning as `bearer.rs` accepting exactly one `alg`: a fixed shape here is
/// what makes "this passed verification" mean something specific enough to record.
const REQUIRED_COMPONENTS: [&str; 4] = ["@method", "@authority", "@path", "signature-key"];

/// How long after `created` a signature is still accepted. Mint-to-arrival latency plus
/// clock skew, not a session length — a signature is proof for one request, not a grant
/// that outlives it.
const MAX_SIGNATURE_AGE_SECS: i64 = 60;

/// How far ahead of this server's clock a signer's `created` may be and still be
/// accepted. Independent clocks drift in both directions, not just late — a signer a
/// few seconds ahead of this server is an ordinary NTP-grade skew, not an attack, and
/// refusing it here would be an operational failure with a security-shaped symptom.
const MAX_CLOCK_SKEW_AHEAD_SECS: i64 = 5;

/// A compact JWS three parts of which each fit in an HTTP header has no business being
/// larger. Mirrors `bearer.rs`'s own token size ceiling.
const MAX_TOKEN_BYTES: usize = 8192;

pub(crate) struct SigConfig {
    /// Agent identifier -> the one key it may sign with. A rollover is a new entry with
    /// the old one still present for the overlap window, exactly as `--bearer-issuer-key`
    /// accepts more than one key rather than requiring an atomic swap.
    pub(crate) agents: BTreeMap<String, VerifyingKey>,
    /// This deployment's resource identifier, which the token's `aud` must contain —
    /// same role as [`crate::bearer::Config::audience`].
    pub(crate) audience: String,
}

/// What a verified signed request says about its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Signed {
    /// The configured agent identifier the token's `sub` named and whose key verified
    /// the signature.
    pub(crate) agent: String,
    pub(crate) issuer: String,
}

/// Parsed `Signature-Input` value for a single signature. RFC 9421 §2.3 permits several
/// labelled signatures in one header; this deployment accepts exactly one.
struct SignatureInput {
    components: Vec<String>,
    created: i64,
    /// Parsed for shape validation only — this deployment pins keys by agent id
    /// (`SigConfig::agents`), not by `keyid`, so the value itself is never consulted.
    _keyid: Option<String>,
}

/// A minimal, fixed-shape parser for one RFC 8941 inner-list-with-params value of the
/// form `("comp1" "comp2" ...);created=NNN;keyid="..."`. Not a general structured-field
/// parser: this module accepts exactly this shape and refuses anything else, the same
/// discipline `bearer.rs` applies to `alg`/`typ`.
fn parse_signature_input(label: &str, raw: &str) -> Result<SignatureInput, Denied> {
    let prefix = format!("{label}=(");
    let rest = raw
        .trim()
        .strip_prefix(&prefix)
        .ok_or_else(|| Denied::Invalid("Signature-Input is not a recognised shape".into()))?;
    let (list, params) = rest
        .split_once(')')
        .ok_or_else(|| Denied::Invalid("Signature-Input component list is unterminated".into()))?;
    let components: Vec<String> = list
        .split_whitespace()
        .map(|c| c.trim_matches('"').to_owned())
        .collect();

    let mut created = None;
    let mut keyid = None;
    for part in params.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| Denied::Invalid("Signature-Input parameter is malformed".into()))?;
        match k {
            "created" => {
                created = Some(v.parse::<i64>().map_err(|_| {
                    Denied::Invalid("Signature-Input created is not an integer".into())
                })?);
            }
            "keyid" => keyid = Some(v.trim_matches('"').to_owned()),
            // An unrecognised parameter is refused rather than ignored: RFC 9421 §2.3
            // lets a signer attach any parameter, and silently accepting one this
            // deployment does not interpret would let it claim a property (e.g. `nonce`,
            // `tag`) that was never actually checked.
            other => {
                return Err(Denied::Invalid(format!(
                    "Signature-Input names an unsupported parameter {other}"
                )));
            }
        }
    }
    let created =
        created.ok_or_else(|| Denied::Invalid("Signature-Input carries no created".into()))?;
    Ok(SignatureInput {
        components,
        created,
        _keyid: keyid,
    })
}

/// Extract the base64 signature bytes for `label` from a `Signature` header value of the
/// form `label=:base64:`.
fn parse_signature(label: &str, raw: &str) -> Result<Vec<u8>, Denied> {
    let prefix = format!("{label}=:");
    let rest = raw
        .trim()
        .strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix(':'))
        .ok_or_else(|| Denied::Invalid("Signature is not a recognised shape".into()))?;
    base64::engine::general_purpose::STANDARD
        .decode(rest)
        .map_err(|_| Denied::Invalid("Signature is not valid base64".into()))
}

/// Build the RFC 9421 §2.5 signature base for exactly [`REQUIRED_COMPONENTS`], given the
/// request line and the raw `Signature-Key` header value, then append the
/// `@signature-params` line reconstructed from the same `Signature-Input` value that was
/// parsed — never a value this function invents, so the base matches byte-for-byte what
/// the signer actually covered.
fn signature_base(
    method: &str,
    authority: &str,
    path: &str,
    signature_key_header: &str,
    signature_input_label: &str,
    signature_input_raw: &str,
) -> String {
    let values = [
        method.to_ascii_uppercase(),
        authority.to_ascii_lowercase(),
        path.to_owned(),
        signature_key_header.to_owned(),
    ];
    let mut base = String::new();
    for (component, value) in REQUIRED_COMPONENTS.iter().zip(values.iter()) {
        base.push_str(&format!("\"{component}\": {value}\n"));
    }
    base.push_str(&format!(
        "\"@signature-params\": {}",
        signature_input_raw
            .trim()
            .strip_prefix(&format!("{signature_input_label}="))
            .unwrap_or(signature_input_raw)
    ));
    base
}

#[derive(Deserialize)]
struct Header {
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    alg: Option<String>,
}

#[derive(Deserialize)]
struct Cnf {
    jwk: JwkEd25519,
}

/// The one JWK shape this deployment accepts: an OKP Ed25519 public key (RFC 8037).
#[derive(Deserialize)]
struct JwkEd25519 {
    kty: String,
    crv: String,
    x: String,
}

fn jwk_to_verifying_key(jwk: &JwkEd25519) -> Result<VerifyingKey, Denied> {
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return Err(Denied::Invalid("cnf.jwk is not an Ed25519 OKP key".into()));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|_| Denied::Invalid("cnf.jwk.x is not base64url".into()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Denied::Invalid("cnf.jwk.x is not 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|_| Denied::Invalid("cnf.jwk.x is not a valid point".into()))
}

impl CallerAuth for SigConfig {
    /// The credential is spread across the request line and three headers, so unlike the
    /// bearer posture this reads the method, authority and path too — they are covered
    /// components of the signature, not incidental context.
    fn authenticate(
        &self,
        req: &axum::extract::Request,
        now_secs: u64,
    ) -> Result<Authenticated, Denied> {
        fn header<'a>(req: &'a axum::extract::Request, name: &str) -> Option<&'a str> {
            req.headers().get(name).and_then(|v| v.to_str().ok())
        }
        let presented = SignedRequest {
            method: req.method().as_str(),
            authority: header(req, "host").unwrap_or_default(),
            path: req.uri().path(),
            signature_key_header: header(req, "signature-key"),
            signature_input_header: header(req, "signature-input"),
            signature_header: header(req, "signature"),
        };
        let signed = authenticate(&presented, self, now_secs as i64)?;
        Ok(Authenticated {
            // A signed request names one agent, which is both the party and the client
            // acting for it — there is no separate delegating client to distinguish.
            subject: signed.agent.clone(),
            client_id: signed.agent,
            issuer: signed.issuer,
        })
    }

    /// No `WWW-Authenticate` here, deliberately: that header names an authentication
    /// scheme, RFC 9421 defines none of its own to name, and emitting `Bearer` would
    /// invite a client to retry with exactly the credential this posture does not accept.
    /// The body carries the reason instead.
    fn refuse(&self, denied: Denied) -> Response {
        let body = axum::Json(
            serde_json::json!({ "error": "invalid_signature", "error_description": denied.detail() }),
        );
        (denied.status(), body).into_response()
    }
}

/// Everything needed from the request to verify a signed presentation, gathered by the
/// caller (an axum extractor/middleware) so this function stays a pure, testable
/// verifier over plain values rather than reaching into a framework request type itself.
pub(crate) struct SignedRequest<'a> {
    pub(crate) method: &'a str,
    pub(crate) authority: &'a str,
    pub(crate) path: &'a str,
    pub(crate) signature_key_header: Option<&'a str>,
    pub(crate) signature_input_header: Option<&'a str>,
    pub(crate) signature_header: Option<&'a str>,
}

/// Validate a signed request and its bound access token, in the order that keeps every
/// cheap, self-asserted check ahead of the two expensive/trust-changing ones (signature
/// verification, then the token's own claims) — the same ordering discipline
/// `bearer::authenticate` uses and for the same reason: nothing before the signature
/// check is believed yet.
pub(crate) fn authenticate(
    req: &SignedRequest<'_>,
    cfg: &SigConfig,
    now_secs: i64,
) -> Result<Signed, Denied> {
    if cfg.agents.is_empty() {
        return Err(Denied::Invalid("no agent keys are configured".into()));
    }
    let key_header = req.signature_key_header.ok_or(Denied::NoCredentials)?;
    let input_header = req
        .signature_input_header
        .ok_or_else(|| Denied::Invalid("request carries no Signature-Input".into()))?;
    let sig_header = req
        .signature_header
        .ok_or_else(|| Denied::Invalid("request carries no Signature".into()))?;

    if key_header.len() > MAX_TOKEN_BYTES || input_header.len() > MAX_TOKEN_BYTES {
        return Err(Denied::Invalid(
            "signature material exceeds the accepted size".into(),
        ));
    }

    // `Signature-Key` conveys the bearer token this signature is over; this deployment
    // accepts the token itself, verbatim. No separate size check here: trimming can only
    // shrink it, and `key_header` is already bounded above.
    let token = key_header.trim();

    // Both headers are labelled dictionaries; this deployment accepts exactly one label,
    // named `sig1`, and refuses anything with more than one signature attached.
    const LABEL: &str = "sig1";
    let input = parse_signature_input(LABEL, input_header)?;
    let sig_bytes = parse_signature(LABEL, sig_header)?;

    if input.components.as_slice() != REQUIRED_COMPONENTS {
        return Err(Denied::Invalid(
            "Signature-Input does not cover exactly the required components".into(),
        ));
    }
    let age = now_secs - input.created;
    if !(-MAX_CLOCK_SKEW_AHEAD_SECS..=MAX_SIGNATURE_AGE_SECS).contains(&age) {
        return Err(Denied::Invalid(
            "signature is outside the accepted freshness window".into(),
        ));
    }

    // Decode the bound token far enough to find its `cnf.jwk` — the key the signature
    // must verify against — before trusting anything else it claims.
    //
    // The token's OWN JWS signature (the third part, discarded below) is never checked
    // against an issuer key. This is deliberate, not an omission: the token travels
    // verbatim inside `Signature-Key`, which is itself one of the components covered by
    // the outer RFC 9421 signature verified at the end of this function. Any change to
    // the token's bytes — including forging a signature over a different `sub`/`cnf`/
    // `aud`/`exp` — changes the `Signature-Key` header value the outer signature was
    // computed over, so only the true holder of `configured_key` can present a token
    // whose claims and outer signature both verify together. A second, independent check
    // of the token's own signature would verify nothing the outer check does not already.
    let mut parts = token.split('.');
    let (h, p, _sig) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(sig), None) => (h, p, sig),
        _ => return Err(Denied::Invalid("bound token is not a compact JWS".into())),
    };
    let header: Header = decode_json(h, "header")?;
    match header.typ.as_deref() {
        Some(t) if t.eq_ignore_ascii_case("dpop-bound+jwt") => {}
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "bound token type {} is not a signature-bound access token",
                brief(other)
            )));
        }
        None => return Err(Denied::Invalid("bound token names no type".into())),
    }
    match header.alg.as_deref() {
        Some("EdDSA") => {}
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "bound token algorithm {} is not accepted here",
                brief(other)
            )));
        }
        None => return Err(Denied::Invalid("bound token names no algorithm".into())),
    }

    let claims: BTreeMap<String, Value> = decode_json(p, "claims")?;
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| Denied::Invalid("bound token carries no sub".into()))?
        .to_owned();
    let issuer = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| Denied::Invalid("bound token carries no iss".into()))?
        .to_owned();

    if !audience_contains(claims.get("aud"), &cfg.audience) {
        return Err(Denied::Invalid(
            "bound token was not issued for this server as audience".into(),
        ));
    }

    // The claimed identity must be one this deployment already governs. This is the
    // whole point of "configured, not discovered": a `sub` decern has no key for is
    // refused here, before any cryptography runs on its behalf.
    let configured_key = cfg.agents.get(&subject).ok_or_else(|| {
        Denied::Invalid(format!("agent {} is not configured here", brief(&subject)))
    })?;

    // The token must bind to that same configured key via `cnf.jwk` — a token claiming
    // `sub=agent-1` but confirming a different key would let a caller name an identity
    // without holding what it takes to prove it.
    let cnf: Cnf = claims
        .get("cnf")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| Denied::Invalid("bound token cnf is malformed".into()))?
        .ok_or_else(|| Denied::Invalid("bound token carries no cnf".into()))?;
    let token_key = jwk_to_verifying_key(&cnf.jwk)?;
    if token_key != *configured_key {
        return Err(Denied::Invalid(
            "bound token cnf.jwk does not match the configured key for this agent".into(),
        ));
    }

    // Token expiry, only now that the key claimed inside it is the one this deployment
    // already trusts for this identity — checking it earlier would validate a claim
    // about a key nobody has confirmed yet.
    let exp = claims
        .get("exp")
        .and_then(Value::as_f64)
        .ok_or_else(|| Denied::Invalid("bound token carries no exp".into()))?;
    if now_secs as f64 >= exp {
        return Err(Denied::Invalid("bound token has expired".into()));
    }

    // Finally, the expensive check: does the signature over this exact request verify
    // against the key this deployment already knows for the claimed identity. Every
    // check above is cheap and self-asserted; this is the one that actually proves
    // possession, so it runs last, over a key this function chose, never one the
    // request supplied for its own verification.
    let base = signature_base(
        req.method,
        req.authority,
        req.path,
        key_header,
        LABEL,
        input_header,
    );
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Denied::Invalid("signature is not 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_arr);
    if configured_key
        .verify_strict(base.as_bytes(), &signature)
        .is_err()
    {
        return Err(Denied::Invalid(
            "signature does not verify against the configured key for this agent".into(),
        ));
    }

    Ok(Signed {
        agent: subject,
        issuer,
    })
}

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

fn brief(s: &str) -> String {
    s.chars()
        .filter(|c| matches!(c, ' '..='~'))
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use decern_crypto::{Signer, SigningKey};
    use serde_json::json;

    const AGENT: &str = "agent-1";
    const ISS: &str = "https://agent-provider.example/";
    const AUD: &str = "https://pdp.example/access/v1/evaluation";
    const METHOD: &str = "GET";
    const AUTHORITY: &str = "pdp.example";
    const PATH: &str = "/access/v1/evaluation";
    const CREATED: i64 = 1_000;
    const NOW: i64 = 1_010;

    fn jwk(key: &VerifyingKey) -> Value {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(key.to_bytes()),
        })
    }

    /// A compact-JWS-shaped bound token. Its own JWS signature segment is never verified
    /// by this module (see the comment in `authenticate` explaining why), so any non-empty
    /// placeholder for the third part is a valid fixture.
    fn bound_token(cnf_key: &VerifyingKey, claims_patch: impl FnOnce(&mut Value)) -> String {
        let header = json!({ "typ": "dpop-bound+jwt", "alg": "EdDSA" });
        let mut claims = json!({
            "sub": AGENT,
            "iss": ISS,
            "aud": AUD,
            "exp": (NOW + 100) as f64,
            "cnf": { "jwk": jwk(cnf_key) },
        });
        claims_patch(&mut claims);
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        format!("{h}.{p}.unverified")
    }

    fn cfg(key: &VerifyingKey) -> SigConfig {
        let mut agents = BTreeMap::new();
        agents.insert(AGENT.to_owned(), *key);
        SigConfig {
            agents,
            audience: AUD.into(),
        }
    }

    /// Builds the three RFC 9421 headers for a request signed with `signing_key`, whose
    /// bound token is `token`. `components` lets a test ask for a shape other than
    /// [`REQUIRED_COMPONENTS`]; `created` lets a test ask for a stale timestamp.
    fn sign_request(
        signing_key: &SigningKey,
        token: &str,
        components: &[&str],
        created: i64,
    ) -> (String, String, String) {
        let component_list = components
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(" ");
        let input_value = format!("sig1=({component_list});created={created}");
        let base = signature_base(METHOD, AUTHORITY, PATH, token, "sig1", &input_value);
        let signature = signing_key.sign(base.as_bytes());
        let sig_value = format!(
            "sig1=:{}:",
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        );
        (token.to_owned(), input_value, sig_value)
    }

    fn req<'a>(
        signature_key_header: &'a str,
        signature_input_header: &'a str,
        signature_header: &'a str,
    ) -> SignedRequest<'a> {
        SignedRequest {
            method: METHOD,
            authority: AUTHORITY,
            path: PATH,
            signature_key_header: Some(signature_key_header),
            signature_input_header: Some(signature_input_header),
            signature_header: Some(signature_header),
        }
    }

    #[test]
    fn a_well_formed_signed_request_authenticates_its_caller() {
        let k = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |_| {});
        let (key_h, input_h, sig_h) = sign_request(&k, &token, &REQUIRED_COMPONENTS, CREATED);
        let who = authenticate(
            &req(&key_h, &input_h, &sig_h),
            &cfg(&k.verifying_key()),
            NOW,
        )
        .unwrap();
        assert_eq!(who.agent, AGENT);
        assert_eq!(who.issuer, ISS);
    }

    /// The property this module exists for: a well-formed token whose `cnf.jwk` names the
    /// configured key is not enough on its own. The request must also be signed, right
    /// now, by that same key. Signing with a different key entirely — even though the
    /// token itself still claims the configured key via `cnf` — must be refused, because
    /// that is exactly what a caller without the real private key would have to do.
    #[test]
    fn a_token_replayed_but_signed_by_a_different_key_is_refused() {
        let configured = decern_crypto::generate().unwrap();
        let attacker = decern_crypto::generate().unwrap();
        let token = bound_token(&configured.verifying_key(), |_| {});
        let (key_h, input_h, sig_h) =
            sign_request(&attacker, &token, &REQUIRED_COMPONENTS, CREATED);
        let e = authenticate(
            &req(&key_h, &input_h, &sig_h),
            &cfg(&configured.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(e.detail().contains("does not verify"), "{}", e.detail());
    }

    #[test]
    fn a_stale_created_timestamp_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |_| {});
        let stale_created = NOW - MAX_SIGNATURE_AGE_SECS - 1;
        let (key_h, input_h, sig_h) = sign_request(&k, &token, &REQUIRED_COMPONENTS, stale_created);
        let e = authenticate(
            &req(&key_h, &input_h, &sig_h),
            &cfg(&k.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(e.detail().contains("freshness"), "{}", e.detail());
    }

    /// Ordinary NTP-grade clock skew, not an attack: a signer a few seconds ahead of this
    /// server's clock must still authenticate.
    #[test]
    fn a_signature_created_slightly_ahead_of_the_servers_clock_is_accepted() {
        let k = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |_| {});
        let ahead_created = NOW + MAX_CLOCK_SKEW_AHEAD_SECS;
        let (key_h, input_h, sig_h) = sign_request(&k, &token, &REQUIRED_COMPONENTS, ahead_created);
        authenticate(
            &req(&key_h, &input_h, &sig_h),
            &cfg(&k.verifying_key()),
            NOW,
        )
        .expect("a signer within the allowed skew tolerance must authenticate");
    }

    /// The tolerance is bounded, not unlimited: a signer far enough ahead is still refused.
    #[test]
    fn a_signature_created_too_far_ahead_of_the_servers_clock_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |_| {});
        let too_far_ahead = NOW + MAX_CLOCK_SKEW_AHEAD_SECS + 1;
        let (key_h, input_h, sig_h) = sign_request(&k, &token, &REQUIRED_COMPONENTS, too_far_ahead);
        let e = authenticate(
            &req(&key_h, &input_h, &sig_h),
            &cfg(&k.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(e.detail().contains("freshness"), "{}", e.detail());
    }

    #[test]
    fn a_request_missing_a_required_covered_component_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |_| {});
        let short_components = ["@method", "@authority", "@path"];
        let (key_h, input_h, sig_h) = sign_request(&k, &token, &short_components, CREATED);
        let e = authenticate(
            &req(&key_h, &input_h, &sig_h),
            &cfg(&k.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(e.detail().contains("required components"), "{}", e.detail());
    }

    /// A caller must already exist in this deployment's configuration before any
    /// cryptography runs on its behalf — the whole point of "configured, not discovered".
    #[test]
    fn an_unconfigured_agent_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let other = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |c| {
            c["sub"] = json!("someone-else");
        });
        let (key_h, input_h, sig_h) = sign_request(&k, &token, &REQUIRED_COMPONENTS, CREATED);
        // `other`'s key is what's configured here, under a different agent id — proving
        // this is refused for the identity lookup, not merely because the wrong key
        // happened to verify.
        let e = authenticate(
            &req(&key_h, &input_h, &sig_h),
            &cfg(&other.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(
            e.detail().contains("is not configured here"),
            "{}",
            e.detail()
        );
    }

    #[test]
    fn an_expired_bound_token_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |c| {
            c["exp"] = json!((NOW - 1) as f64);
        });
        let (key_h, input_h, sig_h) = sign_request(&k, &token, &REQUIRED_COMPONENTS, CREATED);
        let e = authenticate(
            &req(&key_h, &input_h, &sig_h),
            &cfg(&k.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(e.detail().contains("expired"), "{}", e.detail());
    }

    #[test]
    fn a_token_bound_to_a_key_other_than_the_configured_one_is_refused() {
        let configured = decern_crypto::generate().unwrap();
        let elsewhere = decern_crypto::generate().unwrap();
        // The token confirms a key that is not the one configured for this agent; even
        // though the request happens to be signed by the configured key, the token's own
        // claim about which key it binds to must still match.
        let token = bound_token(&elsewhere.verifying_key(), |_| {});
        let (key_h, input_h, sig_h) =
            sign_request(&configured, &token, &REQUIRED_COMPONENTS, CREATED);
        let e = authenticate(
            &req(&key_h, &input_h, &sig_h),
            &cfg(&configured.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(e.detail().contains("does not match"), "{}", e.detail());
    }
}
