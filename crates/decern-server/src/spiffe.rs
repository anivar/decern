// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Who is asking, as a SPIFFE JWT-SVID.
//!
//! A third credential format alongside [`crate::bearer`] and [`crate::sig`], for callers
//! whose identity comes from a SPIFFE issuer rather than an OAuth authorization server.
//! Verification only: trust bundles are configured at startup, never fetched, for the same
//! reason the other two postures configure their keys — a decision must not depend on a
//! third party being reachable, and this binary carries no outbound TLS stack. SPIFFE's own
//! Federation spec makes bundle polling a `SHOULD`, and leaves distribution out of scope
//! entirely, so a pinned bundle is an ordinary deployment rather than a degraded one.
//!
//! **This is a bearer credential, and it is presented as one.** JWT-SVID §5.2 says an SVID
//! sent over HTTP goes in `Authorization` under the `Bearer` scheme, so a refusal here owes
//! an RFC 6750 challenge naming that scheme — the opposite of [`crate::sig`], which
//! deliberately advertises nothing because RFC 9421 has no scheme to name. Same reasoning,
//! opposite answer: name the scheme the client should actually retry with.
//!
//! **A JWT-SVID is not an RFC 9068 access token**, and reusing those checks would refuse
//! every real one. The differences are load-bearing, not cosmetic:
//!   - `typ` is optional here, and if present MUST be `JWT` or `JOSE` (§2.3) — never
//!     `at+jwt`.
//!   - The JOSE header is a closed set. §2: "Any header not described here, registered or
//!     private, MUST NOT be included" — so only `alg`, `kid`, `typ`, and anything else is
//!     refused rather than ignored. Stricter than `bearer.rs`, which refuses only `crit`.
//!   - Only `sub`, `aud` and `exp` are required (§3.1–3.3). There is no mandatory `iss`,
//!     so the issuer recorded for a verified caller is derived from the trust domain in the
//!     verified `sub`, not read from a claim.
//!
//! **`ES256` only.** JWT-SVID permits nine algorithms (§2.1, none marked REQUIRED or
//! RECOMMENDED). `RS*`/`PS*` need the `rsa` crate, which carries an unpatched
//! RUSTSEC-2023-0071 timing side-channel, and this workspace's `deny.toml` runs with
//! `ignore = []` — so admitting RSA would mean writing an exception for a known key-recovery
//! bug. `ES384`/`ES512` are omitted because they are a second curve implementation for no
//! deployment this serves. A SPIRE deployment issuing RSA SVIDs is therefore not
//! interoperable here, which is a real limit and is documented as one rather than softened.
//!
//! This posture establishes **the caller**, and nothing else. A verified `spiffe://…`
//! identity is recorded on the decision, never minted into the Cedar graph: `spiffe://` is
//! reserved in [`decern_identity::exchange::RESERVED_SUBJECT_ID_PREFIXES`] for a
//! verified-provenance mint path that does not exist, and a posture that quietly admitted
//! principals would make that reservation a lie.

use std::collections::{BTreeMap, BTreeSet};

use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::caller::{Authenticated, CallerAuth, Denied};

/// Mirrors the ceiling the other two postures apply, for the same reason: an oversized
/// credential costs its sender a length comparison, not this server an allocation.
const MAX_TOKEN_BYTES: usize = 8192;

/// How much of an attacker-chosen string may be echoed back in an error.
const MAX_ECHO: usize = 64;

/// The one algorithm this deployment accepts. See the module note on why the rest of
/// JWT-SVID §2.1's table is refused rather than supported.
const ACCEPTED_ALG: &str = "ES256";

/// JWT-SVID §2: the JOSE header is a closed set, and anything outside it "MUST NOT be
/// included". Refused rather than ignored, so a header this module does not interpret can
/// never travel unexamined.
const PERMITTED_HEADERS: [&str; 3] = ["alg", "kid", "typ"];

/// One verifying key from a trust domain's bundle. `kid` is mandatory on bundle entries
/// (§6.1) even though it is optional on the token, which is what makes selection possible.
#[derive(Debug)]
pub(crate) struct BundleKey {
    pub(crate) kid: String,
    pub(crate) key: VerifyingKey,
}

pub(crate) struct SpiffeConfig {
    /// Trust domain -> its JWT-SVID signing keys. Matched on the trust domain **exactly**:
    /// a prefix comparison would let `example.org.evil` pass as `example.org`.
    pub(crate) trust_domains: BTreeMap<String, Vec<BundleKey>>,
    /// This deployment's resource identifier, which an SVID's `aud` must contain.
    pub(crate) audience: String,
    /// Workload identities exempt from the self-only bind: a gateway presenting an SVID
    /// is still a PEP. Empty by default, which is the stricter posture.
    pub(crate) pep: std::collections::BTreeSet<String>,
}

/// A JWK as it appears in a SPIFFE bundle. Only the EC/P-256 shape is accepted; every other
/// key type is refused at startup rather than at request time, so a deployment learns its
/// bundle is unusable when it boots and not when a caller arrives.
#[derive(Deserialize)]
struct BundleJwk {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(rename = "use", default)]
    use_: Option<String>,
}

#[derive(Deserialize)]
struct BundleDoc {
    keys: Vec<BundleJwk>,
}

/// Read one trust domain's bundle. Applies §6.2's filter — "Implementations MUST extract
/// the JWT-SVID specific keys before using them" — and then refuses anything left that this
/// deployment could not verify with anyway.
///
/// Returns a human-facing error because every caller is startup configuration; nothing here
/// runs on the request path.
pub(crate) fn load_bundle(raw: &str) -> Result<Vec<BundleKey>, String> {
    let doc: BundleDoc = serde_json::from_str(raw).map_err(|e| format!("not a JWK Set: {e}"))?;
    let mut keys = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for jwk in doc.keys {
        // §6.1: every JWT-SVID bundle entry sets `use` to `jwt-svid`. An entry for some
        // other purpose (an X.509 root, say) is skipped rather than rejected — a bundle
        // legitimately carries both.
        if jwk.use_.as_deref() != Some("jwt-svid") {
            continue;
        }
        let kid = jwk
            .kid
            .filter(|k| !k.is_empty())
            .ok_or_else(|| "a jwt-svid bundle entry has no kid (§6.1 requires one)".to_owned())?;
        if !seen.insert(kid.clone()) {
            return Err(format!("bundle repeats kid {}", brief(&kid)));
        }
        if jwk.kty != "EC" || jwk.crv.as_deref() != Some("P-256") {
            return Err(format!(
                "bundle entry {} is {}/{}, and this deployment verifies {ACCEPTED_ALG} only",
                brief(&kid),
                brief(&jwk.kty),
                brief(jwk.crv.as_deref().unwrap_or("-")),
            ));
        }
        let (Some(x), Some(y)) = (jwk.x.as_deref(), jwk.y.as_deref()) else {
            return Err(format!("bundle entry {} carries no x/y", brief(&kid)));
        };
        keys.push(BundleKey {
            key: p256_key(x, y).map_err(|e| format!("bundle entry {}: {e}", brief(&kid)))?,
            kid,
        });
    }
    if keys.is_empty() {
        return Err("bundle carries no jwt-svid keys, so this trust domain cannot be used".into());
    }
    Ok(keys)
}

fn p256_key(x_b64: &str, y_b64: &str) -> Result<VerifyingKey, String> {
    let x = URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|_| "x is not base64url")?;
    let y = URL_SAFE_NO_PAD
        .decode(y_b64)
        .map_err(|_| "y is not base64url")?;
    let (x, y): ([u8; 32], [u8; 32]) = (
        x.try_into().map_err(|_| "x is not 32 bytes")?,
        y.try_into().map_err(|_| "y is not 32 bytes")?,
    );
    let point = p256::EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
    VerifyingKey::from_encoded_point(&point)
        .ok()
        .ok_or_else(|| "x/y is not a point on P-256".into())
}

/// The trust domain of a SPIFFE ID, per the SPIFFE-ID spec's `spiffe://<trust domain>/<path>`
/// shape. Returns `None` for anything that is not a well-formed ID with a non-empty path —
/// a bare `spiffe://td` names a trust domain, not a workload.
fn trust_domain_of(id: &str) -> Option<&str> {
    let rest = id.strip_prefix("spiffe://")?;
    let (domain, path) = rest.split_once('/')?;
    if domain.is_empty() || path.is_empty() {
        return None;
    }
    // The spec restricts trust-domain characters; anything outside that set is not an ID
    // this deployment should try to match against configuration.
    if !domain
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(domain)
}

impl CallerAuth for SpiffeConfig {
    fn authenticate(
        &self,
        req: &axum::extract::Request,
        now_secs: u64,
        // An SVID is a bearer credential: it covers no part of the request, so the body
        // is not consulted here. Contrast `sig.rs`, where a POST covers its digest.
        _body: &[u8],
    ) -> Result<Authenticated, Denied> {
        let header = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        authenticate(header, self, now_secs)
    }

    /// RFC 6750 §3, because §5.2 makes this a `Bearer` credential. The description says
    /// which check failed and never why it failed for this particular token.
    fn refuse(&self, denied: Denied) -> Response {
        let realm = quoted(&self.audience);
        let (code, challenge) = match &denied {
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
                    "Bearer realm=\"{realm}\", error=\"insufficient_scope\", error_description=\"{}\"",
                    quoted(d)
                ),
            ),
        };
        let body =
            axum::Json(serde_json::json!({ "error": code, "error_description": denied.detail() }));
        let mut resp = (denied.status(), body).into_response();
        let value = axum::http::HeaderValue::from_str(&challenge)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("Bearer"));
        resp.headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, value);
        resp
    }
}

/// Validate a presented JWT-SVID, cheap self-asserted checks first and the signature last —
/// the same ordering discipline the other two postures use, and for the same reason:
/// nothing before the signature check is believed yet.
pub(crate) fn authenticate(
    header: Option<&str>,
    cfg: &SpiffeConfig,
    now_secs: u64,
) -> Result<Authenticated, Denied> {
    if cfg.trust_domains.is_empty() {
        return Err(Denied::Invalid("no trust domains are configured".into()));
    }
    let raw = header.ok_or(Denied::NoCredentials)?;
    // RFC 6750 §2.1, and the scheme is case-insensitive per RFC 7235 §2.1.
    let token = raw
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
        .map(|(_, t)| t.trim())
        .ok_or_else(|| Denied::Invalid("authorization scheme is not Bearer".into()))?;
    if token.len() > MAX_TOKEN_BYTES {
        return Err(Denied::Invalid("token exceeds the accepted size".into()));
    }

    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) if !s.is_empty() => (h, p, s),
        _ => return Err(Denied::Invalid("token is not a compact JWS".into())),
    };

    // The JOSE header is a closed set (§2). Checked before anything in it is trusted, so a
    // parameter this module does not interpret cannot ride along unexamined.
    let head: BTreeMap<String, Value> = decode_json(h, "header")?;
    if let Some(unknown) = head
        .keys()
        .find(|k| !PERMITTED_HEADERS.contains(&k.as_str()))
    {
        return Err(Denied::Invalid(format!(
            "JOSE header {} is not permitted in a JWT-SVID",
            brief(unknown)
        )));
    }
    // §2.3: optional, but if set it is `JWT` or `JOSE`. Notably never `at+jwt` — this is
    // not an RFC 9068 access token and must not be validated as one.
    match head.get("typ").and_then(Value::as_str) {
        None => {}
        Some(t) if t == "JWT" || t == "JOSE" => {}
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "token type {} is not a JWT-SVID type",
                brief(other)
            )));
        }
    }
    match head.get("alg").and_then(Value::as_str) {
        Some(a) if a == ACCEPTED_ALG => {}
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "algorithm {} is not accepted here; this deployment verifies {ACCEPTED_ALG} only",
                brief(other)
            )));
        }
        None => return Err(Denied::Invalid("token names no algorithm".into())),
    }
    let token_kid = head.get("kid").and_then(Value::as_str);

    let claims: BTreeMap<String, Value> = decode_json(p, "claims")?;
    // §3.1–3.3: exactly these three are required. `iss` is deliberately not among them.
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| Denied::Invalid("token carries no sub".into()))?
        .to_owned();
    let domain = trust_domain_of(&subject)
        .ok_or_else(|| {
            Denied::Invalid(format!(
                "sub {} is not a SPIFFE ID naming a workload",
                brief(&subject)
            ))
        })?
        .to_owned();

    // Exact match. A prefix comparison here would let `example.org.evil` present as
    // `example.org`, which is the whole reason the trust domain is a distinct field.
    let bundle = cfg.trust_domains.get(&domain).ok_or_else(|| {
        Denied::Invalid(format!(
            "trust domain {} is not configured here",
            brief(&domain)
        ))
    })?;

    // §2.2 leaves `kid` optional on the token while §6.1 requires it on every bundle entry.
    // With no `kid` and one key the choice is unambiguous; with several it is not, and the
    // spec offers no rule — refusing is this deployment's own decision, not a spec mandate,
    // because guessing which key a token meant is not a judgement a verifier should make.
    let key = match token_kid {
        Some(kid) => bundle
            .iter()
            .find(|k| k.kid == kid)
            .map(|k| &k.key)
            .ok_or_else(|| {
                Denied::Invalid(format!(
                    "no key {} in the bundle for {}",
                    brief(kid),
                    brief(&domain)
                ))
            })?,
        None if bundle.len() == 1 => &bundle[0].key,
        None => {
            return Err(Denied::Invalid(
                "token names no kid and its trust domain has more than one key".into(),
            ));
        }
    };

    // The expensive check, over a key this function chose from configuration — never one
    // the token supplied for its own verification.
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Denied::Invalid("signature is not base64url".into()))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| Denied::Invalid("signature is not a P-256 signature".into()))?;
    let signed = format!("{h}.{p}");
    key.verify(signed.as_bytes(), &signature).map_err(|_| {
        Denied::Invalid("signature does not verify against the trust bundle".into())
    })?;

    // Only past this line are the claims authentic. The trust domain that selected the
    // bundle came from an unverified `sub`, so bind it now: re-derive from the same value
    // and confirm it is still the domain whose key just verified. This holds structurally
    // (the value is parsed once and never re-read), and is asserted anyway so the property
    // is evident locally rather than requiring a reader to trace the flow.
    if trust_domain_of(&subject) != Some(domain.as_str()) {
        return Err(Denied::Invalid(
            "verified sub does not belong to the trust domain that verified it".into(),
        ));
    }

    if !audience_contains(claims.get("aud"), &cfg.audience) {
        return Err(Denied::Invalid(
            "token was not issued for this server as audience".into(),
        ));
    }
    // Exact, with no leeway. §6 of RFC 7519 permits a little; `bearer.rs` takes none, and
    // two JWT paths in one binary disagreeing about expiry is worth more confusion than the
    // leeway is worth.
    let exp = numeric_date(&claims, "exp")?
        .ok_or_else(|| Denied::Invalid("token carries no exp".into()))?;
    if now_secs as f64 >= exp {
        return Err(Denied::Invalid("token has expired".into()));
    }
    // §3 permits registered claims beyond the three it requires, so an `nbf` here carries
    // its RFC 7519 meaning and must gate. SPIRE commonly sets one; without this a token
    // that is not yet valid would be accepted right up until it expired.
    if let Some(nbf) = numeric_date(&claims, "nbf")?
        && (now_secs as f64) < nbf
    {
        return Err(Denied::Invalid("token is not yet valid".into()));
    }

    // An SVID names a workload, which is the same shape of caller a signed request
    // carries: it speaks for itself and not for anyone else. So it binds to itself unless
    // the operator has named it a PEP, exactly as `sig.rs` does. Leaving this `Any` would
    // reopen, through a second posture, the escalation that binding closed — a workload
    // naming any principal it likes as decide subject or mission approver.
    let who = Authenticated::new(
        &subject,
        // One workload is both the party and the client acting for it; there is no
        // separate delegating client in an SVID to name.
        &subject,
        // No `iss` claim is required (§3), so the issuer recorded is the trust domain that
        // actually vouched — derived from the verified `sub`, never read from the token.
        format!("spiffe://{domain}"),
    );
    Ok(if cfg.pep.contains(&subject) {
        who
    } else {
        who.self_only()
    })
}

/// RFC 7519 NumericDate, which may be fractional. A claim present but non-numeric is a
/// refusal rather than an absence: silently skipping a malformed `nbf` would let a token
/// that is not yet valid through. Mirrors `bearer.rs`.
fn numeric_date(claims: &BTreeMap<String, Value>, name: &str) -> Result<Option<f64>, Denied> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_f64()
            .map(Some)
            .ok_or_else(|| Denied::Invalid(format!("token {name} is not a number"))),
    }
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
        .take(MAX_ECHO)
        .collect()
}

/// Strip what would break out of a quoted-string in a header value (RFC 7235 §3.1).
fn quoted(s: &str) -> String {
    s.chars()
        .filter(|c| matches!(c, ' '..='~') && *c != '"' && *c != '\\')
        .take(MAX_ECHO)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use serde_json::json;

    const AUD: &str = "https://pdp.example/access/v1/evaluation";
    const TD: &str = "example.org";
    const SUB: &str = "spiffe://example.org/ns/api/sa/web";
    const NOW: u64 = 1_000;

    fn key(n: u8) -> SigningKey {
        let mut b = [0u8; 32];
        b[31] = n;
        SigningKey::from_bytes(&b.into()).unwrap()
    }

    /// A bundle entry for `k`, in the shape §6.1 requires.
    fn jwk(k: &SigningKey, kid: &str, use_: &str) -> Value {
        let vk = k.verifying_key().to_encoded_point(false);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(vk.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(vk.y().unwrap()),
            "kid": kid,
            "use": use_,
        })
    }

    fn bundle(entries: Vec<Value>) -> String {
        json!({ "keys": entries }).to_string()
    }

    fn cfg_with(domain: &str, keys: Vec<BundleKey>) -> SpiffeConfig {
        let mut trust_domains = BTreeMap::new();
        trust_domains.insert(domain.to_owned(), keys);
        SpiffeConfig {
            trust_domains,
            audience: AUD.into(),
            pep: std::collections::BTreeSet::new(),
        }
    }

    fn cfg(k: &SigningKey) -> SpiffeConfig {
        cfg_with(
            TD,
            load_bundle(&bundle(vec![jwk(k, "k1", "jwt-svid")])).unwrap(),
        )
    }

    /// Build a presented SVID. `head`/`claims` are patched so a test can bend exactly one
    /// thing and leave the rest well-formed.
    fn svid(
        k: &SigningKey,
        head_patch: impl FnOnce(&mut Value),
        claims_patch: impl FnOnce(&mut Value),
    ) -> String {
        let mut head = json!({ "alg": "ES256", "kid": "k1" });
        head_patch(&mut head);
        let mut claims = json!({ "sub": SUB, "aud": AUD, "exp": (NOW + 100) as f64 });
        claims_patch(&mut claims);
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&head).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let sig: Signature = k.sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn auth(token: &str, cfg: &SpiffeConfig) -> Result<Authenticated, Denied> {
        authenticate(Some(&format!("Bearer {token}")), cfg, NOW)
    }

    /// An SVID names a workload, so it binds to itself exactly as a signed-request agent
    /// does. Leaving this `Any` would reopen, through a second posture, the escalation
    /// that binding closed — a workload naming any principal as decide subject or mission
    /// approver. `--pep` is the deliberate exemption, and nothing else is.
    #[test]
    fn a_workload_binds_to_itself_unless_named_a_pep() {
        let k = key(7);
        let who = auth(&svid(&k, |_| {}, |_| {}), &cfg(&k)).unwrap();
        assert_eq!(who.bind, crate::caller::Bind::SelfOnly);

        let mut pep_cfg = cfg(&k);
        pep_cfg.pep.insert(SUB.to_owned());
        let pep_who = auth(&svid(&k, |_| {}, |_| {}), &pep_cfg).unwrap();
        assert_eq!(pep_who.bind, crate::caller::Bind::Any);
    }

    /// A JWT-SVID is still a JWT. An `nbf` a SPIFFE issuer sets must gate, and a
    /// fractional one must gate too — reading it with an integer accessor would skip the
    /// check entirely. Same discipline as the bearer path.
    #[test]
    fn a_not_yet_valid_svid_is_refused_including_a_fractional_nbf() {
        let k = key(7);
        for nbf in [json!(NOW + 100), json!((NOW as f64) + 0.5)] {
            let t = svid(&k, |_| {}, |c| c["nbf"] = nbf.clone());
            let e = auth(&t, &cfg(&k)).unwrap_err();
            assert!(
                e.detail().contains("not yet valid"),
                "{nbf}: {}",
                e.detail()
            );
        }
        // Already valid: an nbf in the past does not gate.
        let ok = svid(&k, |_| {}, |c| c["nbf"] = json!(NOW - 1));
        assert!(auth(&ok, &cfg(&k)).is_ok());
    }

    #[test]
    fn a_non_numeric_nbf_is_refused_not_skipped() {
        let k = key(7);
        let t = svid(&k, |_| {}, |c| c["nbf"] = json!("soon"));
        let e = auth(&t, &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("not a number"), "{}", e.detail());
    }

    #[test]
    fn a_well_formed_svid_authenticates_its_caller() {
        let k = key(7);
        let who = auth(&svid(&k, |_| {}, |_| {}), &cfg(&k)).unwrap();
        assert_eq!(who.subject, SUB);
        // No `iss` claim is required by the spec, so the issuer recorded is derived from
        // the trust domain in the verified `sub`.
        assert_eq!(who.issuer, "spiffe://example.org");
    }

    /// The reason the trust domain is matched exactly rather than by prefix: an attacker
    /// who controls `example.org.evil` must not be able to present as `example.org`.
    #[test]
    fn a_trust_domain_that_merely_starts_the_same_is_refused() {
        let k = key(7);
        let mut c = cfg(&k);
        c.trust_domains = BTreeMap::new();
        c.trust_domains.insert(
            "example.org.evil".to_owned(),
            load_bundle(&bundle(vec![jwk(&k, "k1", "jwt-svid")])).unwrap(),
        );
        let e = auth(&svid(&k, |_| {}, |_| {}), &c).unwrap_err();
        assert!(e.detail().contains("not configured here"), "{}", e.detail());
    }

    /// The property that makes this a distinct posture rather than bearer-with-a-key-swap.
    #[test]
    fn an_svid_signed_by_another_domains_key_is_refused() {
        let mine = key(7);
        let theirs = key(9);
        let e = auth(&svid(&theirs, |_| {}, |_| {}), &cfg(&mine)).unwrap_err();
        assert!(e.detail().contains("does not verify"), "{}", e.detail());
    }

    /// §2.1 permits nine algorithms; this deployment accepts one. Refused on the header,
    /// before any signature work — an RSA SVID must not reach the verifier at all.
    #[test]
    fn an_rs256_svid_is_refused_on_the_algorithm() {
        let k = key(7);
        let t = svid(&k, |h| h["alg"] = json!("RS256"), |_| {});
        let e = auth(&t, &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("ES256"), "{}", e.detail());
    }

    /// §2: "Any header not described here, registered or private, MUST NOT be included."
    /// Refused rather than ignored — `jku` in particular would otherwise name a key source.
    #[test]
    fn an_unknown_jose_header_is_refused() {
        let k = key(7);
        let t = svid(
            &k,
            |h| h["jku"] = json!("https://attacker.example/keys"),
            |_| {},
        );
        let e = auth(&t, &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("not permitted"), "{}", e.detail());
    }

    /// §2.3: `typ` is optional, and `at+jwt` is not one of its permitted values. An RFC
    /// 9068 access token is a different credential and must not pass here.
    #[test]
    fn an_rfc_9068_access_token_type_is_refused() {
        let k = key(7);
        let t = svid(&k, |h| h["typ"] = json!("at+jwt"), |_| {});
        let e = auth(&t, &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("not a JWT-SVID type"), "{}", e.detail());
    }

    #[test]
    fn the_permitted_typ_values_and_its_absence_are_all_accepted() {
        let k = key(7);
        for t in ["JWT", "JOSE"] {
            assert!(auth(&svid(&k, |h| h["typ"] = json!(t), |_| {}), &cfg(&k)).is_ok());
        }
        // Absent is the third permitted shape.
        assert!(auth(&svid(&k, |_| {}, |_| {}), &cfg(&k)).is_ok());
    }

    #[test]
    fn an_expired_svid_is_refused() {
        let k = key(7);
        let t = svid(&k, |_| {}, |c| c["exp"] = json!((NOW - 1) as f64));
        let e = auth(&t, &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("expired"), "{}", e.detail());
    }

    #[test]
    fn an_svid_for_another_service_is_refused() {
        let k = key(7);
        let t = svid(&k, |_| {}, |c| c["aud"] = json!("https://billing.example/"));
        let e = auth(&t, &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("audience"), "{}", e.detail());
    }

    #[test]
    fn a_sub_that_is_not_a_spiffe_id_is_refused() {
        let k = key(7);
        for bad in [
            "not-a-uri",
            "spiffe://example.org",
            "https://example.org/x",
            "",
        ] {
            let t = svid(&k, |_| {}, |c| c["sub"] = json!(bad));
            let e = auth(&t, &cfg(&k)).unwrap_err();
            assert!(
                e.detail().contains("not a SPIFFE ID") || e.detail().contains("not configured"),
                "{bad}: {}",
                e.detail()
            );
        }
    }

    /// §6.2 requires extracting the `jwt-svid` keys specifically. A bundle whose only
    /// entry is for some other purpose does not support this posture at all.
    #[test]
    fn bundle_entries_for_other_uses_are_filtered_out() {
        let k = key(7);
        let e = load_bundle(&bundle(vec![jwk(&k, "k1", "x509-svid")])).unwrap_err();
        assert!(e.contains("no jwt-svid keys"), "{e}");
    }

    /// §6.1 makes `kid` mandatory on every bundle entry, which is what makes selection
    /// possible when a token names one.
    #[test]
    fn a_bundle_entry_without_a_kid_is_refused_at_load() {
        let k = key(7);
        let mut j = jwk(&k, "k1", "jwt-svid");
        j.as_object_mut().unwrap().remove("kid");
        let e = load_bundle(&bundle(vec![j])).unwrap_err();
        assert!(e.contains("no kid"), "{e}");
    }

    /// An RSA bundle is refused when the process starts, not when a caller arrives.
    #[test]
    fn a_non_p256_bundle_entry_is_refused_at_load() {
        let raw = json!({"keys":[{"kty":"RSA","kid":"k1","use":"jwt-svid","n":"…","e":"AQAB"}]});
        let e = load_bundle(&raw.to_string()).unwrap_err();
        assert!(e.contains("ES256 only"), "{e}");
    }

    /// §2.2 leaves `kid` optional on the token. One key is unambiguous; several is not,
    /// and the spec gives no rule — this deployment refuses rather than guessing.
    #[test]
    fn a_kidless_token_resolves_only_when_the_bundle_is_unambiguous() {
        let k = key(7);
        let one = cfg_with(
            TD,
            load_bundle(&bundle(vec![jwk(&k, "k1", "jwt-svid")])).unwrap(),
        );
        let t = svid(
            &k,
            |h| {
                h.as_object_mut().unwrap().remove("kid");
            },
            |_| {},
        );
        assert!(auth(&t, &one).is_ok());

        let two = cfg_with(
            TD,
            load_bundle(&bundle(vec![
                jwk(&k, "k1", "jwt-svid"),
                jwk(&key(9), "k2", "jwt-svid"),
            ]))
            .unwrap(),
        );
        let e = auth(&t, &two).unwrap_err();
        assert!(e.detail().contains("more than one key"), "{}", e.detail());
    }

    #[test]
    fn a_kid_naming_no_bundle_key_is_refused() {
        let k = key(7);
        let t = svid(&k, |h| h["kid"] = json!("nope"), |_| {});
        let e = auth(&t, &cfg(&k)).unwrap_err();
        assert!(e.detail().contains("no key"), "{}", e.detail());
    }

    #[test]
    fn a_non_bearer_scheme_and_a_missing_header_are_distinguished() {
        let k = key(7);
        assert_eq!(
            authenticate(None, &cfg(&k), NOW).unwrap_err(),
            Denied::NoCredentials
        );
        let t = svid(&k, |_| {}, |_| {});
        let e = authenticate(Some(&format!("Basic {t}")), &cfg(&k), NOW).unwrap_err();
        assert!(e.detail().contains("not Bearer"), "{}", e.detail());
    }

    #[test]
    fn the_bearer_scheme_is_matched_case_insensitively() {
        let k = key(7);
        let t = svid(&k, |_| {}, |_| {});
        assert!(authenticate(Some(&format!("bearer {t}")), &cfg(&k), NOW).is_ok());
    }

    #[test]
    fn with_no_trust_domains_configured_nothing_authenticates() {
        let k = key(7);
        let empty = SpiffeConfig {
            trust_domains: BTreeMap::new(),
            audience: AUD.into(),
            pep: std::collections::BTreeSet::new(),
        };
        let e = auth(&svid(&k, |_| {}, |_| {}), &empty).unwrap_err();
        assert!(e.detail().contains("no trust domains"), "{}", e.detail());
    }
}
