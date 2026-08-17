// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! AAuth agent tokens, verified against provider keys pinned at startup.
//!
//! Implements the resource half of `draft-hardt-oauth-aauth-protocol` for **identity-based
//! access**: the mode where the resource applies its own policy to a verified agent identity
//! and no Person Server is involved. The PS-asserted and federated modes need a Person
//! Server, which this project does not implement and does not intend to.
//!
//! **Providers are configured, never discovered.** The draft's verification list says to
//! discover the issuer's JWKS via `{iss}/.well-known/{dwk}`. This deployment does not fetch:
//! it checks that `dwk` names the document the draft requires and then selects a key from a
//! JWK Set the operator supplied at startup. The draft contemplates exactly this — a resource
//! that pre-caches a provider's keys does not need the fetch — so an agent whose provider is
//! configured here interoperates, and an agent from a provider this deployment was never told
//! about is refused before any cryptography runs. That is the same closed-world boundary
//! every other posture applies, and the same reason: a decision must not depend on a third
//! party being reachable.
//!
//! **There is no `aud` claim on an agent token**, which is the sharpest difference from the
//! other token postures. `bearer.rs` and `spiffe.rs` both pin a token to this deployment
//! through its audience; an AAuth agent token carries nothing to match against. The signature
//! covers `@authority`, but that value is the `Host` the client sent, so on its own it binds
//! the signature to a *claimed* authority rather than to this server. Two deployments pinning
//! the same provider would otherwise accept each other's requests. `--aauth-audience` is
//! therefore required, and the `Host` must equal it: the signed `@authority` and the
//! configured identity have to agree before anything is believed.
//!
//! **`jti` is required and this deployment does not use it for replay detection.** The draft
//! gives `jti` for replay detection, audit and revocation. There is no nonce cache here — the
//! same limit the signed-request posture states — so a captured request replays inside the
//! freshness window. The claim is required and its shape checked; nothing more is claimed of
//! it.
//!
//! **`parent_agent` is not a decision input.** When present it marks a sub-agent, and it is
//! the agent provider's assertion about a relationship this server cannot verify. It is
//! validated for shape and otherwise ignored: a caller's account of its own lineage does not
//! reach the kernel, exactly as no other self-asserted claim does.

use std::collections::{BTreeMap, BTreeSet};

use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::caller::{Authenticated, CallerAuth, Denied};
use crate::sig;

/// Mirrors the ceiling every other posture applies: an oversized credential costs its sender
/// a length comparison, not this server an allocation.
const MAX_TOKEN_BYTES: usize = 8192;

/// How much of an attacker-chosen string may be echoed back in an error.
const MAX_ECHO: usize = 64;

/// The draft RECOMMENDs EdDSA and forbids `none`. This deployment accepts EdDSA only, which
/// is the curve every other decern signature path already uses, so the posture adds no new
/// cryptography — unlike the SPIFFE posture, whose spec has no EdDSA at all.
const ACCEPTED_ALG: &str = "EdDSA";

/// The token type an agent token carries. Anything else is refused rather than validated as
/// some other kind of JWT.
const AGENT_TOKEN_TYP: &str = "aa-agent+jwt";

/// The value `dwk` must carry. The draft names the metadata document; this deployment checks
/// the name and never dereferences it.
const REQUIRED_DWK: &str = "aauth-agent.json";

/// The JOSE header shape accepted here. Refused rather than ignored, so a parameter this
/// module does not interpret cannot travel unexamined — the discipline `spiffe.rs` applies
/// for the same reason.
const PERMITTED_HEADERS: [&str; 3] = ["alg", "kid", "typ"];

/// One verifying key from a provider's JWK Set. `kid` is mandatory here even though the
/// draft leaves it optional on some keys, because it is what makes selection unambiguous.
#[derive(Debug)]
pub(crate) struct ProviderKey {
    pub(crate) kid: String,
    pub(crate) key: VerifyingKey,
}

pub(crate) struct AauthConfig {
    /// Agent provider URL to the keys it signs agent tokens with. Matched exactly: a prefix
    /// comparison would let a lookalike issuer present as a configured one.
    pub(crate) providers: BTreeMap<String, Vec<ProviderKey>>,
    /// This deployment's authority, which the request's `Host` must equal. Stands in for the
    /// audience an agent token does not carry — see the module note.
    pub(crate) authority: String,
    /// Agents that may name principals other than themselves.
    pub(crate) pep: BTreeSet<String>,
}

/// A JWK as it appears in a provider's key set. Only the OKP/Ed25519 shape is accepted, and
/// every other key type is refused at startup rather than at request time, so a deployment
/// learns its configuration is unusable when it boots and not when a caller arrives.
#[derive(Deserialize)]
struct ProviderJwk {
    kty: String,
    #[serde(default)]
    crv: String,
    #[serde(default)]
    x: String,
    #[serde(default)]
    kid: String,
    #[serde(default, rename = "use")]
    use_: Option<String>,
}

#[derive(Deserialize)]
struct ProviderJwks {
    keys: Vec<ProviderJwk>,
}

/// Read one provider's JWK Set. Refuses a set this deployment could not verify with anyway,
/// at startup. Returns a human-facing error because every caller is configuration.
pub(crate) fn load_provider_keys(raw: &str) -> Result<Vec<ProviderKey>, String> {
    let doc: ProviderJwks =
        serde_json::from_str(raw).map_err(|e| format!("key set is not valid JSON: {e}"))?;
    let mut out = Vec::new();
    for jwk in doc.keys {
        // A set may legitimately carry keys for other purposes; skip those rather than
        // failing the whole document.
        if matches!(jwk.use_.as_deref(), Some(u) if u != "sig") {
            continue;
        }
        if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
            continue;
        }
        if jwk.kid.is_empty() {
            return Err("a signing key in the set carries no kid".into());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&jwk.x)
            .map_err(|_| format!("key {} has an x that is not base64url", jwk.kid))?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("key {} is not a 32-byte Ed25519 key", jwk.kid))?;
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|_| format!("key {} is not a valid Ed25519 key", jwk.kid))?;
        out.push(ProviderKey { kid: jwk.kid, key });
    }
    if out.is_empty() {
        return Err("key set carries no usable Ed25519 signing key".into());
    }
    Ok(out)
}

/// An agent provider identifier. The draft requires a valid HTTPS URL; checked at startup so
/// a malformed one fails the boot rather than every request.
pub(crate) fn valid_provider_url(iss: &str) -> bool {
    iss.starts_with("https://")
        && iss.len() > "https://".len()
        && !iss.contains(char::is_whitespace)
}

/// Pull the token out of `Signature-Key: sig=jwt; jwt="…"`, the presentation the draft
/// specifies. The raw header is what the outer signature covers, so only the token is taken
/// here; the header value itself is passed through untouched.
fn token_from_signature_key(raw: &str) -> Result<&str, Denied> {
    let (scheme, rest) = raw
        .split_once(';')
        .ok_or_else(|| Denied::Invalid("Signature-Key names no jwt parameter".into()))?;
    let scheme = scheme.trim();
    // `sig=jwt`, where `sig` is the signature label this deployment accepts.
    if !scheme.eq_ignore_ascii_case("sig=jwt") {
        return Err(Denied::Invalid(format!(
            "Signature-Key scheme {} is not jwt",
            brief(scheme)
        )));
    }
    let rest = rest.trim();
    let value = rest
        .strip_prefix("jwt=")
        .ok_or_else(|| Denied::Invalid("Signature-Key names no jwt parameter".into()))?;
    let token = value.trim().trim_matches('"');
    if token.is_empty() {
        return Err(Denied::Invalid("Signature-Key carries an empty jwt".into()));
    }
    Ok(token)
}

impl CallerAuth for AauthConfig {
    fn authenticate(
        &self,
        req: &axum::extract::Request,
        now_secs: u64,
        body: &[u8],
    ) -> Result<Authenticated, Denied> {
        let signed = sig::SignedRequest {
            method: req.method().as_str(),
            authority: header(req, "host").unwrap_or_default(),
            path: req.uri().path(),
            signature_key_header: header(req, "signature-key"),
            signature_input_header: header(req, "signature-input"),
            signature_header: header(req, "signature"),
            content_digest_header: header(req, "content-digest"),
            body,
        };
        authenticate(&signed, self, now_secs as i64)
    }

    /// The draft carries no challenge scheme of its own for a failed signature, so the
    /// refusal states which check failed and offers no `WWW-Authenticate` — the same choice
    /// `sig.rs` makes, and for the same reason: naming a scheme this deployment does not
    /// accept would invite a retry that cannot succeed.
    fn refuse(&self, denied: Denied) -> Response {
        let body = axum::Json(
            serde_json::json!({ "error": "invalid_request", "error_description": denied.detail() }),
        );
        (denied.status(), body).into_response()
    }
}

fn header<'a>(req: &'a axum::extract::Request, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

/// Validate an AAuth agent token and the signature it is bound to, cheap self-asserted checks
/// ahead of the expensive ones. Nothing before the two signature checks is believed.
pub(crate) fn authenticate(
    req: &sig::SignedRequest<'_>,
    cfg: &AauthConfig,
    now_secs: i64,
) -> Result<Authenticated, Denied> {
    if cfg.providers.is_empty() {
        return Err(Denied::Invalid("no agent providers are configured".into()));
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

    // The audience an agent token does not carry. Checked before any cryptography: this is
    // what stops a request signed for one deployment from verifying at another that pins the
    // same provider. `@authority` is the client's `Host`, so it is only meaningful once it
    // has been compared with what this server is actually called.
    if !req.authority.eq_ignore_ascii_case(&cfg.authority) {
        return Err(Denied::Invalid(
            "request authority is not this deployment".into(),
        ));
    }

    const LABEL: &str = "sig1";
    let input = sig::parse_signature_input(LABEL, input_header)?;
    let sig_bytes = sig::parse_signature(LABEL, sig_header)?;

    let components = sig::required_components(req.method, req.body);
    if input.components.as_slice() != components {
        return Err(Denied::Invalid(
            "Signature-Input does not cover exactly the required components".into(),
        ));
    }
    let age = now_secs - input.created;
    if !(-sig::MAX_CLOCK_SKEW_AHEAD_SECS..=sig::MAX_SIGNATURE_AGE_SECS).contains(&age) {
        return Err(Denied::Invalid(
            "signature is outside the accepted freshness window".into(),
        ));
    }

    let token = token_from_signature_key(key_header)?;
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) if !s.is_empty() => (h, p, s),
        _ => return Err(Denied::Invalid("agent token is not a compact JWS".into())),
    };

    let head: BTreeMap<String, Value> = decode_json(h, "header")?;
    if let Some(unknown) = head
        .keys()
        .find(|k| !PERMITTED_HEADERS.contains(&k.as_str()))
    {
        return Err(Denied::Invalid(format!(
            "JOSE header {} is not permitted in an agent token",
            brief(unknown)
        )));
    }
    match head.get("typ").and_then(Value::as_str) {
        Some(t) if t == AGENT_TOKEN_TYP => {}
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "token type {} is not an agent token",
                brief(other)
            )));
        }
        None => return Err(Denied::Invalid("agent token names no typ".into())),
    }
    match head.get("alg").and_then(Value::as_str) {
        Some(a) if a == ACCEPTED_ALG => {}
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "algorithm {} is not accepted here; this deployment verifies {ACCEPTED_ALG} only",
                brief(other)
            )));
        }
        None => return Err(Denied::Invalid("agent token names no algorithm".into())),
    }
    let token_kid = head.get("kid").and_then(Value::as_str);

    let claims: BTreeMap<String, Value> = decode_json(p, "claims")?;

    let issuer = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| Denied::Invalid("agent token carries no iss".into()))?
        .to_owned();
    // Exact match, for the same reason the SPIFFE posture matches trust domains exactly.
    let provider = cfg.providers.get(&issuer).ok_or_else(|| {
        Denied::Invalid(format!(
            "agent provider {} is not configured here",
            brief(&issuer)
        ))
    })?;

    // The draft's verification step for `dwk`: check it names the metadata document. The
    // document is not fetched — see the module note on configured providers.
    match claims.get("dwk").and_then(Value::as_str) {
        Some(d) if d == REQUIRED_DWK => {}
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "dwk {} is not {REQUIRED_DWK}",
                brief(other)
            )));
        }
        None => return Err(Denied::Invalid("agent token carries no dwk".into())),
    }

    let key = match token_kid {
        Some(kid) => provider
            .iter()
            .find(|k| k.kid == kid)
            .map(|k| &k.key)
            .ok_or_else(|| {
                Denied::Invalid(format!(
                    "no key {} for provider {}",
                    brief(kid),
                    brief(&issuer)
                ))
            })?,
        None if provider.len() == 1 => &provider[0].key,
        None => {
            return Err(Denied::Invalid(
                "agent token names no kid and its provider has more than one key".into(),
            ));
        }
    };

    // Unlike the signed-request posture, an agent token's own signature IS verified here.
    // There it is redundant, because the token is covered by the outer signature and the
    // deployment already pins the agent's key. Here the token is a provider's assertion
    // about which key an agent holds, so the provider's signature over it is the only thing
    // that makes `cnf` trustworthy.
    let token_sig_bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Denied::Invalid("agent token signature is not base64url".into()))?;
    let token_sig = Signature::from_slice(&token_sig_bytes)
        .map_err(|_| Denied::Invalid("agent token signature is malformed".into()))?;
    let signed_part = format!("{h}.{p}");
    key.verify_strict(signed_part.as_bytes(), &token_sig)
        .map_err(|_| Denied::Invalid("agent token does not verify against its provider".into()))?;

    // Past this line the claims are the provider's, not the caller's. The provider was
    // selected from an unverified `iss`, so bind it now: confirm the claim still names the
    // provider whose key just verified. This holds structurally — the value is read once and
    // never re-read — and is asserted anyway so the property is evident locally.
    if claims.get("iss").and_then(Value::as_str) != Some(issuer.as_str()) {
        return Err(Denied::Invalid(
            "verified iss is not the provider that verified it".into(),
        ));
    }

    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| Denied::Invalid("agent token carries no sub".into()))?
        .to_owned();
    if claims
        .get("jti")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(Denied::Invalid("agent token carries no jti".into()));
    }
    let exp = numeric_date(&claims, "exp")?
        .ok_or_else(|| Denied::Invalid("agent token carries no exp".into()))?;
    if now_secs as f64 >= exp {
        return Err(Denied::Invalid("agent token has expired".into()));
    }
    let iat = numeric_date(&claims, "iat")?
        .ok_or_else(|| Denied::Invalid("agent token carries no iat".into()))?;
    if iat > now_secs as f64 {
        return Err(Denied::Invalid(
            "agent token is issued in the future".into(),
        ));
    }
    // Shape only. A `ps` names a Person Server, which this deployment does not consult:
    // identity-based access applies local policy and never asks a third party.
    if let Some(ps) = claims.get("ps").and_then(Value::as_str)
        && !valid_provider_url(ps)
    {
        return Err(Denied::Invalid("ps is not a valid HTTPS URL".into()));
    }
    // Shape only, deliberately. See the module note: a caller's account of its own lineage
    // is not a decision input.
    if let Some(parent) = claims.get("parent_agent")
        && parent.as_str().is_none_or(str::is_empty)
    {
        return Err(Denied::Invalid(
            "parent_agent is not an agent identifier".into(),
        ));
    }

    // The confirmed key, and the second signature check: the request itself.
    let cnf: sig::Cnf = serde_json::from_value(
        claims
            .get("cnf")
            .cloned()
            .ok_or_else(|| Denied::Invalid("agent token carries no cnf".into()))?,
    )
    .map_err(|_| Denied::Invalid("cnf does not carry a usable jwk".into()))?;
    let confirmed = sig::jwk_to_verifying_key(&cnf.jwk)?;

    let content_digest = sig::bind_content_digest(components, req)?;
    let authority = req.authority.to_ascii_lowercase();
    let covered = sig::Covered {
        method: req.method,
        authority: &authority,
        path: req.path,
        content_digest,
        signature_key: key_header,
    };
    let mut values = Vec::with_capacity(components.len());
    for component in components {
        values.push(covered.value(component)?);
    }
    let base = sig::signature_base(components, &values, LABEL, input_header);
    let request_sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| Denied::Invalid("signature is malformed".into()))?;
    confirmed
        .verify_strict(base.as_bytes(), &request_sig)
        .map_err(|_| {
            Denied::Invalid("signature does not verify against the token's confirmed key".into())
        })?;

    // An agent speaks for itself. Leaving this `Any` would reopen, through a fifth posture,
    // the escalation that binding closed for the other two workload postures.
    let who = Authenticated::new(&subject, &subject, issuer);
    Ok(if cfg.pep.contains(&subject) {
        who
    } else {
        who.self_only()
    })
}

/// RFC 7519 NumericDate, which may be fractional. A claim present but non-numeric is a
/// refusal rather than an absence, so a malformed `exp` cannot read as "no expiry".
fn numeric_date(claims: &BTreeMap<String, Value>, name: &str) -> Result<Option<f64>, Denied> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_f64()
            .map(Some)
            .ok_or_else(|| Denied::Invalid(format!("agent token {name} is not a number"))),
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(part: &str, what: &str) -> Result<T, Denied> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| Denied::Invalid(format!("agent token {what} is not base64url")))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| Denied::Invalid(format!("agent token {what} is not JSON")))
}

/// Bounded by characters, never bytes: the string is attacker-chosen, and a byte bound that
/// cut a multi-byte character would turn a refusal into a downed request.
fn brief(s: &str) -> String {
    let kept: Vec<char> = s.trim().chars().filter(|c| !c.is_control()).collect();
    let mut out: String = kept.iter().take(MAX_ECHO).collect();
    if kept.len() > MAX_ECHO {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller::Bind;
    use decern_crypto::{Signer, SigningKey};
    use serde_json::json;

    const ISS: &str = "https://agent-provider.example";
    const AGENT: &str = "https://agent-provider.example/agents/agent-1";
    const AUTHORITY: &str = "pdp.example";
    const PATH: &str = "/access/v1/evaluation";
    const KID: &str = "provider-key-1";
    const CREATED: i64 = 1_000;
    const NOW: i64 = 1_010;

    fn jwk(key: &VerifyingKey) -> Value {
        json!({ "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(key.to_bytes()) })
    }

    /// An agent token as a provider would mint it: signed by the provider's key over the
    /// header and claims, unlike `sig.rs`'s fixture whose signature segment is never read.
    fn agent_token(
        provider: &SigningKey,
        cnf_key: &VerifyingKey,
        head_patch: impl FnOnce(&mut Value),
        claims_patch: impl FnOnce(&mut Value),
    ) -> String {
        let mut header = json!({ "typ": AGENT_TOKEN_TYP, "alg": ACCEPTED_ALG, "kid": KID });
        head_patch(&mut header);
        let mut claims = json!({
            "iss": ISS,
            "dwk": REQUIRED_DWK,
            "sub": AGENT,
            "jti": "token-1",
            "iat": (NOW - 100) as f64,
            "exp": (NOW + 100) as f64,
            "cnf": { "jwk": jwk(cnf_key) },
        });
        claims_patch(&mut claims);
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signed = format!("{h}.{p}");
        let sig = provider.sign(signed.as_bytes());
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn signature_key_header(token: &str) -> String {
        format!("sig=jwt; jwt=\"{token}\"")
    }

    fn cfg(provider_key: &VerifyingKey) -> AauthConfig {
        let mut providers = BTreeMap::new();
        providers.insert(
            ISS.to_owned(),
            vec![ProviderKey {
                kid: KID.to_owned(),
                key: *provider_key,
            }],
        );
        AauthConfig {
            providers,
            authority: AUTHORITY.to_owned(),
            pep: BTreeSet::new(),
        }
    }

    /// Sign a POST the way an agent must to reach this deployment: the draft's components
    /// plus `content-digest`, which this profile requires on a bodied request.
    fn sign_post(
        agent: &SigningKey,
        key_header: &str,
        body: &[u8],
        created: i64,
    ) -> (String, String, String) {
        let components = sig::required_components("POST", body);
        let digest = sig::content_digest_header_value(body);
        let list = components
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(" ");
        let input = format!("sig1=({list});created={created}");
        let covered = sig::Covered {
            method: "POST",
            authority: AUTHORITY,
            path: PATH,
            content_digest: Some(digest.as_str()),
            signature_key: key_header,
        };
        let values: Vec<&str> = components
            .iter()
            .map(|c| covered.value(c).expect("fixture component"))
            .collect();
        let base = sig::signature_base(components, &values, "sig1", &input);
        let s = agent.sign(base.as_bytes());
        let sig_value = format!(
            "sig1=:{}:",
            base64::engine::general_purpose::STANDARD.encode(s.to_bytes())
        );
        (input, sig_value, digest)
    }

    struct Fixture {
        key_header: String,
        input: String,
        sig: String,
        digest: String,
        body: Vec<u8>,
    }

    fn post_fixture(provider: &SigningKey, agent: &SigningKey) -> Fixture {
        fixture_with(provider, agent, |_| {}, |_| {})
    }

    fn fixture_with(
        provider: &SigningKey,
        agent: &SigningKey,
        head_patch: impl FnOnce(&mut Value),
        claims_patch: impl FnOnce(&mut Value),
    ) -> Fixture {
        let body = br#"{"subject":{"type":"Principal","id":"corp"}}"#.to_vec();
        let token = agent_token(provider, &agent.verifying_key(), head_patch, claims_patch);
        let key_header = signature_key_header(&token);
        let (input, sig, digest) = sign_post(agent, &key_header, &body, CREATED);
        Fixture {
            key_header,
            input,
            sig,
            digest,
            body,
        }
    }

    fn req<'a>(f: &'a Fixture, authority: &'a str) -> sig::SignedRequest<'a> {
        sig::SignedRequest {
            method: "POST",
            authority,
            path: PATH,
            signature_key_header: Some(&f.key_header),
            signature_input_header: Some(&f.input),
            signature_header: Some(&f.sig),
            content_digest_header: Some(&f.digest),
            body: &f.body,
        }
    }

    fn keys() -> (SigningKey, SigningKey) {
        (
            SigningKey::from_bytes(&[7u8; 32]),
            SigningKey::from_bytes(&[9u8; 32]),
        )
    }

    #[test]
    fn a_well_formed_agent_request_is_authenticated_and_binds_to_itself() {
        let (provider, agent) = keys();
        let f = post_fixture(&provider, &agent);
        let who = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect("should authenticate");
        assert_eq!(who.subject, AGENT);
        assert_eq!(who.issuer, ISS);
        assert_eq!(who.bind, Bind::SelfOnly);
    }

    #[test]
    fn a_listed_pep_may_name_other_principals() {
        let (provider, agent) = keys();
        let f = post_fixture(&provider, &agent);
        let mut c = cfg(&provider.verifying_key());
        c.pep.insert(AGENT.to_owned());
        let who = authenticate(&req(&f, AUTHORITY), &c, NOW).expect("should authenticate");
        assert_eq!(who.bind, Bind::Any);
    }

    /// The control that stands in for the audience an agent token does not carry. Without
    /// it, a request signed for one deployment verifies at another pinning the same provider.
    #[test]
    fn a_request_for_another_authority_is_refused() {
        let (provider, agent) = keys();
        let f = post_fixture(&provider, &agent);
        let err = authenticate(
            &req(&f, "other.example"),
            &cfg(&provider.verifying_key()),
            NOW,
        )
        .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("not this deployment")));
    }

    /// This profile requires body coverage on a bodied request even though the draft's own
    /// example does not. Without it one captured signature authorizes any body at this path.
    #[test]
    fn a_post_that_does_not_cover_the_body_is_refused() {
        let (provider, agent) = keys();
        let body = br#"{"subject":{"type":"Principal","id":"corp"}}"#.to_vec();
        let token = agent_token(&provider, &agent.verifying_key(), |_| {}, |_| {});
        let key_header = signature_key_header(&token);
        // The draft's list, without `content-digest`.
        let components = ["@method", "@authority", "@path", "signature-key"];
        let list = components
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(" ");
        let input = format!("sig1=({list});created={CREATED}");
        let covered = sig::Covered {
            method: "POST",
            authority: AUTHORITY,
            path: PATH,
            content_digest: None,
            signature_key: &key_header,
        };
        let values: Vec<&str> = components
            .iter()
            .map(|c| covered.value(c).expect("fixture component"))
            .collect();
        let base = sig::signature_base(&components, &values, "sig1", &input);
        let s = agent.sign(base.as_bytes());
        let sig_value = format!(
            "sig1=:{}:",
            base64::engine::general_purpose::STANDARD.encode(s.to_bytes())
        );
        let r = sig::SignedRequest {
            method: "POST",
            authority: AUTHORITY,
            path: PATH,
            signature_key_header: Some(&key_header),
            signature_input_header: Some(&input),
            signature_header: Some(&sig_value),
            content_digest_header: None,
            body: &body,
        };
        let err =
            authenticate(&r, &cfg(&provider.verifying_key()), NOW).expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("required components")));
    }

    #[test]
    fn a_token_from_an_unconfigured_provider_is_refused() {
        let (provider, agent) = keys();
        let f = fixture_with(
            &provider,
            &agent,
            |_| {},
            |c| c["iss"] = json!("https://other.example"),
        );
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("is not configured here")));
    }

    #[test]
    fn a_token_signed_by_the_wrong_provider_key_is_refused() {
        let (provider, agent) = keys();
        let impostor = SigningKey::from_bytes(&[3u8; 32]);
        let f = post_fixture(&impostor, &agent);
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(
            matches!(err, Denied::Invalid(ref d) if d.contains("does not verify against its provider"))
        );
    }

    /// Proof of possession: the token is byte-identical and unexpired, and only the key
    /// signing the request differs.
    #[test]
    fn a_request_signed_by_a_key_the_token_does_not_confirm_is_refused() {
        let (provider, agent) = keys();
        let other = SigningKey::from_bytes(&[11u8; 32]);
        let body = br#"{"subject":{"type":"Principal","id":"corp"}}"#.to_vec();
        // `cnf` confirms `agent`; the request is signed by `other`.
        let token = agent_token(&provider, &agent.verifying_key(), |_| {}, |_| {});
        let key_header = signature_key_header(&token);
        let (input, sig, digest) = sign_post(&other, &key_header, &body, CREATED);
        let f = Fixture {
            key_header,
            input,
            sig,
            digest,
            body,
        };
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("confirmed key")));
    }

    #[test]
    fn a_non_agent_token_type_is_refused() {
        let (provider, agent) = keys();
        let f = fixture_with(&provider, &agent, |h| h["typ"] = json!("at+jwt"), |_| {});
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("is not an agent token")));
    }

    #[test]
    fn a_non_eddsa_algorithm_is_refused() {
        let (provider, agent) = keys();
        let f = fixture_with(&provider, &agent, |h| h["alg"] = json!("RS256"), |_| {});
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("is not accepted here")));
    }

    #[test]
    fn an_unknown_jose_header_is_refused_rather_than_ignored() {
        let (provider, agent) = keys();
        let f = fixture_with(
            &provider,
            &agent,
            |h| h["jku"] = json!("https://evil.example"),
            |_| {},
        );
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("is not permitted")));
    }

    #[test]
    fn a_wrong_dwk_is_refused() {
        let (provider, agent) = keys();
        let f = fixture_with(
            &provider,
            &agent,
            |_| {},
            |c| c["dwk"] = json!("elsewhere.json"),
        );
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("is not aauth-agent.json")));
    }

    #[test]
    fn a_kid_naming_no_configured_key_is_refused() {
        let (provider, agent) = keys();
        let f = fixture_with(&provider, &agent, |h| h["kid"] = json!("nope"), |_| {});
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("no key")));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let (provider, agent) = keys();
        let f = fixture_with(
            &provider,
            &agent,
            |_| {},
            |c| c["exp"] = json!((NOW - 1) as f64),
        );
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("has expired")));
    }

    #[test]
    fn a_token_issued_in_the_future_is_refused() {
        let (provider, agent) = keys();
        let f = fixture_with(
            &provider,
            &agent,
            |_| {},
            |c| c["iat"] = json!((NOW + 60) as f64),
        );
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("issued in the future")));
    }

    #[test]
    fn a_token_without_a_jti_is_refused() {
        let (provider, agent) = keys();
        let f = fixture_with(
            &provider,
            &agent,
            |_| {},
            |c| {
                c.as_object_mut().unwrap().remove("jti");
            },
        );
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("no jti")));
    }

    #[test]
    fn no_credentials_is_distinguishable_from_bad_ones() {
        let (provider, _) = keys();
        let r = sig::SignedRequest {
            method: "POST",
            authority: AUTHORITY,
            path: PATH,
            signature_key_header: None,
            signature_input_header: None,
            signature_header: None,
            content_digest_header: None,
            body: b"",
        };
        let err =
            authenticate(&r, &cfg(&provider.verifying_key()), NOW).expect_err("should refuse");
        assert!(matches!(err, Denied::NoCredentials));
    }

    #[test]
    fn a_signature_key_header_that_is_not_the_jwt_scheme_is_refused() {
        let (provider, agent) = keys();
        let mut f = post_fixture(&provider, &agent);
        f.key_header = "sig=mtls; jwt=\"x\"".to_owned();
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("is not jwt")));
    }

    #[test]
    fn a_key_set_without_a_kid_is_refused_at_startup() {
        let raw = json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": "AAAA" }] }).to_string();
        assert!(load_provider_keys(&raw).is_err());
    }

    #[test]
    fn a_provider_url_must_be_https() {
        assert!(valid_provider_url("https://provider.example"));
        assert!(!valid_provider_url("http://provider.example"));
        assert!(!valid_provider_url("provider.example"));
    }
}
