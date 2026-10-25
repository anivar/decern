// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! AAuth agent tokens, verified against provider keys pinned at startup.
//!
//! Implements the resource half of `draft-hardt-oauth-aauth-protocol` for **agent identity
//! access** (-11 §4.2.1): the resource applies its own policy to a verified agent identity
//! and no Person Server is involved. Person identity access (§4.2.3), which verifies a person
//! token instead, is not implemented. The remaining modes have the resource issue session or
//! resource tokens, and this project issues no token.
//!
//! **Providers are configured, never discovered.** The draft has a verifier discover the
//! issuer's JWKS via `{iss}/.well-known/{dwk}` (-11 §11.4, §11.5.2). This deployment does not
//! fetch: it checks that `dwk` names the document the draft requires and then selects a key
//! from a JWK Set the operator supplied at startup. That departs from the draft, which gives a
//! resource no such option; an agent whose provider is configured here interoperates, and an
//! agent from a provider this deployment was never told about is refused before any
//! cryptography runs. That is the same closed-world boundary every other posture applies, and
//! the same reason: a decision must not depend on a third party being reachable.
//!
//! **There is no `aud` claim on an agent token**, which is the sharpest difference from the
//! other token postures. `bearer.rs` and `spiffe.rs` both pin a token to this deployment
//! through its audience; an AAuth agent token carries nothing to match against. The signature
//! covers `@authority`, but that value is the authority the client sent, so on its own it
//! binds the signature to a *claimed* authority rather than to this server. Two deployments
//! pinning the same provider would otherwise accept each other's requests. `--aauth-audience`
//! is therefore required, and the request's authority must equal it: the signed `@authority`
//! and the configured identity have to agree before anything is believed.
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

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::caller::{Authenticated, CallerAuth, Denied, brief};
use crate::sig;

/// Draft -11 §5.3.1: an agent token SHOULD NOT have a lifetime above 24 hours. The draft
/// leaves the bound to the verifier's policy; this deployment refuses a token that claims
/// more, because with no nonce cache a long-lived token is a long replay window.
const MAX_AGENT_TOKEN_LIFETIME_SECS: i64 = 24 * 60 * 60;

/// The two refusals `refuse` must recognise on its way out: draft -11 §11.3.4 step 3 and
/// §11.5.2 answer a signature `created`, or an agent token `iat`, further ahead of the
/// verifier's clock than its window with `Signature-Error: error=clock_skew`, so the agent
/// can tell skew from a bad request. [`Denied`] carries no variant for it — the enum is
/// shared by every posture and the other postures have no such signal — so the detail text
/// is the marker, compared whole.
const CLOCK_SKEW_DETAIL: &str = "agent token is issued ahead of this server's clock";
const CREATED_AHEAD_DETAIL: &str = "signature is created ahead of this server's clock";

/// The token's `alg`: the fully-specified Ed25519, never the polymorphic `EdDSA`, which -11
/// §11.3.1 and §11.5.1 forbid (RFC 9864 §2.2). Ed25519 is the algorithm every other decern
/// signature path already uses, so the posture adds no new cryptography.
const TOKEN_ALG: &str = crate::jwk::ED25519;

/// The signature validity window, applied to `created` behind and ahead of this clock and
/// to an agent token `iat` ahead of it: -11 §11.3.4 step 3's default, which §11.5.2 has the
/// `iat` bound share.
const SIGNATURE_WINDOW_SECS: i64 = 60;

/// What this posture accepts in `Signature-Input`: the label the agent chose, which
/// `Signature-Key` must carry a member under (§11.3.4 step 4); an `alg` parameter, not read
/// at all, since the key names the algorithm (§11.3.3.2); and `expires`, honoured
/// (§11.3.4.2). A `keyid` is checked to be a string, as RFC 9421 §2.3 defines it, and never
/// chooses the key, which is the one `Signature-Key` conveys (§11.3.3.2). `nonce` and `tag`
/// are refused, a choice of this profile: -11 defines no nonce mechanism and no tag.
const PROFILE: crate::httpsig::Profile<'static> = crate::httpsig::Profile {
    label: None,
    ignore_alg: true,
    accept_expires: true,
};

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
    /// This deployment's authority, which the request's authority must equal. Stands in for
    /// the audience an agent token does not carry — see the module note.
    pub(crate) authority: String,
    /// Agents that may name principals other than themselves.
    pub(crate) pep: BTreeSet<String>,
}

#[derive(Deserialize)]
struct ProviderJwks {
    keys: Vec<Value>,
}

/// Read one provider's JWK Set. A member is usable when it has no `use` other than `sig`,
/// names a key this deployment can verify with under the rules in [`crate::jwk`], and carries
/// a `kid` to select it by. Every other member is skipped, one that does not parse as a JWK
/// included: RFC 7517 §5 has an implementation ignore a JWK it cannot use, and sig-key §3.3
/// forbids failing because of a member that is not selected. A member name given twice in a
/// JWK keeps the last, as RFC 7517 §4 permits. The set is refused at startup when no member
/// is usable, or when two usable members share a `kid`, which would make the selection a
/// token's `kid` names ambiguous; a deployment learns its configuration is unusable when it
/// boots and not when a caller arrives. Returns a human-facing error because every caller is
/// configuration.
pub(crate) fn load_provider_keys(raw: &str) -> Result<Vec<ProviderKey>, String> {
    let doc: ProviderJwks =
        serde_json::from_str(raw).map_err(|e| format!("key set is not valid JSON: {e}"))?;
    let mut out = Vec::new();
    for member in doc.keys {
        let Ok(jwk) = serde_json::from_value::<crate::jwk::Jwk>(member) else {
            continue;
        };
        if matches!(jwk.use_.as_deref(), Some(u) if u != "sig") {
            continue;
        }
        let (Ok(key), Some(kid)) = (jwk.ed25519(), jwk.kid.filter(|k| !k.is_empty())) else {
            continue;
        };
        if out.iter().any(|k: &ProviderKey| k.kid == kid) {
            return Err(format!("two usable keys in the set share the kid {kid}"));
        }
        out.push(ProviderKey { kid, key });
    }
    if out.is_empty() {
        return Err(format!(
            "key set carries no usable signing key; one needs kty OKP, crv Ed25519, \
             alg {TOKEN_ALG}, a kid, and no use other than sig"
        ));
    }
    Ok(out)
}

/// An agent provider identifier as §11.1.1 spells it: `https://` and a host, nothing more.
/// Checked at startup so a malformed one fails the boot rather than every request.
pub(crate) fn valid_provider_url(iss: &str) -> bool {
    provider_host(iss).is_some()
}

/// The host an agent provider identifier names, which is the domain of every agent
/// identifier that provider issues (§5.1, §11.2.1).
pub(crate) fn provider_host(iss: &str) -> Option<&str> {
    let host = iss.strip_prefix("https://")?;
    valid_domain(host).then_some(host)
}

/// A domain as §11.1.1 requires: lowercase ASCII letters, digits, `-` and `.`, with a label
/// either side of every dot, so no port, path, query, fragment or trailing slash. An
/// internationalized name arrives as A-labels, which fit.
fn valid_domain(host: &str) -> bool {
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The domain of an agent identifier `aauth:local@domain` (§5.2): a local part that is
/// non-empty, at most 255 characters of ASCII letters, digits, `-`, `_`, `+` and `.`, and a
/// domain as a provider identifier has. The local part is not read further: §5.2 keeps `+`
/// for readability and makes `parent_agent` the marker that counts.
pub(crate) fn agent_identifier_domain(id: &str) -> Option<&str> {
    let (local, domain) = id.strip_prefix("aauth:")?.split_once('@')?;
    let local_ok = !local.is_empty()
        && local.len() <= 255
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_+.".contains(&b));
    (local_ok && valid_domain(domain)).then_some(domain)
}

/// The agent token from `Signature-Key`, an RFC 9651 Dictionary keyed by signature label
/// (sig-key §3): the member under `label`, whose scheme must be `jwt` (-11 §11.3.2) and whose
/// `jwt` parameter is the token. Members under other labels are ignored (sig-key §3.1), as is
/// a `cache` request (§3.8), which this deployment does not act on. The raw header is what
/// the signature covers, so only the token is taken here.
///
/// The header is parsed as RFC 9651 says, so a repeated label or a repeated `jwt` parameter
/// keeps the last, the value every conforming parser reads. One refusal is this deployment's
/// own, a departure from RFC 9651 §3.2's default of ignoring members a recipient does not
/// use: a second `jwt`-scheme member under another label is refused. This deployment
/// verifies one signature, so such a member confirms nothing here, and with two of them the
/// label, which RFC 9421 §7.2.5 says carries no meaning and an intermediary may change,
/// would choose which agent the request is recorded as.
fn token_from_signature_key(raw: &str, label: &str) -> Result<String, Denied> {
    let members = crate::httpsig::dictionary_9651(raw, "Signature-Key")?;
    let jwt_members = members
        .values()
        .filter(|m| {
            matches!(m, sfv::ListEntry::Item(i)
                if matches!(&i.bare_item, sfv::BareItem::Token(t) if t.as_str() == "jwt"))
        })
        .count();
    if jwt_members > 1 {
        return Err(Denied::Invalid(
            "Signature-Key carries more than one jwt-scheme member; one signature is verified here"
                .into(),
        ));
    }
    let Some(member) = members.get(label) else {
        return Err(Denied::Invalid(format!(
            "Signature-Key carries no member labelled {}",
            brief(label)
        )));
    };
    let sfv::ListEntry::Item(item) = member else {
        return Err(Denied::Invalid(
            "Signature-Key member is not a scheme".into(),
        ));
    };
    match &item.bare_item {
        sfv::BareItem::Token(t) if t.as_str() == "jwt" => {}
        sfv::BareItem::Token(t) => {
            return Err(Denied::Invalid(format!(
                "Signature-Key scheme {} is not jwt",
                brief(t.as_str())
            )));
        }
        _ => {
            return Err(Denied::Invalid(
                "Signature-Key scheme is not a token".into(),
            ));
        }
    }
    let token = match item.params.iter().find(|(k, _)| k.as_str() == "jwt") {
        Some((_, sfv::BareItem::String(s))) => s.as_str().to_owned(),
        Some(_) => {
            return Err(Denied::Invalid(
                "Signature-Key jwt parameter is not a string".into(),
            ));
        }
        None => {
            return Err(Denied::Invalid(
                "Signature-Key names no jwt parameter".into(),
            ));
        }
    };
    if token.is_empty() {
        return Err(Denied::Invalid("Signature-Key carries an empty jwt".into()));
    }
    Ok(token)
}

/// An agent token's `cnf`, whose `jwk` is held to the key rules in [`crate::jwk`]: -11
/// §11.5.1 requires it to carry a fully-specified `alg`.
#[derive(Deserialize)]
struct AgentCnf {
    jwk: crate::jwk::Jwk,
}

impl CallerAuth for AauthConfig {
    fn reads_body(&self) -> bool {
        true
    }

    fn authenticate(
        &self,
        req: &axum::extract::Request,
        now_secs: u64,
        body: &[u8],
    ) -> Result<Authenticated, Denied> {
        let fields = sig::SignatureFields::from_request(req)?;
        authenticate_with(
            &fields.request(req, body),
            req.headers(),
            self,
            now_secs as i64,
        )
    }

    /// Two refusals carry a header the draft defines; the rest state which check failed
    /// and offer no `WWW-Authenticate`, the same choice `sig.rs` makes and for the same
    /// reason: naming a scheme this deployment does not accept would invite a retry that
    /// cannot succeed. Draft -11 §6.1: a resource deciding on the agent's identity alone
    /// answers a request that presented no agent token with the one requirement it has,
    /// `AAuth-Requirement: requirement=agent-token`, with no parameters — and AAuth never
    /// conveys a requirement through `WWW-Authenticate`. §11.3.4 step 3 and §11.5.2: a
    /// signature `created`, or a token `iat`, ahead of this clock by more than the window is
    /// a signature failure answered `Signature-Error: error=clock_skew`.
    fn refuse(&self, denied: Denied) -> Response {
        let body = axum::Json(
            serde_json::json!({ "error": "invalid_request", "error_description": denied.detail() }),
        );
        let mut response = (denied.status(), body).into_response();
        match &denied {
            Denied::NoCredentials => {
                response.headers_mut().insert(
                    "aauth-requirement",
                    axum::http::HeaderValue::from_static("requirement=agent-token"),
                );
            }
            Denied::Invalid(detail)
                if detail == CLOCK_SKEW_DETAIL || detail == CREATED_AHEAD_DETAIL =>
            {
                response.headers_mut().insert(
                    "signature-error",
                    axum::http::HeaderValue::from_static("error=clock_skew"),
                );
            }
            _ => {}
        }
        response
    }
}

/// [`authenticate_with`] for a request whose signature covers no header field beyond
/// `signature-key` and `content-digest`.
#[cfg(test)]
pub(crate) fn authenticate(
    req: &sig::SignedRequest<'_>,
    cfg: &AauthConfig,
    now_secs: i64,
) -> Result<Authenticated, Denied> {
    authenticate_with(req, &HeaderMap::new(), cfg, now_secs)
}

/// Validate an AAuth agent token and the signature it is bound to, cheap self-asserted checks
/// ahead of the expensive ones. Nothing before the two signature checks is believed. `headers`
/// supplies any further header field the signature covers.
pub(crate) fn authenticate_with(
    req: &sig::SignedRequest<'_>,
    headers_in: &HeaderMap,
    cfg: &AauthConfig,
    now_secs: i64,
) -> Result<Authenticated, Denied> {
    if cfg.providers.is_empty() {
        return Err(Denied::Invalid("no agent providers are configured".into()));
    }
    let headers = req.signature_headers()?;

    // The audience an agent token does not carry. Checked before any cryptography: this is
    // what stops a request signed for one deployment from verifying at another that pins the
    // same provider. `@authority` is the authority the client sent, so it is only meaningful
    // once it has been compared with what this server is actually called.
    if !req.authority.eq_ignore_ascii_case(&cfg.authority) {
        return Err(Denied::Invalid(
            "request authority is not this deployment".into(),
        ));
    }

    // -11 §11.3.4 steps 2 and 3, and §11.3.4.2. The covered set must include the required
    // components, in any order and beside any others; this profile requires `content-digest`
    // on a bodied request too.
    let presented = crate::httpsig::presented_under(&PROFILE, headers.input, headers.signature)?;
    presented.covers(sig::required_components(req.method, req.body))?;
    if presented.created.saturating_sub(now_secs) > SIGNATURE_WINDOW_SECS {
        return Err(Denied::Invalid(CREATED_AHEAD_DETAIL.into()));
    }
    presented.fresh(now_secs, SIGNATURE_WINDOW_SECS, SIGNATURE_WINDOW_SECS)?;
    presented.unexpired(now_secs)?;

    let token = token_from_signature_key(headers.key, &presented.label)?;
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) if !s.is_empty() => (h, p, s),
        _ => return Err(Denied::Invalid("agent token is not a compact JWS".into())),
    };

    let head: BTreeMap<String, Value> =
        crate::jose::decode_json(h, "agent token header").map_err(Denied::Invalid)?;
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
        Some(a) if a == TOKEN_ALG => {}
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "algorithm {} is not accepted here; this deployment verifies {TOKEN_ALG} only",
                brief(other)
            )));
        }
        None => return Err(Denied::Invalid("agent token names no algorithm".into())),
    }
    let token_kid = head.get("kid").and_then(Value::as_str);

    let claims: BTreeMap<String, Value> =
        crate::jose::decode_json(p, "agent token claims").map_err(Denied::Invalid)?;

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
    // §5.2 gives an agent identifier the form `aauth:local@domain`, and §5.1 names the
    // provider in both that domain and the token's `iss`. A `sub` outside the issuing
    // provider's domain is refused, so one configured provider cannot mint another's agents,
    // nor an id an operator listed in `--pep` for another provider.
    let Some(domain) = agent_identifier_domain(&subject) else {
        return Err(Denied::Invalid(
            "sub is not an agent identifier (aauth:local@domain)".into(),
        ));
    };
    if Some(domain) != provider_host(issuer.as_str()) {
        return Err(Denied::Invalid(
            "agent identifier is not in the domain of the provider that issued the token".into(),
        ));
    }
    if claims
        .get("jti")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(Denied::Invalid("agent token carries no jti".into()));
    }
    let exp = crate::jose::numeric_date(&claims, "exp", "agent token")
        .map_err(Denied::Invalid)?
        .ok_or_else(|| Denied::Invalid("agent token carries no exp".into()))?;
    if now_secs as f64 >= exp {
        return Err(Denied::Invalid("agent token has expired".into()));
    }
    let iat = crate::jose::numeric_date(&claims, "iat", "agent token")
        .map_err(Denied::Invalid)?
        .ok_or_else(|| Denied::Invalid("agent token carries no iat".into()))?;
    // Draft -11 §11.5.2: `iat` is not a validity check. A verifier that refuses an `iat`
    // ahead of its clock bounds the refusal by its signature validity window rather than
    // demanding an exact clock, so the tolerance is the one the signature's `created` gets.
    if iat > (now_secs + SIGNATURE_WINDOW_SECS) as f64 {
        return Err(Denied::Invalid(CLOCK_SKEW_DETAIL.into()));
    }
    if exp - iat > MAX_AGENT_TOKEN_LIFETIME_SECS as f64 {
        return Err(Denied::Invalid(
            "agent token claims a lifetime above 24 hours".into(),
        ));
    }
    // The draft lists `exp` and `iat` among its required claims and does not name `nbf`, but
    // a JWT may carry registered claims beyond a profile's required set, and there an `nbf`
    // keeps its RFC 7519 meaning. A provider staging activation would otherwise have its
    // token honoured before the window it chose. Refused rather than skipped when malformed,
    // for the reason both sibling postures give: silently ignoring it admits a token that is
    // not yet valid.
    if let Some(nbf) =
        crate::jose::numeric_date(&claims, "nbf", "agent token").map_err(Denied::Invalid)?
        && (now_secs as f64) < nbf
    {
        return Err(Denied::Invalid("agent token is not yet valid".into()));
    }
    // Shape only: a server identifier, as §5.3.3 step 2 asks. A `ps` names a Person Server,
    // which this deployment does not consult: identity-based access applies local policy and
    // never asks a third party.
    if let Some(ps) = claims.get("ps").and_then(Value::as_str)
        && !valid_provider_url(ps)
    {
        return Err(Denied::Invalid(
            "ps is not a server identifier (https:// and a lowercase host)".into(),
        ));
    }
    // Shape only, deliberately: a valid agent identifier, as §5.3.3 step 3 asks. See the
    // module note: a caller's account of its own lineage is not a decision input.
    if let Some(parent) = claims.get("parent_agent")
        && parent
            .as_str()
            .is_none_or(|p| agent_identifier_domain(p).is_none())
    {
        return Err(Denied::Invalid(
            "parent_agent is not an agent identifier".into(),
        ));
    }

    // The confirmed key, and the second signature check: the request itself.
    let cnf: AgentCnf = serde_json::from_value(
        claims
            .get("cnf")
            .cloned()
            .ok_or_else(|| Denied::Invalid("agent token carries no cnf".into()))?,
    )
    .map_err(|_| Denied::Invalid("cnf does not carry a jwk".into()))?;
    let confirmed = cnf
        .jwk
        .ed25519()
        .map_err(|e| Denied::Invalid(format!("cnf.jwk is not usable: {e}")))?;

    // Every further header field the signature covers, as the request carries it.
    let mut extra: Vec<(&str, String)> = Vec::new();
    for name in &presented.components {
        if name.starts_with('@') || name == "signature-key" || name == "content-digest" {
            continue;
        }
        let value = crate::httpsig::field(headers_in, name)?.ok_or_else(|| {
            Denied::Invalid(format!(
                "covered field {} is not in the request",
                brief(name)
            ))
        })?;
        extra.push((name.as_str(), value));
    }
    let extra: Vec<(&str, &str)> = extra.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let base = req.signature_base_with(headers.key, &presented, &extra)?;
    let request_sig = Signature::from_slice(&presented.signature)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller::Bind;
    use decern_crypto::{Signer, SigningKey};
    use serde_json::json;

    const ISS: &str = "https://agent-provider.example";
    const AGENT: &str = "aauth:agent-1@agent-provider.example";
    const AUTHORITY: &str = "pdp.example";
    const PATH: &str = "/access/v1/evaluation";
    const KID: &str = "provider-key-1";
    const CREATED: i64 = 1_000;
    const NOW: i64 = 1_010;

    fn jwk(key: &VerifyingKey) -> Value {
        json!({ "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(key.to_bytes()) })
    }

    /// An agent token as a provider would mint it: signed by the provider's key over the
    /// header and claims, unlike `sig.rs`'s fixture whose signature segment is never read.
    fn agent_token(
        provider: &SigningKey,
        cnf_key: &VerifyingKey,
        head_patch: impl FnOnce(&mut Value),
        claims_patch: impl FnOnce(&mut Value),
    ) -> String {
        let mut header = json!({ "typ": AGENT_TOKEN_TYP, "alg": TOKEN_ALG, "kid": KID });
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

    /// The presentation -11 §11.3.3.1's example uses: label `sig`, scheme `jwt`.
    fn signature_key_header(token: &str) -> String {
        format!("sig=jwt;jwt=\"{token}\"")
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
        let (input, sig_value) =
            sign_components(agent, components, key_header, Some(&digest), created);
        (input, sig_value, digest)
    }

    /// `Signature-Input` and `Signature` for a POST covering `components`, the base written
    /// out line by line rather than built by the code under test.
    fn sign_components(
        agent: &SigningKey,
        components: &[&str],
        key_header: &str,
        digest: Option<&str>,
        created: i64,
    ) -> (String, String) {
        sign_as(
            agent,
            &Signing {
                method: "POST",
                components,
                key_header,
                digest,
                fields: &[],
                label: "sig",
                tail: &format!(";created={created}"),
            },
        )
    }

    /// What a test signs: the method, the covered components in order, the values of covered
    /// header fields beyond `signature-key` and `content-digest`, the label and the parameter
    /// tail as written.
    struct Signing<'a> {
        method: &'a str,
        components: &'a [&'a str],
        key_header: &'a str,
        digest: Option<&'a str>,
        fields: &'a [(&'a str, &'a str)],
        label: &'a str,
        tail: &'a str,
    }

    fn sign_as(agent: &SigningKey, s: &Signing<'_>) -> (String, String) {
        let lines: Vec<(&str, &str)> = s
            .components
            .iter()
            .map(|c| {
                let value = match *c {
                    "@method" => s.method,
                    "@authority" => AUTHORITY,
                    "@path" => PATH,
                    "content-digest" => s.digest.expect("fixture digest"),
                    "signature-key" => s.key_header,
                    other => s
                        .fields
                        .iter()
                        .find(|(n, _)| *n == other)
                        .map(|(_, v)| *v)
                        .unwrap_or_else(|| panic!("fixture component {other}")),
                };
                (*c, value)
            })
            .collect();
        crate::httpsig::sign_for_test_as(agent, &lines, s.label, s.tail)
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
        let (input, sig_value) = sign_components(&agent, &components, &key_header, None, CREATED);
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

    /// -11 §11.3.1 and §11.5.1: the token names the fully-specified `Ed25519`, and the
    /// polymorphic `EdDSA` a 0.6 agent sent is refused like any other algorithm.
    #[test]
    fn a_token_algorithm_other_than_ed25519_is_refused() {
        let (provider, agent) = keys();
        for alg in ["EdDSA", "RS256", "none"] {
            let f = fixture_with(&provider, &agent, |h| h["alg"] = json!(alg), |_| {});
            let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
                .expect_err("should refuse");
            assert!(
                matches!(err, Denied::Invalid(ref d) if d.contains("is not accepted here")),
                "{alg}: {err:?}"
            );
        }
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
            |c| c["iat"] = json!((NOW + 2 * SIGNATURE_WINDOW_SECS) as f64),
        );
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(
            matches!(err, Denied::Invalid(ref d) if d == CLOCK_SKEW_DETAIL),
            "{err:?}"
        );
    }

    /// Draft -11 §6.1: a resource that decides on the agent's identity alone tells an agent
    /// that presented no token what it needs, and only that — the header carries no
    /// parameters, and AAuth never conveys a requirement through `WWW-Authenticate`. A
    /// refused credential is a different thing from a missing one and gets no requirement.
    #[test]
    fn a_request_with_no_agent_token_is_told_the_requirement() {
        let (provider, _) = keys();
        let resp = cfg(&provider.verifying_key()).refuse(Denied::NoCredentials);
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get("aauth-requirement")
                .and_then(|v| v.to_str().ok()),
            Some("requirement=agent-token")
        );
        assert!(resp.headers().get("www-authenticate").is_none());

        let resp = cfg(&provider.verifying_key()).refuse(Denied::Invalid("not this".into()));
        assert!(resp.headers().get("aauth-requirement").is_none());
        assert!(resp.headers().get("signature-error").is_none());
    }

    /// Draft -11 §11.5.2: `iat` is not a validity check. An `iat` ahead of this clock by no
    /// more than the signature window is honoured; one beyond it is refused as the draft's
    /// `clock_skew`, signalled in `Signature-Error` so the agent can tell skew from a bad
    /// token.
    #[test]
    fn an_iat_ahead_of_the_clock_is_tolerated_within_the_signature_window() {
        let (provider, agent) = keys();
        let within = fixture_with(
            &provider,
            &agent,
            |_| {},
            |c| c["iat"] = json!((NOW + SIGNATURE_WINDOW_SECS) as f64),
        );
        assert!(
            authenticate(
                &req(&within, AUTHORITY),
                &cfg(&provider.verifying_key()),
                NOW
            )
            .is_ok()
        );

        let beyond = fixture_with(
            &provider,
            &agent,
            |_| {},
            |c| c["iat"] = json!((NOW + SIGNATURE_WINDOW_SECS + 1) as f64),
        );
        let err = authenticate(
            &req(&beyond, AUTHORITY),
            &cfg(&provider.verifying_key()),
            NOW,
        )
        .expect_err("should refuse");
        assert!(
            matches!(err, Denied::Invalid(ref d) if d == CLOCK_SKEW_DETAIL),
            "{err:?}"
        );
        let resp = cfg(&provider.verifying_key()).refuse(err);
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get("signature-error")
                .and_then(|v| v.to_str().ok()),
            Some("error=clock_skew")
        );
    }

    /// Draft -11 §5.3.1: an agent token SHOULD NOT outlive 24 hours. The draft leaves the
    /// bound to the verifier; this deployment refuses a token that claims more, and honours
    /// one that claims exactly a day.
    #[test]
    fn a_token_claiming_more_than_a_day_is_refused() {
        let (provider, agent) = keys();
        let long = fixture_with(
            &provider,
            &agent,
            |_| {},
            |c| {
                c["iat"] = json!((NOW - 100) as f64);
                c["exp"] = json!((NOW - 100 + MAX_AGENT_TOKEN_LIFETIME_SECS + 1) as f64);
            },
        );
        let err = authenticate(&req(&long, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(
            matches!(err, Denied::Invalid(ref d) if d.contains("24 hours")),
            "{err:?}"
        );

        let day = fixture_with(
            &provider,
            &agent,
            |_| {},
            |c| {
                c["iat"] = json!((NOW - 100) as f64);
                c["exp"] = json!((NOW - 100 + MAX_AGENT_TOKEN_LIFETIME_SECS) as f64);
            },
        );
        assert!(authenticate(&req(&day, AUTHORITY), &cfg(&provider.verifying_key()), NOW).is_ok());
    }

    #[test]
    fn a_token_that_is_not_yet_valid_is_refused() {
        let (provider, agent) = keys();
        let f = fixture_with(
            &provider,
            &agent,
            |_| {},
            |c| c["nbf"] = json!((NOW + 60) as f64),
        );
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("not yet valid")));
    }

    #[test]
    fn a_past_nbf_is_accepted() {
        let (provider, agent) = keys();
        let f = fixture_with(
            &provider,
            &agent,
            |_| {},
            |c| c["nbf"] = json!((NOW - 60) as f64),
        );
        authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect("a past nbf is valid");
    }

    /// Refused, not skipped: a malformed `nbf` that read as absent would admit a token its
    /// provider staged for later.
    #[test]
    fn a_non_numeric_nbf_is_refused_rather_than_ignored() {
        let (provider, agent) = keys();
        let f = fixture_with(&provider, &agent, |_| {}, |c| c["nbf"] = json!("soon"));
        let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("nbf is not a number")));
    }

    /// RFC 9421 §2.2.1: the method is case-sensitive and the base carries it as received. A
    /// signature over `POST` does not cover a request whose method is `post`.
    #[test]
    fn the_method_is_signed_as_received() {
        let (provider, agent) = keys();
        let f = post_fixture(&provider, &agent);
        authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
            .expect("signed as sent");
        let mut r = req(&f, AUTHORITY);
        r.method = "post";
        let err =
            authenticate(&r, &cfg(&provider.verifying_key()), NOW).expect_err("another method");
        assert!(
            matches!(err, Denied::Invalid(ref d) if d.contains("confirmed key")),
            "{err:?}"
        );
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

    fn provider_member(key: &VerifyingKey, patch: impl FnOnce(&mut Value)) -> Value {
        let mut m = jwk(key);
        m["kid"] = json!(KID);
        patch(&mut m);
        m
    }

    /// A key the token could not name by `kid` is not usable: skipped beside a usable one, and
    /// alone it leaves the set with nothing, which is refused at startup.
    #[test]
    fn a_key_without_a_kid_is_not_usable() {
        let (provider, other) = keys();
        let kidless = provider_member(&other.verifying_key(), |m| {
            m.as_object_mut().unwrap().remove("kid");
        });
        let e = load_provider_keys(&json!({ "keys": [kidless.clone()] }).to_string())
            .expect_err("nothing usable");
        assert!(e.contains("a kid"), "{e}");
        let usable = provider_member(&provider.verifying_key(), |_| {});
        let keys = load_provider_keys(&json!({ "keys": [kidless, usable] }).to_string())
            .expect("the usable one is kept");
        assert_eq!(keys.len(), 1);
    }

    /// sig-key §3.3: the rules bind the selected key, and an unusable member does not fail the
    /// set. A set with no usable key at all is refused at startup.
    #[test]
    fn a_provider_set_keeps_its_usable_keys_and_needs_one() {
        let (provider, other) = keys();
        let usable = provider_member(&provider.verifying_key(), |_| {});
        let unusable = [
            provider_member(&other.verifying_key(), |m| {
                m.as_object_mut().unwrap().remove("alg");
                m["kid"] = json!("no-alg");
            }),
            provider_member(&other.verifying_key(), |m| {
                m["alg"] = json!("EdDSA");
                m["kid"] = json!("polymorphic");
            }),
            provider_member(&other.verifying_key(), |m| {
                m["kty"] = json!("EC");
                m["kid"] = json!("inconsistent");
            }),
            json!({ "kty": "RSA", "alg": "RS256", "kid": "rsa", "n": "AQAB", "e": "AQAB" }),
            // Fields of the wrong JSON type: not a JWK of the shape read here, so skipped.
            json!({ "kty": "OKP", "crv": "Ed25519", "alg": 5, "kid": "typed" }),
            json!({ "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "kid": 7 }),
            json!("not an object"),
        ];
        let mut all = unusable.to_vec();
        all.push(usable);
        let keys = load_provider_keys(&json!({ "keys": all }).to_string()).expect("one usable");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, KID);
        assert!(load_provider_keys(&json!({ "keys": unusable }).to_string()).is_err());
        // A key for encryption is not a signing key, whatever else it names.
        let enc = provider_member(&provider.verifying_key(), |m| m["use"] = json!("enc"));
        assert!(load_provider_keys(&json!({ "keys": [enc] }).to_string()).is_err());
        // Two usable keys under one kid would make a token's kid ambiguous.
        let twin = provider_member(&other.verifying_key(), |_| {});
        let e = load_provider_keys(
            &json!({ "keys": [provider_member(&provider.verifying_key(), |_| {}), twin] })
                .to_string(),
        )
        .expect_err("a shared kid");
        assert!(e.contains("share the kid"), "{e}");
    }

    /// -11 §11.5.1: the key `cnf` confirms carries a fully-specified `alg` consistent with it.
    #[test]
    fn a_confirmation_key_the_rules_refuse_is_refused() {
        let (provider, agent) = keys();
        for patch in [
            (|c: &mut Value| {
                c["cnf"]["jwk"].as_object_mut().unwrap().remove("alg");
            }) as fn(&mut Value),
            |c| c["cnf"]["jwk"]["alg"] = json!("EdDSA"),
            |c| c["cnf"]["jwk"]["kty"] = json!("EC"),
        ] {
            let f = fixture_with(&provider, &agent, |_| {}, patch);
            let err = authenticate(&req(&f, AUTHORITY), &cfg(&provider.verifying_key()), NOW)
                .expect_err("should refuse");
            assert!(
                matches!(err, Denied::Invalid(ref d) if d.contains("cnf.jwk is not usable")),
                "{err:?}"
            );
        }
    }

    /// -11 §11.3.3.1's example: a GET under label `sig`, covering a header field beyond the
    /// required four. Without that header the covered field cannot be resolved.
    #[test]
    fn a_request_shaped_as_the_drafts_example_authenticates() {
        let (provider, agent) = keys();
        let token = agent_token(&provider, &agent.verifying_key(), |_| {}, |_| {});
        let key_header = signature_key_header(&token);
        let auth = "AAuth session-token-placeholder";
        let (input, sig) = sign_as(
            &agent,
            &Signing {
                method: "GET",
                components: &[
                    "@method",
                    "@authority",
                    "@path",
                    "authorization",
                    "signature-key",
                ],
                key_header: &key_header,
                digest: None,
                fields: &[("authorization", auth)],
                label: "sig",
                tail: &format!(";created={CREATED}"),
            },
        );
        let r = sig::SignedRequest {
            method: "GET",
            authority: AUTHORITY,
            path: PATH,
            signature_key_header: Some(&key_header),
            signature_input_header: Some(&input),
            signature_header: Some(&sig),
            content_digest_header: None,
            body: b"",
        };
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth.parse().unwrap());
        let who = authenticate_with(&r, &headers, &cfg(&provider.verifying_key()), NOW)
            .expect("the draft's shape authenticates");
        assert_eq!(who.subject, AGENT);
        let err = authenticate_with(&r, &HeaderMap::new(), &cfg(&provider.verifying_key()), NOW)
            .expect_err("a covered field must be in the request");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("authorization")));
    }

    /// -11 §11.3.4 step 2 asks that the required components be covered, not in an order and
    /// not alone: a POST covering them reordered, with `content-type` beside them, verifies.
    #[test]
    fn the_covered_components_may_be_reordered_and_extended() {
        let (provider, agent) = keys();
        let body = br#"{"subject":{"type":"Principal","id":"corp"}}"#.to_vec();
        let token = agent_token(&provider, &agent.verifying_key(), |_| {}, |_| {});
        let key_header = signature_key_header(&token);
        let digest = sig::content_digest_header_value(&body);
        let (input, sig) = sign_as(
            &agent,
            &Signing {
                method: "POST",
                components: &[
                    "signature-key",
                    "content-type",
                    "@path",
                    "content-digest",
                    "@authority",
                    "@method",
                ],
                key_header: &key_header,
                digest: Some(&digest),
                fields: &[("content-type", "application/json")],
                label: "sig",
                tail: &format!(";created={CREATED}"),
            },
        );
        let f = Fixture {
            key_header,
            input,
            sig,
            digest,
            body,
        };
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        authenticate_with(
            &req(&f, AUTHORITY),
            &headers,
            &cfg(&provider.verifying_key()),
            NOW,
        )
        .expect("reordered and extended");
    }

    /// -11 §11.3.4 step 4 selects the `Signature-Key` member by the signature's label, so the
    /// label the agent chose must name a member there; members under other labels are
    /// ignored (sig-key §3.1); `Signature-Input` and `Signature` must agree on the label.
    #[test]
    fn the_token_is_selected_by_the_signatures_label() {
        let (provider, agent) = keys();
        let token = agent_token(&provider, &agent.verifying_key(), |_| {}, |_| {});
        let body = br#"{"subject":{"type":"Principal","id":"corp"}}"#.to_vec();
        let c = cfg(&provider.verifying_key());
        let run = |key_header: String, label: &str, sig_label: &str| {
            let (input, sig, digest) = {
                let digest = sig::content_digest_header_value(&body);
                let (input, sig) = sign_as(
                    &agent,
                    &Signing {
                        method: "POST",
                        components: sig::required_components("POST", &body),
                        key_header: &key_header,
                        digest: Some(&digest),
                        fields: &[],
                        label,
                        tail: &format!(";created={CREATED}"),
                    },
                );
                (input, sig.replacen(label, sig_label, 1), digest)
            };
            let f = Fixture {
                key_header,
                input,
                sig,
                digest,
                body: body.clone(),
            };
            authenticate(&req(&f, AUTHORITY), &c, NOW)
        };
        run(format!("sig=jwt;jwt=\"{token}\""), "sig", "sig").expect("sig everywhere");
        run(format!("agent=jwt;jwt=\"{token}\""), "agent", "agent").expect("any one label");
        run(
            format!("sig=jwt;jwt=\"{token}\", other=hwk;kty=\"OKP\""),
            "sig",
            "sig",
        )
        .expect("another member is ignored");
        run(
            format!("sig=jwt;jwt=\"{token}\", other=hwk, other=hwk"),
            "sig",
            "sig",
        )
        .expect("a repeat under another label is folded, as RFC 9651 says");
        // A second jwt member would let the label choose the agent recorded.
        let err = run(
            format!("sig=jwt;jwt=\"{token}\", other=jwt;jwt=\"{token}\""),
            "sig",
            "sig",
        )
        .expect_err("two jwt members");
        assert!(
            matches!(err, Denied::Invalid(ref d) if d.contains("more than one jwt-scheme member"))
        );
        // RFC 9651 §4.2.2 and §4.2.3.2: a repeated key, and a repeated parameter, keep the last.
        run(
            format!("sig=jwt;jwt=\"x\", sig=jwt;jwt=\"{token}\""),
            "sig",
            "sig",
        )
        .expect("the verified label given twice keeps the last");
        run(format!("sig=jwt;jwt=\"x\";jwt=\"{token}\""), "sig", "sig")
            .expect("a repeated jwt parameter keeps the last");
        let err =
            run("sig=jwt;jwt=abc".to_owned(), "sig", "sig").expect_err("a token, not a string");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("not a string")));
        let err = run(format!("other=jwt;jwt=\"{token}\""), "sig", "sig")
            .expect_err("no member under the label");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("no member labelled sig")));
        let err = run(format!("sig=jwt;jwt=\"{token}\""), "sig", "sig2")
            .expect_err("the two signature headers disagree");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("different labels")));
    }

    /// -11 §11.3.3.2: an `alg` parameter is ignored, the key naming the algorithm.
    /// §11.3.4.2: `expires` in the past is refused, and one still ahead is honoured.
    #[test]
    fn an_alg_parameter_is_ignored_and_expires_is_honoured() {
        let (provider, agent) = keys();
        let c = cfg(&provider.verifying_key());
        let run = |tail: String| {
            let body = br#"{"subject":{"type":"Principal","id":"corp"}}"#.to_vec();
            let token = agent_token(&provider, &agent.verifying_key(), |_| {}, |_| {});
            let key_header = signature_key_header(&token);
            let digest = sig::content_digest_header_value(&body);
            let (input, sig) = sign_as(
                &agent,
                &Signing {
                    method: "POST",
                    components: sig::required_components("POST", &body),
                    key_header: &key_header,
                    digest: Some(&digest),
                    fields: &[],
                    label: "sig",
                    tail: &tail,
                },
            );
            let f = Fixture {
                key_header,
                input,
                sig,
                digest,
                body,
            };
            authenticate(&req(&f, AUTHORITY), &c, NOW)
        };
        run(format!(";created={CREATED};alg=\"ed25519\"")).expect("alg ignored");
        run(format!(";created={CREATED};alg=1")).expect("alg not read, whatever its type");
        let err = run(format!(";created={CREATED};nonce=\"n\"")).expect_err("nonce refused");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("nonce")));
        run(format!(";created={CREATED};expires={}", NOW + 30)).expect("expires ahead");
        let err = run(format!(";created={CREATED};expires={}", NOW - 1)).expect_err("expired");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("expired")));
    }

    /// -11 §11.3.4 step 3: `created` within 60 seconds of this clock either way; further
    /// ahead is `clock_skew`, further behind a stale signature.
    #[test]
    fn created_is_held_to_a_sixty_second_window_both_ways() {
        let (provider, agent) = keys();
        let c = cfg(&provider.verifying_key());
        let body = br#"{"subject":{"type":"Principal","id":"corp"}}"#.to_vec();
        let at = |created: i64| {
            let token = agent_token(&provider, &agent.verifying_key(), |_| {}, |_| {});
            let key_header = signature_key_header(&token);
            let (input, sig, digest) = sign_post(&agent, &key_header, &body, created);
            let f = Fixture {
                key_header,
                input,
                sig,
                digest,
                body: body.clone(),
            };
            authenticate(&req(&f, AUTHORITY), &c, NOW)
        };
        at(NOW + SIGNATURE_WINDOW_SECS).expect("60 s ahead");
        at(NOW - SIGNATURE_WINDOW_SECS).expect("60 s behind");
        let ahead = at(NOW + SIGNATURE_WINDOW_SECS + 1).expect_err("61 s ahead");
        assert!(matches!(ahead, Denied::Invalid(ref d) if d == CREATED_AHEAD_DETAIL));
        assert_eq!(
            c.refuse(ahead)
                .headers()
                .get("signature-error")
                .and_then(|v| v.to_str().ok()),
            Some("error=clock_skew")
        );
        let behind = at(NOW - SIGNATURE_WINDOW_SECS - 1).expect_err("61 s behind");
        assert!(matches!(behind, Denied::Invalid(ref d) if d.contains("freshness")));
    }

    /// §5.2 gives an agent identifier the form `aauth:local@domain`, and §5.1 names the
    /// provider in both that domain and the token's `iss`. A `sub` anywhere else is refused,
    /// so a configured provider cannot mint another provider's agents, nor a `--pep` id meant
    /// for one of them. `parent_agent`, when present, has to be an agent identifier too.
    #[test]
    fn an_agent_outside_its_providers_domain_is_refused() {
        let (provider, agent) = keys();
        let mut c = cfg(&provider.verifying_key());
        c.pep
            .insert("aauth:gateway@other-provider.example".to_owned());
        for sub in [
            "aauth:gateway@other-provider.example",
            "aauth:agent-1@other-provider.example",
            "https://agent-provider.example/agents/agent-1",
            "agent-1",
        ] {
            let f = fixture_with(&provider, &agent, |_| {}, |cl| cl["sub"] = json!(sub));
            let err = authenticate(&req(&f, AUTHORITY), &c, NOW)
                .expect_err("a sub outside the provider's domain should be refused");
            assert!(
                matches!(err, Denied::Invalid(ref d) if d.contains("agent identifier")),
                "{sub} was refused for another reason"
            );
        }
        let f = fixture_with(
            &provider,
            &agent,
            |_| {},
            |cl| {
                cl["parent_agent"] = json!("planner");
            },
        );
        let err = authenticate(&req(&f, AUTHORITY), &c, NOW).expect_err("should refuse");
        assert!(matches!(err, Denied::Invalid(ref d) if d.contains("parent_agent")));
        let f = fixture_with(
            &provider,
            &agent,
            |_| {},
            |cl| {
                cl["parent_agent"] = json!("aauth:planner@agent-provider.example");
            },
        );
        authenticate(&req(&f, AUTHORITY), &c, NOW).expect("a sub-agent of the same provider");
    }

    /// §5.3.3 step 2: a `ps` claim, when present, is a server identifier, `https://` and a
    /// lowercase host alone.
    #[test]
    fn a_ps_claim_is_checked_as_a_server_identifier() {
        let (provider, agent) = keys();
        let c = cfg(&provider.verifying_key());
        let f = fixture_with(
            &provider,
            &agent,
            |_| {},
            |cl| {
                cl["ps"] = json!("https://ps.example");
            },
        );
        authenticate(&req(&f, AUTHORITY), &c, NOW).expect("a host alone is a server identifier");
        for ps in [
            "https://ps.example/path",
            "https://ps.example/",
            "https://PS.example",
            "http://ps.example",
            "https://ps.example:8443",
        ] {
            let f = fixture_with(&provider, &agent, |_| {}, |cl| cl["ps"] = json!(ps));
            let err = authenticate(&req(&f, AUTHORITY), &c, NOW).expect_err("should refuse");
            assert!(
                matches!(err, Denied::Invalid(ref d) if d.contains("ps is not a server identifier")),
                "{ps} was refused for another reason"
            );
        }
    }

    /// §11.1.1's own valid and invalid examples, plus the whitespace case kept from before.
    #[test]
    fn a_provider_identifier_is_https_and_a_lowercase_host_alone() {
        for ok in ["https://agent.example", "https://xn--nxasmq6b.example"] {
            assert_eq!(provider_host(ok), Some(&ok["https://".len()..]), "{ok}");
        }
        for bad in [
            "http://agent.example",
            "https://Agent.Example",
            "https://agent.example:8443",
            "https://agent.example/v1",
            "https://agent.example/",
            "https://agent .example",
            "https://",
            "provider.example",
        ] {
            assert!(!valid_provider_url(bad), "{bad} was accepted");
        }
    }

    /// §5.2's own valid and invalid examples. The local part's `+` is not read (§5.2 keeps
    /// it for readability and makes `parent_agent` the marker), so a sub-agent id parses.
    #[test]
    fn an_agent_identifier_is_local_at_domain() {
        for (ok, domain) in [
            ("aauth:assistant-v2@agent.example", "agent.example"),
            ("aauth:planner.7f3c@vendor.example", "vendor.example"),
            (
                "aauth:planner.7f3c+search1@vendor.example",
                "vendor.example",
            ),
        ] {
            assert_eq!(agent_identifier_domain(ok), Some(domain), "{ok}");
        }
        let long = format!("aauth:{}@agent.example", "a".repeat(256));
        for bad in [
            "My Agent@agent.example",
            "aauth:My Agent@agent.example",
            "@agent.example",
            "aauth:@agent.example",
            "agent@http://agent.example",
            "aauth:agent@http://agent.example",
            "aauth:agent@Agent.Example",
            "aauth:agent@agent.example:8443",
            "https://agent-provider.example/agents/agent-1",
            long.as_str(),
        ] {
            assert!(agent_identifier_domain(bad).is_none(), "{bad} was accepted");
        }
    }
}
