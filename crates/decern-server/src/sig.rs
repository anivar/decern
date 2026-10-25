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
//! bearer token is replayable against any request until it expires. A leaked signed
//! request cannot be replayed against a *different* request: `@method`, `@authority`
//! and `@path` are always covered, and a POST also covers `content-digest` (RFC 9530)
//! of the body bytes the handler will see — so swapping the JSON at the same path
//! is a different request, and the captured signature does not verify. Verbatim
//! replay of the exact same captured signature (same path, same body) is not
//! separately prevented here (no nonce/`jti` cache): it verifies again within
//! [`MAX_SIGNATURE_AGE_SECS`], the same as it did the first time. What shrinks is the
//! window, from a token's full lifetime to one signature's freshness period, not the
//! possibility of replaying that one request.
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
//! Verification only, over a fixed, small profile of RFC 9421 applied through
//! [`crate::httpsig`]: exactly one signature, labelled `sig1`, covering exactly the
//! components named below, `ed25519` only, and `sha-256` only for `Content-Digest`. A
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
use sha2::{Digest, Sha256};

use crate::caller::{Authenticated, CallerAuth, Denied, printable};

/// Covered components for a request with no body that is an input (GET, HEAD).
const UNBODIED_COMPONENTS: [&str; 4] = ["@method", "@authority", "@path", "signature-key"];

/// Covered components for POST. `content-digest` sits with the request-target
/// components, before `signature-key`, so the body is part of "this request"
/// rather than an afterthought on the credential.
const BODIED_COMPONENTS: [&str; 5] = [
    "@method",
    "@authority",
    "@path",
    "content-digest",
    "signature-key",
];

/// How long after `created` a signature is still accepted. Mint-to-arrival latency plus
/// clock skew, not a session length — a signature is proof for one request, not a grant
/// that outlives it.
pub(crate) const MAX_SIGNATURE_AGE_SECS: i64 = 60;

/// How far ahead of this server's clock a signer's `created` may be and still be
/// accepted. Independent clocks drift in both directions, not just late — a signer a
/// few seconds ahead of this server is an ordinary NTP-grade skew, not an attack, and
/// refusing it here would be an operational failure with a security-shaped symptom.
pub(crate) const MAX_CLOCK_SKEW_AHEAD_SECS: i64 = 5;

/// A compact JWS three parts of which each fit in an HTTP header has no business being
/// larger. Mirrors `bearer.rs`'s own token size ceiling.
const MAX_TOKEN_BYTES: usize = 8192;

pub(crate) struct SigConfig {
    /// Agent identifier -> the keys it may sign with. More than one during a rollover: the
    /// new key is added while the old one still verifies, as `--bearer-issuer-key` accepts
    /// more than one key rather than requiring an atomic swap.
    pub(crate) agents: BTreeMap<String, Vec<VerifyingKey>>,
    /// This deployment's resource identifier, which the token's `aud` must contain —
    /// same role as [`crate::bearer::Config::audience`].
    pub(crate) audience: String,
    /// This deployment's authority, which the signed `@authority` must equal. The audience
    /// names a resource and can be shared; the signature covers the host the request was
    /// sent to, and only this comparison stops a request signed for one deployment from
    /// verifying at another that trusts the same agent key and audience.
    pub(crate) authority: String,
    /// Agent identifiers that remain PEPs under this posture: they may name principals
    /// other than themselves. Empty by default — a signed-request agent is a workload.
    pub(crate) pep: std::collections::BTreeSet<String>,
}

impl SigConfig {
    pub(crate) fn new(
        agents: BTreeMap<String, Vec<VerifyingKey>>,
        audience: impl Into<String>,
        authority: impl Into<String>,
    ) -> Self {
        Self {
            agents,
            audience: audience.into(),
            authority: authority.into(),
            pep: std::collections::BTreeSet::new(),
        }
    }
}

/// What a verified signed request says about its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Signed {
    /// The configured agent identifier the token's `sub` named and whose key verified
    /// the signature.
    pub(crate) agent: String,
}

/// Which components this request must cover.
///
/// Driven by the body as well as the method, deliberately. Keying on `POST` alone would
/// mean a guarded `PUT` or `PATCH` added later fell into the bodiless branch and stopped
/// covering its body — silently, and that is precisely the defect this component list
/// exists to close. Anything carrying bytes covers them; `POST` covers them even when
/// empty, so an empty-bodied POST cannot be downgraded to the shorter list either.
pub(crate) fn required_components(method: &str, body: &[u8]) -> &'static [&'static str] {
    if method.eq_ignore_ascii_case("POST") || !body.is_empty() {
        &BODIED_COMPONENTS
    } else {
        &UNBODIED_COMPONENTS
    }
}

/// RFC 9530 `Content-Digest` with exactly one member, `sha-256`, as an RFC 8941
/// byte sequence (`sha-256=:base64:`). Anything else — a second algorithm, a
/// different hash, extra dictionary members — is refused rather than ignored.
fn parse_sha256_content_digest(raw: &str) -> Result<[u8; 32], Denied> {
    let rest = raw
        .trim()
        .strip_prefix("sha-256=:")
        .and_then(|s| s.strip_suffix(':'))
        .ok_or_else(|| Denied::Invalid("Content-Digest is not sha-256=:…: (RFC 9530)".into()))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(rest)
        .map_err(|_| Denied::Invalid("Content-Digest is not valid base64".into()))?;
    bytes
        .try_into()
        .map_err(|_| Denied::Invalid("Content-Digest sha-256 value is not 32 bytes".into()))
}

fn sha256_of(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

/// RFC 9530 dictionary value for a `sha-256` digest of `body`. Test-only: the server
/// verifies a digest it was sent and never produces one.
#[cfg(test)]
pub(crate) fn content_digest_header_value(body: &[u8]) -> String {
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(sha256_of(body))
    )
}

#[derive(Deserialize)]
struct Header {
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    alg: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Cnf {
    pub(crate) jwk: JwkEd25519,
}

/// The one JWK shape this deployment accepts: an OKP Ed25519 public key (RFC 8037).
#[derive(Deserialize)]
pub(crate) struct JwkEd25519 {
    kty: String,
    crv: String,
    x: String,
}

pub(crate) fn jwk_to_verifying_key(jwk: &JwkEd25519) -> Result<VerifyingKey, Denied> {
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
    fn reads_body(&self) -> bool {
        true
    }

    /// The credential is spread across the request line and the signature headers,
    /// and for POST the body via `Content-Digest`. Unlike bearer, those are covered
    /// components of the signature, not incidental context.
    fn authenticate(
        &self,
        req: &axum::extract::Request,
        now_secs: u64,
        body: &[u8],
    ) -> Result<Authenticated, Denied> {
        let fields = SignatureFields::from_request(req)?;
        let signed = authenticate(&fields.request(req, body), self, now_secs as i64)?;
        // A signed request names one agent, which is both the party and the client
        // acting for it — there is no separate delegating client to distinguish — and no
        // issuer this server verified.
        let who = Authenticated::without_issuer(signed.agent.clone(), signed.agent.clone());
        Ok(if self.pep.contains(&signed.agent) {
            who
        } else {
            who.self_only()
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

/// The header fields a signature posture reads, each combined across its lines
/// ([`crate::httpsig::field`]), and the authority, owned so a [`SignedRequest`] can
/// borrow them. Shared with the AAuth posture, which reads the same fields. A field that
/// is not visible ASCII refuses the request here, where it once read as absent: a malformed
/// value is not the same thing as no value.
pub(crate) struct SignatureFields {
    authority: String,
    signature_key: Option<String>,
    signature_input: Option<String>,
    signature: Option<String>,
    content_digest: Option<String>,
}

impl SignatureFields {
    pub(crate) fn from_request(req: &axum::extract::Request) -> Result<Self, Denied> {
        let headers = req.headers();
        Ok(Self {
            authority: crate::httpsig::authority(req.uri(), headers)?,
            signature_key: crate::httpsig::field(headers, "signature-key")?,
            signature_input: crate::httpsig::field(headers, "signature-input")?,
            signature: crate::httpsig::field(headers, "signature")?,
            content_digest: crate::httpsig::field(headers, "content-digest")?,
        })
    }

    pub(crate) fn request<'a>(
        &'a self,
        req: &'a axum::extract::Request,
        body: &'a [u8],
    ) -> SignedRequest<'a> {
        SignedRequest {
            method: req.method().as_str(),
            authority: &self.authority,
            path: req.uri().path(),
            signature_key_header: self.signature_key.as_deref(),
            signature_input_header: self.signature_input.as_deref(),
            signature_header: self.signature.as_deref(),
            content_digest_header: self.content_digest.as_deref(),
            body,
        }
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
    pub(crate) content_digest_header: Option<&'a str>,
    pub(crate) body: &'a [u8],
}

impl<'a> SignedRequest<'a> {
    /// Whether this request was sent to `authority`, the deployment's own. `@authority` is the
    /// host the client sent to, so a signature over it binds the request to this deployment
    /// only once the two are compared. Both signature postures call this before any key is
    /// consulted; a host compares without case.
    pub(crate) fn sent_to(&self, authority: &str) -> Result<(), Denied> {
        if self.authority.eq_ignore_ascii_case(authority) {
            Ok(())
        } else {
            Err(Denied::Invalid(
                "request authority is not this deployment".into(),
            ))
        }
    }

    /// `Signature-Key`, `Signature-Input` and `Signature`, each present and within the size
    /// either posture allows. No `Signature-Key` is no credential at all, which a posture
    /// answers with its own challenge; the others missing, or any oversized, is a bad one.
    pub(crate) fn signature_headers(&self) -> Result<SignatureHeaders<'a>, Denied> {
        let key = self.signature_key_header.ok_or(Denied::NoCredentials)?;
        let input = self
            .signature_input_header
            .ok_or_else(|| Denied::Invalid("request carries no Signature-Input".into()))?;
        let signature = self
            .signature_header
            .ok_or_else(|| Denied::Invalid("request carries no Signature".into()))?;
        if key.len() > MAX_TOKEN_BYTES
            || input.len() > MAX_TOKEN_BYTES
            || signature.len() > MAX_TOKEN_BYTES
        {
            return Err(Denied::Invalid(
                "signature material exceeds the accepted size".into(),
            ));
        }
        Ok(SignatureHeaders {
            key,
            input,
            signature,
        })
    }

    /// The one signature this request carries, held to the signed-request profile: label
    /// `sig1`, exactly the covered components for this method and body, and `created` inside
    /// the freshness window. Parsing only; no key is consulted yet.
    pub(crate) fn presented(
        &self,
        headers: &SignatureHeaders<'_>,
        now_secs: i64,
    ) -> Result<crate::httpsig::Presented, Denied> {
        let presented = crate::httpsig::presented(LABEL, headers.input, headers.signature)?;
        presented.covers_exactly(required_components(self.method, self.body))?;
        presented.fresh(now_secs, MAX_SIGNATURE_AGE_SECS, MAX_CLOCK_SKEW_AHEAD_SECS)?;
        Ok(presented)
    }

    /// The signature base over the fields a signature posture lets a request cover: the
    /// request line, `Signature-Key`, and `Content-Digest`. Call it after
    /// [`Self::presented`] has held the covered components to the profile: whether
    /// `Content-Digest` is bound is read from them. A covered `Content-Digest` is bound to
    /// the body first, so a POST whose body does not match its digest is refused without
    /// running Ed25519.
    pub(crate) fn signature_base(
        &self,
        signature_key: &str,
        presented: &crate::httpsig::Presented,
    ) -> Result<String, Denied> {
        self.signature_base_with(signature_key, presented, &[])
    }

    /// As [`Self::signature_base`], with the further covered header fields a profile lets a
    /// request cover, each read with [`crate::httpsig::field`].
    pub(crate) fn signature_base_with(
        &self,
        signature_key: &str,
        presented: &crate::httpsig::Presented,
        extra: &[(&str, &str)],
    ) -> Result<String, Denied> {
        let authority = self.authority.to_ascii_lowercase();
        let mut fields = vec![("signature-key", signature_key)];
        if presented.components.iter().any(|c| c == "content-digest") {
            fields.push(("content-digest", self.bound_content_digest()?));
        }
        fields.extend_from_slice(extra);
        let msg = crate::httpsig::Message {
            method: self.method,
            authority: &authority,
            path: self.path,
            fields: &fields,
        };
        crate::httpsig::signature_base(&msg, presented)
    }

    /// `Content-Digest`, present, `sha-256` only, and equal to the hash of the body bytes the
    /// handler will see. Only a covered digest is bound: a stray one on a GET is not checked
    /// against anything. Like every field a signature posture reads, it must still be visible
    /// ASCII: [`SignatureFields::from_request`] refuses one that is not, rather than reading
    /// it as absent.
    fn bound_content_digest(&self) -> Result<&'a str, Denied> {
        let raw = self
            .content_digest_header
            .ok_or_else(|| Denied::Invalid("request carries no Content-Digest".into()))?;
        if raw.len() > MAX_TOKEN_BYTES {
            return Err(Denied::Invalid(
                "Content-Digest exceeds the accepted size".into(),
            ));
        }
        let claimed = parse_sha256_content_digest(raw)?;
        if claimed != sha256_of(self.body) {
            return Err(Denied::Invalid(
                "Content-Digest does not match the request body".into(),
            ));
        }
        Ok(raw)
    }
}

/// The three signature headers a request carries, from [`SignedRequest::signature_headers`].
pub(crate) struct SignatureHeaders<'a> {
    pub(crate) key: &'a str,
    pub(crate) input: &'a str,
    pub(crate) signature: &'a str,
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
    let headers = req.signature_headers()?;
    req.sent_to(&cfg.authority)?;
    // `Signature-Key` conveys the bearer token this signature is over; this deployment
    // accepts the token itself, verbatim. No separate size check here: trimming can only
    // shrink it, and the header is already bounded above.
    let token = headers.key.trim();
    let presented = req.presented(&headers, now_secs)?;

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
    let header: Header = crate::jose::decode_json(h, "token header").map_err(Denied::Invalid)?;
    match header.typ.as_deref() {
        Some(t) if t.eq_ignore_ascii_case("dpop-bound+jwt") => {}
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "bound token type {} is not a signature-bound access token",
                printable(other)
            )));
        }
        None => return Err(Denied::Invalid("bound token names no type".into())),
    }
    match header.alg.as_deref() {
        Some("EdDSA") => {}
        Some(other) => {
            return Err(Denied::Invalid(format!(
                "bound token algorithm {} is not accepted here",
                printable(other)
            )));
        }
        None => return Err(Denied::Invalid("bound token names no algorithm".into())),
    }

    let claims: BTreeMap<String, Value> =
        crate::jose::decode_json(p, "token claims").map_err(Denied::Invalid)?;
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| Denied::Invalid("bound token carries no sub".into()))?
        .to_owned();
    // Required by this profile, and still not recorded: nothing here verifies who issued the
    // token, so its `iss` is the caller's own claim.
    claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| Denied::Invalid("bound token carries no iss".into()))?;

    if !crate::jose::audience_contains(claims.get("aud"), &cfg.audience) {
        return Err(Denied::Invalid(
            "bound token was not issued for this server as audience".into(),
        ));
    }

    // The claimed identity must be one this deployment already governs. This is what
    // "configured, not discovered" means: a `sub` decern has no key for is
    // refused here, before any cryptography runs on its behalf.
    let configured_keys = cfg.agents.get(&subject).ok_or_else(|| {
        Denied::Invalid(format!(
            "agent {} is not configured here",
            printable(&subject)
        ))
    })?;

    // The token must bind, via `cnf.jwk`, to a key configured for that agent — a token
    // claiming `sub=agent-1` but confirming some other key would let a caller name an
    // identity without holding what it takes to prove it. The key it confirms is the one
    // the signature is checked against below.
    let cnf: Cnf = claims
        .get("cnf")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| Denied::Invalid("bound token cnf is malformed".into()))?
        .ok_or_else(|| Denied::Invalid("bound token carries no cnf".into()))?;
    let token_key = jwk_to_verifying_key(&cnf.jwk)?;
    let configured_key = configured_keys
        .iter()
        .find(|k| **k == token_key)
        .ok_or_else(|| {
            Denied::Invalid(
                "bound token cnf.jwk does not match a configured key for this agent".into(),
            )
        })?;

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

    let base = req.signature_base(headers.key, &presented)?;

    // Finally, the expensive check: does the signature over this exact request verify
    // against the key this deployment already knows for the claimed identity. Every
    // check above is cheap and self-asserted; this is the one that actually proves
    // possession, so it runs last, over a key this function chose, never one the
    // request supplied for its own verification.
    let sig_arr: [u8; 64] = presented
        .signature
        .as_slice()
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

    Ok(Signed { agent: subject })
}

/// The one label the signed-request posture accepts. RFC 9421 §4 has the signer choose the
/// label, and §7.2.5 advises an application not to rely on a specific one, since an
/// intermediary may relabel; this profile departs from that, so a relabelled signature is
/// refused. The AAuth posture takes the signer's label instead. [`crate::httpsig::presented`] refuses a request carrying more than one
/// signature; the fixed label is what lets that check name the member it reads.
pub(crate) const LABEL: &str = "sig1";

#[cfg(test)]
mod tests {
    use super::*;
    use decern_crypto::SigningKey;
    use serde_json::json;

    const AGENT: &str = "agent-1";
    const ISS: &str = "https://agent-provider.example/";
    const AUD: &str = "https://pdp.example/access/v1/evaluation";
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
        agents.insert(AGENT.to_owned(), vec![*key]);
        SigConfig::new(agents, AUD, AUTHORITY)
    }

    /// Signed GET headers. GET has no body that is an input, so `content-digest` is not
    /// covered and `body` is empty.
    fn sign_get(
        signing_key: &SigningKey,
        token: &str,
        components: &[&str],
        created: i64,
    ) -> (String, String, String) {
        let (key, input, sig, _) = sign_at(signing_key, "GET", token, components, created, b"");
        (key, input, sig)
    }

    /// Signed POST headers, including `Content-Digest` of `body`.
    fn sign_post(
        signing_key: &SigningKey,
        token: &str,
        components: &[&str],
        created: i64,
        body: &[u8],
    ) -> (String, String, String, String) {
        sign_at(signing_key, "POST", token, components, created, body)
    }

    fn sign_at(
        signing_key: &SigningKey,
        method: &str,
        token: &str,
        components: &[&str],
        created: i64,
        body: &[u8],
    ) -> (String, String, String, String) {
        let digest = content_digest_header_value(body);
        let lines: Vec<(&str, &str)> = components
            .iter()
            .map(|c| {
                let value = match *c {
                    "@method" => method,
                    "@authority" => AUTHORITY,
                    "@path" => PATH,
                    "content-digest" => digest.as_str(),
                    "signature-key" => token,
                    other => panic!("test fixture component {other}"),
                };
                (*c, value)
            })
            .collect();
        let (input_value, sig_value) = crate::httpsig::sign_for_test(signing_key, &lines, created);
        (token.to_owned(), input_value, sig_value, digest)
    }

    fn get_req<'a>(
        signature_key_header: &'a str,
        signature_input_header: &'a str,
        signature_header: &'a str,
    ) -> SignedRequest<'a> {
        SignedRequest {
            method: "GET",
            authority: AUTHORITY,
            path: PATH,
            signature_key_header: Some(signature_key_header),
            signature_input_header: Some(signature_input_header),
            signature_header: Some(signature_header),
            content_digest_header: None,
            body: b"",
        }
    }

    fn post_req<'a>(
        signature_key_header: &'a str,
        signature_input_header: &'a str,
        signature_header: &'a str,
        content_digest_header: &'a str,
        body: &'a [u8],
    ) -> SignedRequest<'a> {
        SignedRequest {
            method: "POST",
            authority: AUTHORITY,
            path: PATH,
            signature_key_header: Some(signature_key_header),
            signature_input_header: Some(signature_input_header),
            signature_header: Some(signature_header),
            content_digest_header: Some(content_digest_header),
            body,
        }
    }

    /// The component list is chosen from the body as well as the method, so a
    /// body-carrying method nobody thought to name still covers what it carries. Keying
    /// on POST alone would let a guarded PUT added later stop covering its body — the
    /// same defect this list exists to close, recurring quietly.
    #[test]
    fn any_request_carrying_bytes_covers_them() {
        assert_eq!(required_components("POST", b""), BODIED_COMPONENTS);
        assert_eq!(required_components("POST", b"{}"), BODIED_COMPONENTS);
        assert_eq!(required_components("PUT", b"{}"), BODIED_COMPONENTS);
        assert_eq!(required_components("PATCH", b"{}"), BODIED_COMPONENTS);
        assert_eq!(required_components("GET", b""), UNBODIED_COMPONENTS);
        // A GET that somehow arrives with bytes covers them rather than ignoring them.
        assert_eq!(required_components("GET", b"x"), BODIED_COMPONENTS);
    }

    #[test]
    fn a_well_formed_signed_request_authenticates_its_caller() {
        let k = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |_| {});
        let (key_h, input_h, sig_h) = sign_get(&k, &token, &UNBODIED_COMPONENTS, CREATED);
        let who = authenticate(
            &get_req(&key_h, &input_h, &sig_h),
            &cfg(&k.verifying_key()),
            NOW,
        )
        .unwrap();
        assert_eq!(who.agent, AGENT);
    }

    /// The token's `iss` is the agent's own claim: nothing verifies it against an issuer
    /// key. So the caller a signed request establishes, and the record of what it asked,
    /// name no issuer.
    #[test]
    fn a_signed_caller_names_no_issuer() {
        let k = decern_crypto::generate().unwrap();
        let req = get_request(PATH, &signed_get_headers(&k, &[]));
        let who = CallerAuth::authenticate(&cfg(&k.verifying_key()), &req, NOW as u64, b"")
            .expect("a well-formed signed request");
        assert_eq!(who.subject, AGENT);
        assert_eq!(who.issuer, None);
    }

    /// A request signed for another deployment's authority is refused before any key is
    /// consulted, though the same agent key and audience would verify it: the signature
    /// covers where the request was sent, and that is compared with this deployment.
    #[test]
    fn a_request_signed_for_another_authority_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let req = get_request(PATH, &signed_get_headers(&k, &[]));
        let mut elsewhere = cfg(&k.verifying_key());
        elsewhere.authority = "other.example".into();
        let e = CallerAuth::authenticate(&elsewhere, &req, NOW as u64, b"").unwrap_err();
        assert_eq!(e.detail(), "request authority is not this deployment");
        let mut cased = cfg(&k.verifying_key());
        cased.authority = AUTHORITY.to_ascii_uppercase();
        CallerAuth::authenticate(&cased, &req, NOW as u64, b"")
            .expect("an authority compares without case, as a host name does");
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
        let (key_h, input_h, sig_h) = sign_get(&attacker, &token, &UNBODIED_COMPONENTS, CREATED);
        let e = authenticate(
            &get_req(&key_h, &input_h, &sig_h),
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
        let (key_h, input_h, sig_h) = sign_get(&k, &token, &UNBODIED_COMPONENTS, stale_created);
        let e = authenticate(
            &get_req(&key_h, &input_h, &sig_h),
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
        let (key_h, input_h, sig_h) = sign_get(&k, &token, &UNBODIED_COMPONENTS, ahead_created);
        authenticate(
            &get_req(&key_h, &input_h, &sig_h),
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
        let (key_h, input_h, sig_h) = sign_get(&k, &token, &UNBODIED_COMPONENTS, too_far_ahead);
        let e = authenticate(
            &get_req(&key_h, &input_h, &sig_h),
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
        let (key_h, input_h, sig_h) = sign_get(&k, &token, &short_components, CREATED);
        let e = authenticate(
            &get_req(&key_h, &input_h, &sig_h),
            &cfg(&k.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(e.detail().contains("required components"), "{}", e.detail());
    }

    /// A caller must already exist in this deployment's configuration before any
    /// cryptography runs on its behalf, which is what "configured, not discovered" means.
    #[test]
    fn an_unconfigured_agent_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let other = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |c| {
            c["sub"] = json!("someone-else");
        });
        let (key_h, input_h, sig_h) = sign_get(&k, &token, &UNBODIED_COMPONENTS, CREATED);
        // `other`'s key is what's configured here, under a different agent id — proving
        // this is refused for the identity lookup, not merely because the wrong key
        // happened to verify.
        let e = authenticate(
            &get_req(&key_h, &input_h, &sig_h),
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
        let (key_h, input_h, sig_h) = sign_get(&k, &token, &UNBODIED_COMPONENTS, CREATED);
        let e = authenticate(
            &get_req(&key_h, &input_h, &sig_h),
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
        let (key_h, input_h, sig_h) = sign_get(&configured, &token, &UNBODIED_COMPONENTS, CREATED);
        let e = authenticate(
            &get_req(&key_h, &input_h, &sig_h),
            &cfg(&configured.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(e.detail().contains("does not match"), "{}", e.detail());
    }

    /// A rollover adds the new key while the old one still verifies, so an agent re-keyed
    /// mid-flight is not refused until the old key is dropped from the configuration. A key
    /// configured for nobody is refused as before.
    #[test]
    fn an_agent_with_two_configured_keys_signs_with_either() {
        let old = decern_crypto::generate().unwrap();
        let new = decern_crypto::generate().unwrap();
        let stranger = decern_crypto::generate().unwrap();
        let mut agents = BTreeMap::new();
        agents.insert(
            AGENT.to_owned(),
            vec![old.verifying_key(), new.verifying_key()],
        );
        let cfg = SigConfig::new(agents, AUD, AUTHORITY);
        for k in [&old, &new] {
            let token = bound_token(&k.verifying_key(), |_| {});
            let (key_h, input_h, sig_h) = sign_get(k, &token, &UNBODIED_COMPONENTS, CREATED);
            let who = authenticate(&get_req(&key_h, &input_h, &sig_h), &cfg, NOW).unwrap();
            assert_eq!(who.agent, AGENT);
        }
        // The signature is checked under the key the token confirms, not under any key the
        // agent holds: a token bound to the new key but signed with the old one is refused.
        let token = bound_token(&new.verifying_key(), |_| {});
        let (key_h, input_h, sig_h) = sign_get(&old, &token, &UNBODIED_COMPONENTS, CREATED);
        let e = authenticate(&get_req(&key_h, &input_h, &sig_h), &cfg, NOW).unwrap_err();
        assert!(e.detail().contains("does not verify"), "{}", e.detail());
        let token = bound_token(&stranger.verifying_key(), |_| {});
        let (key_h, input_h, sig_h) = sign_get(&stranger, &token, &UNBODIED_COMPONENTS, CREATED);
        let e = authenticate(&get_req(&key_h, &input_h, &sig_h), &cfg, NOW).unwrap_err();
        assert!(e.detail().contains("does not match"), "{}", e.detail());
    }

    #[test]
    fn a_post_with_matching_content_digest_authenticates() {
        let k = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |_| {});
        let body = br#"{"subject":{"id":"corp"},"action":{"name":"Read"}}"#;
        let (key_h, input_h, sig_h, digest) =
            sign_post(&k, &token, &BODIED_COMPONENTS, CREATED, body);
        authenticate(
            &post_req(&key_h, &input_h, &sig_h, &digest, body),
            &cfg(&k.verifying_key()),
            NOW,
        )
        .expect("a POST whose digest matches its body must authenticate");
    }

    /// The exploit: a captured signature over one POST body must not authorize a
    /// different body at the same path. Before `content-digest` was covered, this
    /// authenticated — the signature contributed nothing, and only the Mission
    /// gate happened to stop MoveMoney. There is no such backstop on
    /// `/mission/v1/approve`.
    #[test]
    fn a_captured_signature_cannot_authorize_a_different_body() {
        let k = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |_| {});
        let read = br#"{"action":{"name":"Read"}}"#;
        let move_money = br#"{"action":{"name":"MoveMoney"}}"#;
        let (key_h, input_h, sig_h, digest) =
            sign_post(&k, &token, &BODIED_COMPONENTS, CREATED, read);
        let e = authenticate(
            &post_req(&key_h, &input_h, &sig_h, &digest, move_money),
            &cfg(&k.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(
            e.detail().contains("does not match the request body"),
            "{}",
            e.detail()
        );
    }

    /// Every signature header is bounded before it is parsed, `Signature` with the others:
    /// parsing a long dictionary costs work before any key is consulted.
    #[test]
    fn an_oversized_signature_header_is_refused_before_it_is_parsed() {
        let k = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |_| {});
        let (key_h, input_h, _sig_h) = sign_get(&k, &token, &UNBODIED_COMPONENTS, CREATED);
        let huge = format!("sig1=:{}:", "A".repeat(MAX_TOKEN_BYTES));
        let e = authenticate(
            &get_req(&key_h, &input_h, &huge),
            &cfg(&k.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(
            e.detail().contains("exceeds the accepted size"),
            "{}",
            e.detail()
        );
    }

    #[test]
    fn a_post_without_content_digest_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let token = bound_token(&k.verifying_key(), |_| {});
        let (key_h, input_h, sig_h) = sign_get(&k, &token, &UNBODIED_COMPONENTS, CREATED);
        let e = authenticate(
            &SignedRequest {
                method: "POST",
                authority: AUTHORITY,
                path: PATH,
                signature_key_header: Some(&key_h),
                signature_input_header: Some(&input_h),
                signature_header: Some(&sig_h),
                content_digest_header: None,
                body: b"{}",
            },
            &cfg(&k.verifying_key()),
            NOW,
        )
        .unwrap_err();
        assert!(e.detail().contains("required components"), "{}", e.detail());
    }

    /// A GET as the guard receives it, so the fields are read the way a live request's are.
    fn get_request(
        uri: &str,
        headers: &[(&str, axum::http::HeaderValue)],
    ) -> axum::extract::Request {
        let mut req = axum::http::Request::builder().method("GET").uri(uri);
        for (name, value) in headers {
            req = req.header(*name, value.clone());
        }
        req.body(axum::body::Body::empty()).unwrap()
    }

    /// The headers of a GET `agent-1` signed, with `extra` lines appended.
    fn signed_get_headers(
        k: &SigningKey,
        extra: &[(&'static str, axum::http::HeaderValue)],
    ) -> Vec<(&'static str, axum::http::HeaderValue)> {
        let token = bound_token(&k.verifying_key(), |_| {});
        let (key_h, input_h, sig_h) = sign_get(k, &token, &UNBODIED_COMPONENTS, CREATED);
        let mut headers = vec![
            ("host", AUTHORITY.parse().unwrap()),
            ("signature-key", key_h.parse().unwrap()),
            ("signature-input", input_h.parse().unwrap()),
            ("signature", sig_h.parse().unwrap()),
        ];
        headers.extend_from_slice(extra);
        headers
    }

    fn authenticate_live(k: &SigningKey, req: &axum::extract::Request) -> Result<Signed, Denied> {
        let fields = SignatureFields::from_request(req)?;
        authenticate(&fields.request(req, b""), &cfg(&k.verifying_key()), NOW)
    }

    /// RFC 9421 §2.1: every line of a field is read. A second `Signature-Input` line, which
    /// reading the first line alone never saw, makes this two signatures and is refused.
    #[test]
    fn a_second_signature_input_line_is_read() {
        let k = decern_crypto::generate().unwrap();
        let req = get_request(PATH, &signed_get_headers(&k, &[]));
        authenticate_live(&k, &req).expect("one line each");

        let second = (
            "signature-input",
            r#"sig2=("@method");created=1000"#.parse().unwrap(),
        );
        let req = get_request(PATH, &signed_get_headers(&k, &[second]));
        let e = authenticate_live(&k, &req).unwrap_err();
        assert!(
            e.detail().contains("exactly one signature"),
            "{}",
            e.detail()
        );
    }

    /// A field that is not visible ASCII is malformed, not absent: a stray `Content-Digest`
    /// on a GET is not checked against the body, and is still refused when it cannot be read.
    #[test]
    fn a_field_that_is_not_visible_ascii_is_refused() {
        let k = decern_crypto::generate().unwrap();
        let stray = (
            "content-digest",
            axum::http::HeaderValue::from_bytes(b"sha-256=:\xff:").unwrap(),
        );
        let req = get_request(PATH, &signed_get_headers(&k, &[stray]));
        let e = authenticate_live(&k, &req).unwrap_err();
        assert!(e.detail().contains("not visible ASCII"), "{}", e.detail());
    }

    /// An absolute-form target carries the authority the signer covered; a `Host` that
    /// disagrees with it is not what `@authority` is read from.
    #[test]
    fn an_absolute_form_target_supplies_the_authority() {
        let k = decern_crypto::generate().unwrap();
        let mut headers = signed_get_headers(&k, &[]);
        headers[0].1 = "elsewhere.example".parse().unwrap();
        let req = get_request(&format!("http://{AUTHORITY}{PATH}"), &headers);
        authenticate_live(&k, &req).expect("signed over the target's authority");
    }
}
