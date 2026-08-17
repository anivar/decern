// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! How the caller is established, and the one layer that establishes it.
//!
//! Each posture verifies something different — a bearer token, a signature over the
//! request, or nothing at all because something in front already did it — but they answer
//! the same question and owe the same two things: an [`Authenticated`] identity, or a
//! refusal that names its own scheme. [`CallerAuth`] is that shared obligation, so
//! [`guard`] can dispatch without knowing which posture it holds, and a posture added
//! later cannot quietly skip a step by being wired in slightly differently.
//!
//! What lives here is only what more than one posture needs. The RFC 9068 rules stay in
//! [`crate::bearer`] and the RFC 9421 rules stay in [`crate::sig`]; neither has to know
//! the other exists.
//!
//! Every posture verifies against keys configured at startup. None of them fetch, so
//! [`CallerAuth::authenticate`] is deliberately synchronous: establishing a caller must
//! not be able to wait on a third party, and a signature that cannot `.await` cannot
//! grow that dependency by accident.
//!
//! Establishing the caller is not the same as admitting the name the request speaks as.
//! Bearer and `--trust-proxy` authenticate a PEP, which legitimately asks about other
//! parties. A signed-request agent is a workload: unless it is named in `--pep`, it may
//! only name itself as AuthZEN `subject`, mission `approver`, or directory principal.
//! That check lives in the handlers, not here — the guard does not parse bodies.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// How the caller is established. Chosen explicitly at startup: a server that cannot say who
/// is asking should say so in its configuration rather than discover it in an audit.
pub(crate) enum Caller {
    /// A token is required, verified, and bound to this server as audience.
    Bearer(Box<crate::bearer::Config>),
    /// A signature over the request itself is required, verified against a configured
    /// per-agent key, and the bound token verified and bound to this server as audience.
    Signed(Box<crate::sig::SigConfig>),
    /// A SPIFFE JWT-SVID is required, verified against a trust bundle configured for the
    /// trust domain its `sub` names. See [`crate::spiffe`].
    Spiffe(Box<crate::spiffe::SpiffeConfig>),
    /// An AAuth agent token is required, verified against the keys pinned for the agent
    /// provider its `iss` names, and the request signature verified against the key that
    /// token's `cnf` confirms. See [`crate::aauth`].
    Aauth(Box<crate::aauth::AauthConfig>),
    /// Something in front has already authenticated the caller. Named rather than defaulted,
    /// because "no token configured" and "authentication deliberately delegated" look identical
    /// from inside the process and mean very different things outside it.
    TrustedProxy,
}

/// How large a request body this layer will buffer in order to verify it. Axum's own
/// default limit is the same size; capping here too means a signed POST cannot spend
/// unbounded memory on a digest the handler would have refused anyway.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// What one posture must be able to do. Both methods are synchronous by design — see the
/// module note on why establishing a caller must never wait on the network.
pub(crate) trait CallerAuth: Sync {
    /// Establish the caller from the request and the body bytes already buffered for
    /// it, or say why not. The body is passed in rather than read here so a signature
    /// over `content-digest` can be checked against the same bytes the handler will
    /// see, without this trait growing an `.await`.
    fn authenticate(
        &self,
        req: &axum::extract::Request,
        now_secs: u64,
        body: &[u8],
    ) -> Result<Authenticated, Denied>;

    /// This posture's refusal. Separate from [`Denied`] itself because the challenge a
    /// refusal should carry is a property of the scheme, not of the reason: a bearer
    /// refusal owes an RFC 6750 `WWW-Authenticate`, and a signature refusal has no
    /// equivalent header to offer.
    fn refuse(&self, denied: Denied) -> Response;
}

/// Why a request was refused, shaped by OAuth 2.1 §5.3 (draft-ietf-oauth-v2-1-15):
/// no credentials and bad credentials are both 401 but carry different challenges, and a
/// valid credential missing a required scope is 403.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Denied {
    /// Nothing was presented. RFC 6750 §3: the challenge then carries no error code —
    /// there is nothing wrong with a credential that was never presented.
    NoCredentials,
    /// A credential that cannot be trusted. 401.
    Invalid(String),
    /// A verified credential that does not carry a scope this deployment requires. 403,
    /// and the challenge names the scopes so the client knows what to ask its issuer for.
    InsufficientScope(String),
}

impl Denied {
    pub(crate) fn detail(&self) -> &str {
        match self {
            Denied::NoCredentials => "no credentials presented",
            Denied::Invalid(d) | Denied::InsufficientScope(d) => d,
        }
    }

    /// 403 only for a scope refusal; everything else is 401. Shared because this split is
    /// the OAuth rule, not a per-posture choice.
    pub(crate) fn status(&self) -> axum::http::StatusCode {
        match self {
            Denied::InsufficientScope(_) => axum::http::StatusCode::FORBIDDEN,
            _ => axum::http::StatusCode::UNAUTHORIZED,
        }
    }
}

/// What a verified credential says about its holder: the party, the client acting for it,
/// and the issuer whose signature was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Authenticated {
    pub(crate) subject: String,
    pub(crate) client_id: String,
    pub(crate) issuer: String,
    /// Whether this caller may name principals other than itself. Set by the posture
    /// that established it, so a handler cannot pick the wrong default by omission.
    pub(crate) bind: Bind,
}

/// How tightly a verified caller is bound to the principals a request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bind {
    /// A PEP: may ask about, approve as, and inspect any principal.
    Any,
    /// A workload: may only name itself.
    SelfOnly,
}

impl Authenticated {
    /// A PEP caller. Handler tests that inject an identity without going through a
    /// posture use this, matching bearer and `--trust-proxy`.
    pub(crate) fn new(
        subject: impl Into<String>,
        client_id: impl Into<String>,
        issuer: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            client_id: client_id.into(),
            issuer: issuer.into(),
            bind: Bind::Any,
        }
    }

    /// Restrict this caller to naming itself. Signed-request agents that are not
    /// in `--pep` are this shape.
    pub(crate) fn self_only(mut self) -> Self {
        self.bind = Bind::SelfOnly;
        self
    }

    fn admits(&self, named: &str) -> bool {
        match self.bind {
            Bind::Any => true,
            Bind::SelfOnly => self.subject == named,
        }
    }
}

/// How much of an attacker-chosen principal id may be echoed in a 403. Enough to
/// recognise a mismatch; not enough to use the error channel as a reflector.
const MAX_ECHO: usize = 64;

fn brief(s: &str) -> String {
    // Bounded by characters, never by bytes. `&t[..MAX_ECHO]` panics when the cut lands
    // inside a multi-byte character, and the string being cut here is an attacker-chosen
    // principal id — so a byte bound turns this refusal into a downed request. Control
    // characters are dropped as well: the value lands in a JSON body, which escapes them,
    // but an id is not a place they belong.
    let t = s.trim();
    let kept: Vec<char> = t.chars().filter(|c| !c.is_control()).collect();
    let mut out: String = kept.iter().take(MAX_ECHO).collect();
    if kept.len() > MAX_ECHO {
        out.push('…');
    }
    out
}

/// Refuse a principal this caller is not allowed to speak as. No extension means
/// `--trust-proxy`: the operator said the front is the PEP, and there is no verified
/// identity here to compare.
///
/// 403, not 401: the credential was accepted. The name in the request is not theirs.
/// A distinct error from `insufficient_scope`, which is about what the token carries,
/// not about who it is.
pub(crate) fn refuse_unless_admits(
    caller: &Option<axum::Extension<Authenticated>>,
    named: &str,
) -> Option<Response> {
    match caller {
        None => None,
        Some(axum::Extension(who)) if who.admits(named) => None,
        Some(axum::Extension(who)) => Some(
            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "caller_mismatch",
                    "detail": format!(
                        "caller {} cannot name principal {}",
                        brief(&who.subject),
                        brief(named)
                    ),
                })),
            )
                .into_response(),
        ),
    }
}

/// The layer over the protected routes.
///
/// Applied as a layer rather than a handler argument. The check is the same for every
/// protected route, and a route that needs it should not be able to acquire it by
/// omission — which is how the mission mutations would otherwise quietly ship open.
///
/// Under [`Caller::TrustedProxy`] this passes everything through: the operator has said the
/// caller is established in front of this process, and re-checking here would only invent a
/// second, weaker answer. Under every other posture nothing reaches a handler unverified,
/// and the verified identity rides the request so the record can say who asserted it.
pub(crate) async fn guard(
    axum::extract::State(caller): axum::extract::State<std::sync::Arc<Caller>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if matches!(caller.as_ref(), Caller::TrustedProxy) {
        return next.run(req).await;
    }

    // Buffer once, restore onto the request, and hand the same bytes to authenticate.
    // A signed POST covers `content-digest` of these bytes; reading the body again
    // inside the verifier would either consume it out from under the handler or
    // hash a different copy. Bearer ignores the slice.
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({ "error": "payload too large" })),
            )
                .into_response();
        }
    };
    let mut req = axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes.clone()));

    // The borrow of `caller` is confined to this block and released before any `.await`.
    // Holding a reference across the suspension point is what previously failed axum's
    // `Service` bounds here, and scoping it is cheaper than proving it safe each time a
    // posture is added.
    let established = {
        let posture: &dyn CallerAuth = match caller.as_ref() {
            Caller::TrustedProxy => unreachable!("trusted-proxy returned above"),
            Caller::Bearer(cfg) => cfg.as_ref(),
            Caller::Signed(cfg) => cfg.as_ref(),
            Caller::Spiffe(cfg) => cfg.as_ref(),
            Caller::Aauth(cfg) => cfg.as_ref(),
        };
        posture
            .authenticate(&req, now_secs(), &bytes)
            .map_err(|denied| posture.refuse(denied))
    };
    match established {
        Ok(who) => {
            req.extensions_mut().insert(who);
            next.run(req).await
        }
        Err(refusal) => refusal,
    }
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused principal id is attacker-chosen, and it is echoed back through
    /// `brief`. Truncating it by byte index panics when the cut lands inside a
    /// multi-byte character, which turns a 403 into a downed request — so the
    /// echo must be bounded by characters, not bytes.
    #[test]
    fn a_refused_multibyte_principal_id_does_not_panic() {
        // 22 x 3 bytes = 66: over the echo bound, and byte 64 is mid-character.
        let hostile = "\u{3042}".repeat(22);
        assert!(hostile.len() > MAX_ECHO && !hostile.is_char_boundary(MAX_ECHO));
        let who = axum::Extension(Authenticated::new("agent-1", "agent-1", "iss").self_only());
        assert!(refuse_unless_admits(&Some(who), &hostile).is_some());
    }

    #[test]
    fn a_pep_admits_any_principal() {
        let who = Authenticated::new("gateway-1", "gw", "https://issuer.example/");
        assert!(refuse_unless_admits(&Some(axum::Extension(who.clone())), "corp").is_none());
        assert!(refuse_unless_admits(&Some(axum::Extension(who)), "anyone").is_none());
    }

    #[test]
    fn a_self_only_caller_admits_only_itself() {
        let who = Authenticated::new("agent-1", "agent-1", "https://issuer.example/").self_only();
        assert!(refuse_unless_admits(&Some(axum::Extension(who.clone())), "agent-1").is_none());
        let refusal = refuse_unless_admits(&Some(axum::Extension(who)), "corp").unwrap();
        assert_eq!(refusal.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn a_trusted_proxy_has_no_caller_to_bind() {
        assert!(refuse_unless_admits(&None, "corp").is_none());
    }
}
