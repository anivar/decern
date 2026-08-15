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
