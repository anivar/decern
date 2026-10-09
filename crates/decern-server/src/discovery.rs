// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! AuthZEN 1.0 PDP metadata (§9): where this decision point is, for a PEP that discovers it.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// AuthZEN 1.0 PDP metadata, `GET /.well-known/authzen-configuration`. Only what this
/// deployment serves is advertised: the decision point, its evaluation endpoint and its
/// evaluations endpoint. The search endpoints exist in the specification and not here, so
/// they are not named. Without `--public-url` there is nothing true to advertise, and the
/// document is 404 rather than a guess assembled from a `Host` header the caller controls.
pub(crate) async fn authzen_configuration(State(st): State<crate::AppState>) -> Response {
    match st.public_url.as_deref() {
        Some(base) => (
            StatusCode::OK,
            Json(json!({
                "policy_decision_point": base,
                "access_evaluation_endpoint": format!("{base}/access/v1/evaluation"),
                "access_evaluations_endpoint": format!("{base}/access/v1/evaluations"),
            })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_configured",
                "detail": "this deployment has no --public-url to advertise",
            })),
        )
            .into_response(),
    }
}
