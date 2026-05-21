//! Policies API endpoints

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;

use super::models::*;

/// GET /api/v1/policies
pub async fn list_policies(State(state): State<crate::AppState>) -> impl IntoResponse {
    let engine = state.policy_engine.read().await;
    let policies = engine.list_policies();
    Json(serde_json::json!({
        "policies": policies,
        "total": policies.len(),
    }))
}

/// GET /api/v1/policies/:id
pub async fn get_policy(
    State(state): State<crate::AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let engine = state.policy_engine.read().await;
    match engine.get_policy(&id) {
        Some(policy) => (StatusCode::OK, Json(serde_json::json!(policy))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "not_found",
                format!("Policy {id} not found"),
            )),
        )
            .into_response(),
    }
}

/// POST /api/v1/policies/reload
pub async fn reload_policies(State(state): State<crate::AppState>) -> impl IntoResponse {
    let mut engine = state.policy_engine.write().await;
    let result = engine.reload();
    Json(serde_json::json!({
        "reloaded": result.reloaded,
        "errors": result.errors,
        "timestamp": Utc::now().to_rfc3339(),
    }))
}
