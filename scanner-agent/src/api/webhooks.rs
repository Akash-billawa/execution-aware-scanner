//! Webhooks API endpoints

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;

use super::models::*;

/// GET /api/v1/webhooks
pub async fn list_webhooks() -> impl IntoResponse {
    Json(serde_json::json!({
        "webhooks": [],
        "total": 0,
        "note": "Webhook management is configured via CLI flags and config files. Full CRUD API coming in future release."
    }))
}

/// POST /api/v1/webhooks
pub async fn create_webhook(Json(_req): Json<CreateWebhookRequest>) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse::new(
            "not_implemented",
            "Webhook creation via API is not yet supported. Use config files or CLI flags.",
        )),
    )
}

/// DELETE /api/v1/webhooks/:id
pub async fn delete_webhook() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse::new(
            "not_implemented",
            "Webhook deletion via API is not yet supported. Use config files or CLI flags.",
        )),
    )
}
