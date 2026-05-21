//! Scans API endpoints

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;

use super::models::*;

/// POST /api/v1/scans
pub async fn trigger_scan(
    State(state): State<crate::AppState>,
    Json(req): Json<TriggerScanRequest>,
) -> impl IntoResponse {
    match state.scan_trigger.send(req).await {
        Ok(()) => {
            let scan_id = uuid::Uuid::new_v4().to_string();
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "scan_id": scan_id,
                    "status": "queued",
                    "started_at": Utc::now().to_rfc3339(),
                })),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse::new(
                "unavailable",
                "Scan trigger channel closed",
            )),
        )
            .into_response(),
    }
}

/// GET /api/v1/stats
pub async fn system_stats(State(_state): State<crate::AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": Utc::now().to_rfc3339(),
        "metrics_endpoint": "/metrics",
        "health_endpoint": "/health",
        "ready_endpoint": "/ready",
        "api_version": "v1",
    }))
}
