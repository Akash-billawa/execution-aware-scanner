//! Findings API endpoints

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;

use super::models::*;

/// GET /api/v1/findings
pub async fn list_findings(
    State(state): State<crate::AppState>,
    Query(filter): Query<FindingsFilter>,
) -> impl IntoResponse {
    let store = state.finding_store.read().await;
    let all_findings = store.get_all();

    let filtered: Vec<_> = all_findings
        .iter()
        .filter(|f| {
            if let Some(ref priority) = filter.priority {
                if f.priority.to_lowercase() != priority.to_lowercase() {
                    return false;
                }
            }
            if let Some(ref namespace) = filter.namespace {
                if f.namespace != *namespace {
                    return false;
                }
            }
            if let Some(ref workload) = filter.workload {
                if f.workload != *workload {
                    return false;
                }
            }
            if let Some(ref cve) = filter.cve {
                if !f.cve.contains(cve.as_str()) {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = filtered.len();
    let offset = filter.pagination.offset();
    let limit = filter.pagination.limit();
    let page = filter.pagination.page.unwrap_or(1);
    let per_page = filter.pagination.per_page.unwrap_or(50).min(200);

    let data: Vec<_> = filtered
        .into_iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect();

    Json(PaginatedResponse {
        data,
        total,
        page,
        per_page,
    })
}

/// GET /api/v1/findings/:id
pub async fn get_finding(
    State(state): State<crate::AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let store = state.finding_store.read().await;
    match store.get(&id) {
        Some(finding) => (StatusCode::OK, Json(serde_json::json!(finding))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "not_found",
                format!("Finding {id} not found"),
            )),
        )
            .into_response(),
    }
}

/// POST /api/v1/findings/:id/acknowledge
pub async fn acknowledge_finding(
    State(state): State<crate::AppState>,
    Path(id): Path<String>,
    Json(req): Json<AcknowledgeRequest>,
) -> impl IntoResponse {
    let mut store = state.finding_store.write().await;
    match store.acknowledge(&id, req.reason) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "acknowledged",
                "finding_id": id,
                "timestamp": Utc::now().to_rfc3339(),
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("not_found", e)),
        )
            .into_response(),
    }
}

/// GET /api/v1/findings/stats
pub async fn findings_stats(State(state): State<crate::AppState>) -> impl IntoResponse {
    let store = state.finding_store.read().await;
    let stats = store.stats();
    Json(serde_json::json!({
        "total": stats.total,
        "by_priority": {
            "critical": stats.critical,
            "high": stats.high,
            "medium": stats.medium,
            "low": stats.low,
            "informational": stats.informational,
        },
        "acknowledged": stats.acknowledged,
        "unacknowledged": stats.total - stats.acknowledged,
    }))
}
