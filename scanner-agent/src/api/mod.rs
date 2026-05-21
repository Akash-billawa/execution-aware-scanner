//! REST API for the execution-aware scanner
//!
//! Provides CRUD endpoints for findings, policies, webhooks, and scans.
//! All endpoints are under /api/v1/.

pub mod findings;
pub mod models;
pub mod policies;
pub mod scans;
pub mod webhooks;

use axum::{
    routing::{delete, get, post},
    Router,
};

/// Build the API router with all v1 endpoints
/// This returns a Router<()> that can be merged with the main app router
pub fn routes(state: crate::AppState) -> Router<crate::AppState> {
    let slack_routes = Router::new()
        .route(
            "/commands",
            post(crate::slack_commands::handle_slack_command),
        )
        .route(
            "/actions",
            post(crate::slack_commands::handle_slack_interaction),
        );

    Router::new()
        .route("/api/v1/findings", get(findings::list_findings))
        .route("/api/v1/findings/stats", get(findings::findings_stats))
        .route("/api/v1/findings/{id}", get(findings::get_finding))
        .route(
            "/api/v1/findings/{id}/acknowledge",
            post(findings::acknowledge_finding),
        )
        .route("/api/v1/policies", get(policies::list_policies))
        .route("/api/v1/policies/reload", post(policies::reload_policies))
        .route("/api/v1/policies/{id}", get(policies::get_policy))
        .route(
            "/api/v1/webhooks",
            get(webhooks::list_webhooks).post(webhooks::create_webhook),
        )
        .route("/api/v1/webhooks/{id}", delete(webhooks::delete_webhook))
        .route("/api/v1/scans", post(scans::trigger_scan))
        .route("/api/v1/stats", get(scans::system_stats))
        .nest("/api/v1/slack", slack_routes)
}
