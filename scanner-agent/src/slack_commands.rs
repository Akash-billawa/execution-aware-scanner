//! Slack Slash Commands and Interactive Messages
//!
//! Handles incoming Slack slash commands and interactive message callbacks.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Form, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::state::FindingStore;

/// Slack slash command payload
#[derive(Debug, Deserialize)]
pub struct SlackCommand {
    pub token: String,
    pub team_id: String,
    pub team_domain: String,
    pub channel_id: String,
    pub channel_name: String,
    pub user_id: String,
    pub user_name: String,
    pub command: String,
    pub text: String,
    pub response_url: String,
    pub trigger_id: String,
}

/// Slack interactive message payload
#[derive(Debug, Deserialize)]
pub struct SlackInteraction {
    #[serde(rename = "type")]
    pub interaction_type: String,
    pub user: SlackUser,
    pub trigger_id: String,
    pub response_url: String,
    pub actions: Vec<SlackAction>,
}

#[derive(Debug, Deserialize)]
pub struct SlackUser {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct SlackAction {
    pub action_id: String,
    pub value: String,
}

/// Slack response types
#[derive(Debug, Serialize)]
struct SlackResponse {
    response_type: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocks: Option<Vec<serde_json::Value>>,
}

/// Handle Slack slash command
pub async fn handle_slack_command(
    State(state): State<crate::AppState>,
    Form(cmd): Form<SlackCommand>,
) -> impl IntoResponse {
    let finding_store = state.finding_store.clone();

    let response = match cmd.command.as_str() {
        "/scanner" => handle_scanner_command(&cmd.text, &finding_store).await,
        _ => SlackResponse {
            response_type: "ephemeral".to_string(),
            text: format!("Unknown command: {}", cmd.command),
            blocks: None,
        },
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(&response).unwrap()),
    )
}

/// Handle /scanner subcommands
async fn handle_scanner_command(
    text: &str,
    finding_store: &Arc<RwLock<FindingStore>>,
) -> SlackResponse {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let subcommand = parts.first().copied().unwrap_or("help");

    match subcommand {
        "status" => {
            let store = finding_store.read().await;
            let stats = store.stats();
            SlackResponse {
                response_type: "in_channel".to_string(),
                text: format!(
                    "*Scanner Status*\n\
                     • Total Findings: {}\n\
                     • Critical: {} | High: {} | Medium: {} | Low: {}\n\
                     • Acknowledged: {}",
                    stats.total,
                    stats.critical,
                    stats.high,
                    stats.medium,
                    stats.low,
                    stats.acknowledged
                ),
                blocks: Some(vec![
                    serde_json::json!({
                        "type": "header",
                        "text": {"type": "plain_text", "text": "Scanner Status"}
                    }),
                    serde_json::json!({
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": format!("*Total Findings:* {}", stats.total)},
                            {"type": "mrkdwn", "text": format!("*Acknowledged:* {}", stats.acknowledged)}
                        ]
                    }),
                    serde_json::json!({
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": format!("*Critical:* {}", stats.critical)},
                            {"type": "mrkdwn", "text": format!("*High:* {}", stats.high)},
                            {"type": "mrkdwn", "text": format!("*Medium:* {}", stats.medium)},
                            {"type": "mrkdwn", "text": format!("*Low:* {}", stats.low)}
                        ]
                    }),
                ]),
            }
        }
        "findings" => {
            let priority_filter = parts.get(1).map(|s| s.to_string());
            let store = finding_store.read().await;
            let all = store.get_all();

            let filtered: Vec<_> = all
                .iter()
                .filter(|f| {
                    if let Some(ref p) = priority_filter {
                        f.priority.to_lowercase() == p.to_lowercase()
                    } else {
                        true
                    }
                })
                .take(5)
                .collect();

            if filtered.is_empty() {
                SlackResponse {
                    response_type: "ephemeral".to_string(),
                    text: "No findings match the filter.".to_string(),
                    blocks: None,
                }
            } else {
                let mut blocks = vec![serde_json::json!({
                    "type": "header",
                    "text": {"type": "plain_text", "text": "Recent Findings"}
                })];

                for f in &filtered {
                    blocks.push(serde_json::json!({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": format!(
                                "*{}* ({})\nWorkload: {} | Score: {:.1}\n{}",
                                f.cve, f.priority, f.workload, f.score, f.recommendation
                            )
                        },
                        "accessory": {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Acknowledge"},
                            "action_id": "acknowledge_finding",
                            "value": f.id
                        }
                    }));
                }

                SlackResponse {
                    response_type: "in_channel".to_string(),
                    text: format!("{} findings found", filtered.len()),
                    blocks: Some(blocks),
                }
            }
        }
        "help" => SlackResponse {
            response_type: "ephemeral".to_string(),
            text: "*Available Commands*\n\
                   • `/scanner status` - Show scanner status\n\
                   • `/scanner findings [priority]` - List recent findings\n\
                   • `/scanner help` - Show this help"
                .to_string(),
            blocks: None,
        },
        _ => SlackResponse {
            response_type: "ephemeral".to_string(),
            text: format!(
                "Unknown subcommand: {subcommand}. Use `/scanner help` for available commands."
            ),
            blocks: None,
        },
    }
}

/// Handle Slack interactive message callback
pub async fn handle_slack_interaction(
    State(state): State<crate::AppState>,
    Form(payload): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let finding_store = state.finding_store.clone();
    let payload_str = payload.get("payload").cloned().unwrap_or_default();

    let interaction: SlackInteraction = match serde_json::from_str(&payload_str) {
        Ok(i) => i,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid payload: {e}")})),
            )
        }
    };

    for action in &interaction.actions {
        if action.action_id == "acknowledge_finding" {
            let mut store = finding_store.write().await;
            let _ = store.acknowledge(
                &action.value,
                Some(format!(
                    "Acknowledged by {} via Slack",
                    interaction.user.name
                )),
            );
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"text": "Action processed"})),
    )
}
