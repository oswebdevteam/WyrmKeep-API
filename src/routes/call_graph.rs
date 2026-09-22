use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::error::AppError;
use crate::state::AppState;

#[derive(Serialize)]
pub struct CallGraphResponse {
    pub nodes: serde_json::Value,
    pub edges: serde_json::Value,
    pub attack_paths: serde_json::Value,
    pub request_id: String,
}

pub async fn get_call_graph(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<CallGraphResponse>, AppError> {
    let row = sqlx::query!(
        "SELECT report FROM audits WHERE id = $1 AND tenant_id = $2",
        id,
        auth.tenant_id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Audit not found".into()))?;

    let report = row
        .report
        .ok_or_else(|| AppError::NotFound("Report not ready yet".into()))?;

    let call_graph = report
        .get("call_graph")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "nodes": [], "edges": [] }));

    let nodes = call_graph.get("nodes").cloned().unwrap_or_else(|| serde_json::json!([]));
    let edges = call_graph.get("edges").cloned().unwrap_or_else(|| serde_json::json!([]));
    let attack_paths = call_graph
        .get("attack_paths")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));

    Ok(Json(CallGraphResponse {
        nodes,
        edges,
        attack_paths,
        request_id: Uuid::new_v4().to_string(),
    }))
}
