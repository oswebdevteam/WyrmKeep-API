use axum::{
    extract::State,
    Json,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::error::AppError;
use crate::services::cognee_client::MemoryMatch;
use crate::state::AppState;

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatasetScope {
    Shared,
    Private,
    Session,
}

impl Default for DatasetScope {
    fn default() -> Self {
        DatasetScope::Shared
    }
}

#[derive(Deserialize)]
pub struct RecallRequest {
    pub query: String,
    #[serde(default = "default_top_k")]
    pub top_k: usize,
    #[serde(default)]
    pub scope: DatasetScope,
}

fn default_top_k() -> usize {
    5
}

#[derive(Serialize)]
pub struct RecallResponse {
    pub data: Vec<MemoryMatch>,
    pub request_id: String,
}

#[derive(Serialize)]
pub struct StatsResponse {
    pub shared_patterns: DatasetStats,
    pub private_dataset: DatasetStats,
    pub session_dataset: DatasetStats,
    pub request_id: String,
}

#[derive(Serialize)]
pub struct DatasetStats {
    pub name: String,
    pub nodes: usize,
    pub edges: usize,
}

pub async fn recall_memory(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<RecallRequest>,
) -> Result<Json<RecallResponse>, AppError> {
    let dataset = match payload.scope {
        DatasetScope::Shared => "wyrmkeep:shared:patterns".to_string(),
        DatasetScope::Private => format!("wyrmkeep:{}:private", auth.tenant_id),
        DatasetScope::Session => format!("wyrmkeep:{}:session", auth.tenant_id),
    };
    
    let matches = state.cognee_client.recall(&payload.query, &dataset, payload.top_k).await?;
    
    Ok(Json(RecallResponse {
        data: matches,
        request_id: Uuid::new_v4().to_string(),
    }))
}

pub async fn prune_memory(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    // Delete private dataset
    let private_dataset = format!("wyrmkeep:{}:private", auth.tenant_id);
    state.cognee_client.forget_dataset(&private_dataset).await?;
    
    // Delete session dataset
    let session_dataset = format!("wyrmkeep:{}:session", auth.tenant_id);
    state.cognee_client.forget_dataset(&session_dataset).await?;
    
    tracing::info!("Pruned memory for tenant: {}", auth.tenant_id);
    
    Ok(StatusCode::NO_CONTENT)
}

pub async fn memory_stats(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<StatsResponse>, AppError> {
    // Get stats for all datasets
    let shared_dataset = "wyrmkeep:shared:patterns";
    let private_dataset = format!("wyrmkeep:{}:private", auth.tenant_id);
    let session_dataset = format!("wyrmkeep:{}:session", auth.tenant_id);
    
    let (shared_nodes, shared_edges) = state.cognee_client.get_dataset_stats(shared_dataset).await?;
    let (private_nodes, private_edges) = state.cognee_client.get_dataset_stats(&private_dataset).await?;
    let (session_nodes, session_edges) = state.cognee_client.get_dataset_stats(&session_dataset).await?;
    
    Ok(Json(StatsResponse {
        shared_patterns: DatasetStats {
            name: shared_dataset.to_string(),
            nodes: shared_nodes,
            edges: shared_edges,
        },
        private_dataset: DatasetStats {
            name: private_dataset,
            nodes: private_nodes,
            edges: private_edges,
        },
        session_dataset: DatasetStats {
            name: session_dataset,
            nodes: session_nodes,
            edges: session_edges,
        },
        request_id: Uuid::new_v4().to_string(),
    }))
}
