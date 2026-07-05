use axum::{
    extract::{Path, State},
    response::sse::{Event, Sse},
    Json,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use uuid::Uuid;
use std::convert::Infallible;
use std::time::Duration;

use crate::auth::middleware::AuthUser;
use crate::error::AppError;
use crate::models::audit::{AuditJob, AuditStatus, AuditListRow};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateAuditRequest {
    pub contract_id: Uuid,
    #[serde(default = "default_vuln_tags")]
    pub vuln_class_tags: Vec<String>,
}

fn default_vuln_tags() -> Vec<String> {
    vec!["all".to_string(), "solidity".to_string()]
}

#[derive(Serialize)]
pub struct CreateAuditResponse {
    pub audit_id: Uuid,
    pub status: String,
    pub request_id: String,
}

#[derive(Deserialize)]
pub struct ListQuery {
    limit: Option<i64>,
    after: Option<Uuid>,
}

#[derive(Serialize)]
pub struct AuditListResponse {
    data: Vec<AuditListRow>,
    next_cursor: Option<Uuid>,
    has_more: bool,
    request_id: String,
}

#[derive(Clone, Serialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    StatusUpdate { stage: String, message: String },
    SlitherComplete { finding_count: usize },
    PatternExtracted { node_count: usize, edge_count: usize },
    MemoryIngested { dataset: String },
    CognifyComplete { elapsed_ms: u64 },
    RecallComplete { match_count: usize },
    ReportReady { audit_id: Uuid },
    Error { message: String },
}

pub async fn create_audit(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateAuditRequest>,
) -> Result<(StatusCode, Json<CreateAuditResponse>), AppError> {
    // 1. Verify contract belongs to tenant and get source
    let contract = sqlx::query!(
        "SELECT name, source_code FROM contracts WHERE id = $1 AND tenant_id = $2",
        payload.contract_id,
        auth.tenant_id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Contract not found".into()))?;

    // 2. Create Audit row
    let row = sqlx::query!(
        "INSERT INTO audits (tenant_id, contract_id, status) VALUES ($1, $2, $3) RETURNING id",
        auth.tenant_id,
        payload.contract_id,
        AuditStatus::Queued.as_ref()
    )
    .fetch_one(&state.pool)
    .await?;

    let audit_id = row.id;

    // 3. Setup SSE broadcast channel
    let (tx, _) = broadcast::channel(100);
    state.audit_events.insert(audit_id, tx);

    // 4. Send to job queue
    let job = AuditJob {
        id: audit_id,
        tenant_id: auth.tenant_id,
        contract_id: payload.contract_id,
        contract_name: contract.name,
        source_code: contract.source_code,
        vuln_class_tags: payload.vuln_class_tags,
    };

    state.job_tx.send(job).await.map_err(|_| {
        AppError::Internal("Failed to enqueue audit job".into())
    })?;

    Ok((
        StatusCode::ACCEPTED,
        Json(CreateAuditResponse {
            audit_id,
            status: AuditStatus::Queued.as_ref().to_string(),
            request_id: Uuid::new_v4().to_string(),
        }),
    ))
}

pub async fn stream_audit(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, AppError> {
    // Verify ownership
    sqlx::query!(
        "SELECT id FROM audits WHERE id = $1 AND tenant_id = $2",
        id,
        auth.tenant_id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Audit not found".into()))?;

    let rx = if let Some(tx) = state.audit_events.get(&id) {
        tx.subscribe()
    } else {
        return Err(AppError::NotFound("Audit stream not active".into()));
    };

    let stream = BroadcastStream::new(rx).filter_map(|res| match res {
        Ok(event) => {
            let data = serde_json::to_string(&event).unwrap();
            Some(Ok(Event::default().data(data)))
        }
        Err(_) => None,
    });

    Ok(Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(15))))
}

pub async fn get_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let report = sqlx::query_scalar!(
        "SELECT report FROM audits WHERE id = $1 AND tenant_id = $2",
        id,
        auth.tenant_id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Audit not found".into()))?;

    if let Some(r) = report {
        Ok(Json(r))
    } else {
        Err(AppError::NotFound("Report not ready yet".into()))
    }
}

pub async fn list_audits(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Query(query): axum::extract::Query<ListQuery>,
) -> Result<Json<AuditListResponse>, AppError> {
    let limit = query.limit.unwrap_or(20);
    
    let rows = if let Some(after) = query.after {
        sqlx::query_as!(
            AuditListRow,
            r#"
            SELECT a.id, a.contract_id, c.name as contract_name, a.status, a.created_at
            FROM audits a
            JOIN contracts c ON a.contract_id = c.id
            WHERE a.tenant_id = $1 AND a.id > $2
            ORDER BY a.id ASC
            LIMIT $3
            "#,
            auth.tenant_id,
            after,
            limit + 1
        )
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query_as!(
            AuditListRow,
            r#"
            SELECT a.id, a.contract_id, c.name as contract_name, a.status, a.created_at
            FROM audits a
            JOIN contracts c ON a.contract_id = c.id
            WHERE a.tenant_id = $1
            ORDER BY a.id ASC
            LIMIT $2
            "#,
            auth.tenant_id,
            limit + 1
        )
        .fetch_all(&state.pool)
        .await?
    };

    let has_more = rows.len() > limit as usize;
    let items: Vec<AuditListRow> = rows.into_iter().take(limit as usize).collect();
    let next_cursor = items.last().map(|c| c.id);

    Ok(Json(AuditListResponse {
        data: items,
        next_cursor,
        has_more,
        request_id: Uuid::new_v4().to_string(),
    }))
}
