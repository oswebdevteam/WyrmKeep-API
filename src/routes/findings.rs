use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::auth::middleware::AuthUser;
use crate::error::AppError;
use crate::models::finding::Finding;
use crate::state::AppState;

fn offset_datetime_to_chrono(dt: time::OffsetDateTime) -> DateTime<Utc> {
    DateTime::from_timestamp(dt.unix_timestamp(), dt.nanosecond()).unwrap()
}

#[derive(sqlx::FromRow)]
struct FindingRow {
    id: Uuid,
    audit_id: Uuid,
    tenant_id: Uuid,
    vuln_class: String,
    severity: String,
    description: String,
    affected_functions: serde_json::Value,
    causal_chain: Option<serde_json::Value>,
    historical_matches: Option<i32>,
    created_at: time::OffsetDateTime,
}

#[derive(Serialize)]
pub struct FindingListResponse {
    pub data: Vec<Finding>,
    pub next_cursor: Option<Uuid>,
    pub has_more: bool,
    pub request_id: String,
}

#[derive(Deserialize)]
pub struct ListQuery {
    limit: Option<i64>,
    after: Option<Uuid>,
}

pub async fn list_findings(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Query(query): axum::extract::Query<ListQuery>,
) -> Result<Json<FindingListResponse>, AppError> {
    let limit = query.limit.unwrap_or(20);
    
    let rows: Vec<FindingRow> = if let Some(after) = query.after {
        sqlx::query_as(
            r#"
            SELECT id, audit_id, tenant_id, vuln_class, severity, description, affected_functions, causal_chain, historical_matches, created_at
            FROM findings
            WHERE tenant_id = $1 AND id > $2
            ORDER BY id ASC
            LIMIT $3
            "#
        )
        .bind(auth.tenant_id)
        .bind(after)
        .bind(limit + 1)
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT id, audit_id, tenant_id, vuln_class, severity, description, affected_functions, causal_chain, historical_matches, created_at
            FROM findings
            WHERE tenant_id = $1
            ORDER BY id ASC
            LIMIT $2
            "#
        )
        .bind(auth.tenant_id)
        .bind(limit + 1)
        .fetch_all(&state.pool)
        .await?
    };

    let has_more = rows.len() > limit as usize;
    let findings: Vec<Finding> = rows.into_iter().take(limit as usize).map(|r| {
        Finding {
            id: r.id,
            audit_id: r.audit_id,
            tenant_id: r.tenant_id,
            vuln_class: r.vuln_class,
            severity: r.severity.parse().unwrap(),
            description: r.description,
            affected_functions: r.affected_functions,
            causal_chain: r.causal_chain,
            historical_matches: r.historical_matches.unwrap_or(0),
            created_at: offset_datetime_to_chrono(r.created_at),
        }
    }).collect();
    
    let next_cursor = findings.last().map(|f| f.id);

    Ok(Json(FindingListResponse {
        data: findings,
        next_cursor,
        has_more,
        request_id: Uuid::new_v4().to_string(),
    }))
}

pub async fn get_causal_chain(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let chain: Option<serde_json::Value> = sqlx::query_scalar!(
        "SELECT causal_chain FROM findings WHERE id = $1 AND tenant_id = $2",
        id,
        auth.tenant_id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Finding not found".into()))?;

    if let Some(c) = chain {
        Ok(Json(c))
    } else {
        Err(AppError::NotFound("No causal chain available for this finding".into()))
    }
}
