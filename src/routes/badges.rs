use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::error::AppError;
use crate::models::badge::AuditBadge;
use crate::state::AppState;


#[derive(Serialize)]
pub struct BadgeResponse {
    pub data: AuditBadge,
    pub request_id: String,
}

#[derive(Serialize)]
pub struct BadgeListResponse {
    pub data: Vec<AuditBadge>,
    pub next_cursor: Option<Uuid>,
    pub has_more: bool,
    pub request_id: String,
}

#[derive(Deserialize)]
pub struct ListQuery {
    limit: Option<i64>,
    after: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct BadgeRow {
    id: Uuid,
    audit_id: Uuid,
    tenant_id: Uuid,
    contract_name: String,
    certificate_hash: String,
    grade: String,
    vulnerability_count: i32,
    high_severity_count: i32,
    chain: String,
    issued_at: chrono::DateTime<Utc>,
    metadata_json: sqlx::types::Json<serde_json::Value>,
}

impl From<BadgeRow> for AuditBadge {
    fn from(r: BadgeRow) -> Self {
        Self {
            id: r.id,
            audit_id: r.audit_id,
            tenant_id: r.tenant_id,
            contract_name: r.contract_name,
            certificate_hash: r.certificate_hash,
            grade: r.grade,
            vulnerability_count: r.vulnerability_count,
            high_severity_count: r.high_severity_count,
            chain: r.chain,
            issued_at: r.issued_at,
            metadata_json: r.metadata_json.0,
        }
    }
}

pub async fn list_badges(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Query(query): axum::extract::Query<ListQuery>,
) -> Result<Json<BadgeListResponse>, AppError> {
    let limit = query.limit.unwrap_or(20);

    let rows: Vec<BadgeRow> = if let Some(after) = query.after {
        sqlx::query_as(
            r#"
            SELECT id, audit_id, tenant_id, contract_name, certificate_hash,
                   grade, vulnerability_count, high_severity_count, chain,
                   issued_at, metadata_json
            FROM audit_badges
            WHERE tenant_id = $1 AND id > $2
            ORDER BY id ASC
            LIMIT $3
            "#,
        )
        .bind(auth.tenant_id)
        .bind(after)
        .bind(limit + 1)
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT id, audit_id, tenant_id, contract_name, certificate_hash,
                   grade, vulnerability_count, high_severity_count, chain,
                   issued_at, metadata_json
            FROM audit_badges
            WHERE tenant_id = $1
            ORDER BY id ASC
            LIMIT $2
            "#,
        )
        .bind(auth.tenant_id)
        .bind(limit + 1)
        .fetch_all(&state.pool)
        .await?
    };

    let has_more = rows.len() > limit as usize;
    let badges: Vec<AuditBadge> = rows.into_iter().take(limit as usize).map(Into::into).collect();
    let next_cursor = badges.last().map(|b| b.id);

    Ok(Json(BadgeListResponse {
        data: badges,
        next_cursor,
        has_more,
        request_id: Uuid::new_v4().to_string(),
    }))
}

pub async fn get_badge(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<BadgeResponse>, AppError> {
    let row: BadgeRow = sqlx::query_as(
        r#"
        SELECT id, audit_id, tenant_id, contract_name, certificate_hash,
               grade, vulnerability_count, high_severity_count, chain,
               issued_at, metadata_json
        FROM audit_badges
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Badge not found".into()))?;

    Ok(Json(BadgeResponse {
        data: row.into(),
        request_id: Uuid::new_v4().to_string(),
    }))
}

/// Public endpoint — no auth required. Third parties verify audit badges.
pub async fn verify_badge(
    State(state): State<AppState>,
    Path(cert_hash): Path<String>,
) -> Result<Json<BadgeResponse>, AppError> {
    let row: BadgeRow = sqlx::query_as(
        r#"
        SELECT id, audit_id, tenant_id, contract_name, certificate_hash,
               grade, vulnerability_count, high_severity_count, chain,
               issued_at, metadata_json
        FROM audit_badges
        WHERE certificate_hash = $1
        "#,
    )
    .bind(&cert_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("No badge found for this certificate hash".into()))?;

    Ok(Json(BadgeResponse {
        data: row.into(),
        request_id: Uuid::new_v4().to_string(),
    }))
}
