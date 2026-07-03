use axum::{
    extract::{Multipart, Path, State},
    Json,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sha2::{Digest, Sha256};

use crate::auth::middleware::AuthUser;
use crate::error::AppError;
use crate::models::contract::{Contract, ContractRow};
use crate::state::AppState;

#[derive(Serialize)]
pub struct ContractResponse {
    data: Contract,
    request_id: String,
}

#[derive(Serialize)]
pub struct ContractListResponse {
    data: Vec<Contract>,
    next_cursor: Option<Uuid>,
    has_more: bool,
    request_id: String,
}

#[derive(Deserialize)]
pub struct ListQuery {
    limit: Option<i64>,
    after: Option<Uuid>,
}

pub async fn upload_contract(
    State(state): State<AppState>,
    auth: AuthUser,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<ContractResponse>), AppError> {
    let mut name = String::new();
    let mut source_code = String::new();
    let mut language = "solidity".to_string();

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "name" {
            name = field.text().await.unwrap_or_default();
        } else if field_name == "language" {
            language = field.text().await.unwrap_or_default();
        } else if field_name == "file" || field_name == "source_code" {
            source_code = field.text().await.unwrap_or_default();
        }
    }

    if name.is_empty() || source_code.is_empty() {
        return Err(AppError::Validation("name and file are required".into()));
    }

    let mut hasher = Sha256::new();
    hasher.update(source_code.as_bytes());
    let source_hash = format!("{:x}", hasher.finalize());

    let row = sqlx::query_as::<_, ContractRow>(
        r#"
        INSERT INTO contracts (tenant_id, name, source_hash, source_code, language)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, tenant_id, name, source_hash, source_code, language, uploaded_at
        "#
    )
    .bind(auth.tenant_id)
    .bind(name)
    .bind(source_hash)
    .bind(source_code)
    .bind(language)
    .fetch_one(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ContractResponse {
            data: row.into(),
            request_id: Uuid::new_v4().to_string(), // In reality, we'd extract from Request parts
        }),
    ))
}

pub async fn list_contracts(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Query(query): axum::extract::Query<ListQuery>,
) -> Result<Json<ContractListResponse>, AppError> {
    let limit = query.limit.unwrap_or(20);
    
    let rows = if let Some(after) = query.after {
        sqlx::query_as::<_, ContractRow>(
            "SELECT id, tenant_id, name, source_hash, source_code, language, uploaded_at FROM contracts WHERE tenant_id = $1 AND id > $2 ORDER BY id ASC LIMIT $3"
        )
        .bind(auth.tenant_id)
        .bind(after)
        .bind(limit + 1)
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query_as::<_, ContractRow>(
            "SELECT id, tenant_id, name, source_hash, source_code, language, uploaded_at FROM contracts WHERE tenant_id = $1 ORDER BY id ASC LIMIT $2"
        )
        .bind(auth.tenant_id)
        .bind(limit + 1)
        .fetch_all(&state.pool)
        .await?
    };

    let has_more = rows.len() > limit as usize;
    let items: Vec<Contract> = rows.into_iter().take(limit as usize).map(Into::into).collect();
    let next_cursor = items.last().map(|c| c.id);

    Ok(Json(ContractListResponse {
        data: items,
        next_cursor,
        has_more,
        request_id: Uuid::new_v4().to_string(),
    }))
}

pub async fn get_contract(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ContractResponse>, AppError> {
    let row = sqlx::query_as::<_, ContractRow>(
        "SELECT id, tenant_id, name, source_hash, source_code, language, uploaded_at FROM contracts WHERE id = $1 AND tenant_id = $2"
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Contract not found".into()))?;

    Ok(Json(ContractResponse {
        data: row.into(),
        request_id: Uuid::new_v4().to_string(),
    }))
}
