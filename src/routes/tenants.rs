use axum::{
    extract::State,
    Json,
};
use reqwest::StatusCode;
use serde::Serialize;
use uuid::Uuid;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

use crate::auth::middleware::{AuthUser, Role};
use crate::error::AppError;
use crate::models::tenant::{CreateTenantRequest, Tenant};
use crate::state::AppState;
use crate::auth::jwt::encode_token;

#[derive(Serialize)]
pub struct CreateTenantResponse {
    pub data: Tenant,
    pub api_key: String,
    pub session_token: String,
    pub request_id: String,
}

#[derive(Serialize)]
pub struct TenantResponse {
    pub data: Tenant,
    pub request_id: String,
}

pub async fn create_tenant(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateTenantRequest>,
) -> Result<(StatusCode, Json<CreateTenantResponse>), AppError> {
    if auth.role != Role::Admin {
        return Err(AppError::Forbidden);
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let api_key_hash = argon2
        .hash_password(payload.raw_api_key.as_bytes(), &salt)
        .map_err(|_| AppError::Internal("Failed to hash API key".into()))?
        .to_string();

    let tenant_id = Uuid::new_v4();

    let tenant = sqlx::query_as::<_, Tenant>(
        r#"
        INSERT INTO tenants (id, name, api_key_hash)
        VALUES ($1, $2, $3)
        RETURNING id, name, api_key_hash, created_at
        "#
    )
    .bind(tenant_id)
    .bind(&payload.name)
    .bind(&api_key_hash)
    .fetch_one(&state.pool)
    .await?;

    let session_token = encode_token(tenant_id, "tenant", &state.config.jwt_secret)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateTenantResponse {
            data: tenant,
            api_key: payload.raw_api_key,
            session_token,
            request_id: Uuid::new_v4().to_string(),
        }),
    ))
}

pub async fn get_me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<TenantResponse>, AppError> {
    let tenant = sqlx::query_as::<_, Tenant>(
        r#"
        SELECT id, name, api_key_hash, created_at
        FROM tenants
        WHERE id = $1
        "#
    )
    .bind(auth.tenant_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Tenant not found".into()))?;

    Ok(Json(TenantResponse {
        data: tenant,
        request_id: Uuid::new_v4().to_string(),
    }))
}
