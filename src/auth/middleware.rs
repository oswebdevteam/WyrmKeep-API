use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::request::Parts,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use uuid::Uuid;

use crate::error::AppError;
use crate::state::AppState;
use crate::auth::jwt::decode_token;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    Admin,
    Tenant,
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub tenant_id: Uuid,
    pub role: Role,
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try Bearer token first
        if let Ok(TypedHeader(Authorization(bearer))) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state).await
        {
            let claims = decode_token(bearer.token(), &state.config.jwt_secret)?;
            let tenant_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
            
            let role = match claims.role.as_str() {
                "admin" => Role::Admin,
                "tenant" => Role::Tenant,
                _ => return Err(AppError::Unauthorized),
            };

            return Ok(AuthUser { tenant_id, role });
        }

        // Try X-API-Key header fallback
        if let Some(api_key) = parts.headers.get("X-API-Key") {
            let api_key_str = api_key.to_str().map_err(|_| AppError::Unauthorized)?;
            
            // Extract the tenant id if it is prepended, or lookup by a fast method.
            // But since api keys are usually passed directly, we'd need to find the tenant.
            // For this design, let's assume the API key is passed as tenant_id:actual_key
            // If it's just raw_key, we'd have to scan all tenants (bad idea) or cache hashes.
            // Let's assume the format is `<tenant_id>.<raw_key>`
            let split: Vec<&str> = api_key_str.splitn(2, '.').collect();
            if split.len() != 2 {
                return Err(AppError::Unauthorized);
            }
            let tenant_id_str = split[0];
            let raw_key = split[1];

            let tenant_id = Uuid::parse_str(tenant_id_str).map_err(|_| AppError::Unauthorized)?;

            let tenant_hash: Option<String> = sqlx::query_scalar!(
                "SELECT api_key_hash FROM tenants WHERE id = $1",
                tenant_id
            )
            .fetch_optional(&state.pool)
            .await?;

            if let Some(hash) = tenant_hash {
                let parsed_hash = PasswordHash::new(&hash).map_err(|_| AppError::Unauthorized)?;
                if Argon2::default()
                    .verify_password(raw_key.as_bytes(), &parsed_hash)
                    .is_ok()
                {
                    return Ok(AuthUser {
                        tenant_id,
                        role: Role::Tenant,
                    });
                }
            }
        }

        Err(AppError::Unauthorized)
    }
}
