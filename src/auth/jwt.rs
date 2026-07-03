use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,     // Subject (Tenant ID)
    pub role: String,
    pub exp: usize,      // Expiration time
    pub iat: usize,      // Issued at
}

pub fn encode_token(tenant_id: Uuid, role: &str, secret: &str) -> Result<String, AppError> {
    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + Duration::days(1)).timestamp() as usize; // 1 day validity

    let claims = Claims {
        sub: tenant_id.to_string(),
        role: role.to_string(),
        exp,
        iat,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| {
        tracing::error!("JWT encode error: {}", e);
        AppError::Internal("Failed to generate token".to_string())
    })
}

pub fn decode_token(token: &str, secret: &str) -> Result<Claims, AppError> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| {
        tracing::debug!("JWT decode error: {}", e);
        AppError::Unauthorized
    })?;

    Ok(token_data.claims)
}
