use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing)]
    pub api_key_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTenantRequest {
    pub name: String,
    pub raw_api_key: String,
}
