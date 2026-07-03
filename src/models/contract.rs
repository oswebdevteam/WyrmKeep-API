use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Contract {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub source_hash: String,
    pub source_code: String,
    pub language: String,
    pub uploaded_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateContractRequest {
    pub name: String,
    pub source_code: String,
    #[serde(default = "default_language")]
    pub language: String,
}

fn default_language() -> String {
    "solidity".to_string()
}

#[derive(Debug, sqlx::FromRow)]
pub struct ContractRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub source_hash: String,
    pub source_code: String,
    pub language: String,
    pub uploaded_at: DateTime<Utc>,
}

impl From<ContractRow> for Contract {
    fn from(row: ContractRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            source_hash: row.source_hash,
            source_code: row.source_code,
            language: row.language,
            uploaded_at: row.uploaded_at,
        }
    }
}
