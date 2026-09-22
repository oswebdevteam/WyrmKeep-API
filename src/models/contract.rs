use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContractLanguage {
    Solidity,
    Rust,
    Move,
    Cairo,
    Aiken,
    Compact,
    Quorlin,
}

impl std::fmt::Display for ContractLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Solidity => "solidity",
            Self::Rust => "rust",
            Self::Move => "move",
            Self::Cairo => "cairo",
            Self::Aiken => "aiken",
            Self::Compact => "compact",
            Self::Quorlin => "quorlin",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for ContractLanguage {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "solidity" | "sol" => Ok(Self::Solidity),
            "rust" | "rs" | "solana" | "anchor" => Ok(Self::Rust),
            "move" | "aptos" | "sui" => Ok(Self::Move),
            "cairo" | "starknet" => Ok(Self::Cairo),
            "aiken" | "cardano" => Ok(Self::Aiken),
            "compact" | "midnight" => Ok(Self::Compact),
            "quorlin" | "kortana" => Ok(Self::Quorlin),
            _ => Err(format!("Unsupported language: {}. Supported: solidity, rust, move, cairo, aiken, compact, quorlin", s)),
        }
    }
}

impl Default for ContractLanguage {
    fn default() -> Self {
        Self::Solidity
    }
}

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
