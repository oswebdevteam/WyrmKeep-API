use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub audit_id: Uuid,
    pub tenant_id: Uuid,
    pub vuln_class: String,
    pub severity: FindingSeverity,
    pub description: String,
    pub affected_functions: serde_json::Value, // JSONB array
    pub causal_chain: Option<serde_json::Value>,
    pub historical_matches: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum FindingSeverity {
    High,
    Medium,
    Low,
    Informational,
}

impl AsRef<str> for FindingSeverity {
    fn as_ref(&self) -> &str {
        match self {
            FindingSeverity::High => "High",
            FindingSeverity::Medium => "Medium",
            FindingSeverity::Low => "Low",
            FindingSeverity::Informational => "Informational",
        }
    }
}

impl std::str::FromStr for FindingSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "High" => Ok(FindingSeverity::High),
            "Medium" => Ok(FindingSeverity::Medium),
            "Low" => Ok(FindingSeverity::Low),
            "Informational" => Ok(FindingSeverity::Informational),
            _ => Err(format!("Invalid severity: {}", s)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CausalChain {
    pub nodes: Vec<ChainNode>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChainNode {
    pub id: Uuid,
    pub node_type: String,
    pub label: String,
}
