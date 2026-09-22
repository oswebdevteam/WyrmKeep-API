use chrono::{Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AuditStatus {
    Queued,
    Running,
    Complete,
    Failed,
}

impl AsRef<str> for AuditStatus {
    fn as_ref(&self) -> &str {
        match self {
            AuditStatus::Queued => "queued",
            AuditStatus::Running => "running",
            AuditStatus::Complete => "complete",
            AuditStatus::Failed => "failed",
        }
    }
}

impl std::str::FromStr for AuditStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "queued" => Ok(AuditStatus::Queued),
            "running" => Ok(AuditStatus::Running),
            "complete" => Ok(AuditStatus::Complete),
            "failed" => Ok(AuditStatus::Failed),
            _ => Err(format!("Invalid AuditStatus: {}", s)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditJob {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub contract_id: Uuid,
    pub contract_name: String,
    pub source_code: String,
    pub language: String,
    pub vuln_class_tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SeverityBreakdown {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub vulnerability_count: usize,
    pub severity_breakdown: SeverityBreakdown,
    pub call_graph: serde_json::Value,
    pub bounty_estimate_usd: u64,
    pub badge_id: Option<Uuid>,
    pub chain: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditListRow {
    pub id: Uuid,
    pub contract_id: Uuid,
    pub contract_name: String,
    pub status: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: chrono::DateTime<Utc>,
}
