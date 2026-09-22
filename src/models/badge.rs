use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum AuditGrade {
    APlus,
    A,
    B,
    C,
    D,
    F,
}

impl AuditGrade {
    pub fn from_counts(high: usize, medium: usize) -> Self {
        match (high, medium) {
            (0, 0) => Self::APlus,
            (0, m) if m <= 2 => Self::A,
            (0, _) => Self::B,
            (1, _) => Self::C,
            (h, _) if h <= 3 => Self::D,
            _ => Self::F,
        }
    }
}

impl std::fmt::Display for AuditGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::APlus => "A+",
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditBadge {
    pub id: Uuid,
    pub audit_id: Uuid,
    pub tenant_id: Uuid,
    pub contract_name: String,
    pub certificate_hash: String,
    pub grade: String,
    pub vulnerability_count: i32,
    pub high_severity_count: i32,
    pub chain: String,
    pub issued_at: DateTime<Utc>,
    pub metadata_json: serde_json::Value,
}
