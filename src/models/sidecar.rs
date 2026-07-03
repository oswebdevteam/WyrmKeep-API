use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SidecarAuditRequest {
    pub source_code: String,
    pub contract_name: String,
    pub dataset: String,
    pub node_set: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SidecarAuditResult {
    pub slither_report: SlitherReport,
    pub elapsed_ms: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SlitherReport {
    pub success: bool,
    #[serde(default)]
    pub detectors: Vec<SlitherDetector>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SlitherDetector {
    pub check: String,
    pub impact: String,
    pub confidence: String,
    pub description: String,
    #[serde(default)]
    pub elements: Vec<SlitherElement>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SlitherElement {
    #[serde(rename = "type")]
    pub element_type: String,
    pub name: String,
    pub source_mapping: Option<serde_json::Value>,
}
