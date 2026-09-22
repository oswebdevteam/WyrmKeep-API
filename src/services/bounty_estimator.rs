use crate::models::finding::FindingSeverity;
use crate::services::analyzer::engine::DetectedVulnerability;

pub struct BountyEstimator {
    high: u64,
    medium: u64,
    low: u64,
    info: u64,
}

impl Default for BountyEstimator {
    fn default() -> Self {
        Self {
            high: 50_000,
            medium: 10_000,
            low: 1_000,
            info: 0,
        }
    }
}

impl BountyEstimator {
    pub fn estimate(&self, findings: &[DetectedVulnerability]) -> u64 {
        findings.iter().map(|f| self.per_finding(&f.severity)).sum()
    }

    pub fn per_finding(&self, severity: &FindingSeverity) -> u64 {
        match severity {
            FindingSeverity::High => self.high,
            FindingSeverity::Medium => self.medium,
            FindingSeverity::Low => self.low,
            FindingSeverity::Informational => self.info,
        }
    }
}
