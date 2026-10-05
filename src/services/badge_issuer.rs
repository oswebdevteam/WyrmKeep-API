use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::AppError;
use crate::models::badge::AuditGrade;

pub struct BadgeIssuer;

#[derive(Debug, Clone, Copy)]
pub struct BadgeIssueParams<'a> {
    pub audit_id: Uuid,
    pub tenant_id: Uuid,
    pub contract_name: &'a str,
    pub chain: &'a str,
    pub report_json: &'a serde_json::Value,
    pub vulnerability_count: i32,
    pub high_severity_count: i32,
    pub medium_severity_count: i32,
}

impl BadgeIssuer {
    pub async fn issue(
        pool: &sqlx::PgPool,
        params: BadgeIssueParams<'_>,
    ) -> Result<Uuid, AppError> {
        let BadgeIssueParams {
            audit_id,
            tenant_id,
            contract_name,
            chain,
            report_json,
            vulnerability_count,
            high_severity_count,
            medium_severity_count,
        } = params;
        let grade = AuditGrade::from_counts(
            high_severity_count as usize,
            medium_severity_count as usize,
        );

        let mut hasher = Sha256::new();
        hasher.update(audit_id.as_bytes());
        hasher.update(report_json.to_string().as_bytes());
        let certificate_hash = format!("{:x}", hasher.finalize());

        let metadata = serde_json::json!({
            "name": format!("WyrmKeep Audit Badge — {}", contract_name),
            "description": format!(
                "This contract was audited by WyrmKeep and received a grade of {}.",
                grade
            ),
            "image": "https://wyrmkeep.io/badge.svg",
            "attributes": [
                { "trait_type": "Grade", "value": grade.to_string() },
                { "trait_type": "Chain", "value": chain },
                { "trait_type": "Vulnerabilities Found", "value": vulnerability_count },
                { "trait_type": "High Severity", "value": high_severity_count },
                { "trait_type": "Audit ID", "value": audit_id.to_string() },
                { "trait_type": "Certificate Hash", "value": &certificate_hash },
            ],
            "external_url": format!("https://wyrmkeep.io/verify/{}", certificate_hash),
        });

        let badge_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO audit_badges
                (audit_id, tenant_id, contract_name, certificate_hash, grade,
                 vulnerability_count, high_severity_count, chain, metadata_json)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#
        )
        .bind(audit_id)
        .bind(tenant_id)
        .bind(contract_name)
        .bind(certificate_hash)
        .bind(grade.to_string())
        .bind(vulnerability_count)
        .bind(high_severity_count)
        .bind(chain)
        .bind(sqlx::types::Json(metadata))
        .fetch_one(pool)
        .await?;

        tracing::info!(
            "Issued badge {} (grade {}) for audit {}",
            badge_id, grade, audit_id
        );

        Ok(badge_id)
    }
}
