use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::AppError;
use crate::models::badge::AuditGrade;

pub struct BadgeIssuer;

impl BadgeIssuer {
    pub async fn issue(
        pool: &sqlx::PgPool,
        audit_id: Uuid,
        tenant_id: Uuid,
        contract_name: &str,
        chain: &str,
        report_json: &serde_json::Value,
        vulnerability_count: i32,
        high_severity_count: i32,
        medium_severity_count: i32,
    ) -> Result<Uuid, AppError> {
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
        .bind(certificate_hash.clone())
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
