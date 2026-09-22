use std::time::Instant;
use uuid::Uuid;

use crate::models::audit::{AuditJob, AuditReport, AuditStatus, SeverityBreakdown};
use crate::models::contract::ContractLanguage;
use crate::models::finding::FindingSeverity;
use crate::routes::audits::AuditEvent;
use crate::services::analyzer::AnalysisEngine;
use crate::services::badge_issuer::BadgeIssuer;
use crate::services::bounty_estimator::BountyEstimator;
use crate::state::AppState;

pub struct AuditPipeline {
    state: AppState,
}

impl AuditPipeline {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn run(&self, job: AuditJob) -> Result<(), crate::error::AppError> {
        let start_time = Instant::now();
        let audit_id = job.id;

        let emit = |event: AuditEvent| {
            if let Some(sender_ref) = self.state.audit_events.get(&audit_id) {
                let _ = sender_ref.value().send(event);
            }
        };

        sqlx::query!(
            "UPDATE audits SET status = $1 WHERE id = $2",
            AuditStatus::Running.as_ref(),
            audit_id
        )
        .execute(&self.state.pool)
        .await?;

        emit(AuditEvent::StatusUpdate {
            stage: "starting".into(),
            message: "Audit initiated".into(),
        });

        let language: ContractLanguage = job.language.parse().unwrap_or_default();

        emit(AuditEvent::AnalysisStarted {
            language: language.to_string(),
        });

        let vulnerabilities = AnalysisEngine::analyze(&job.source_code, &language);
        let analysis_elapsed = start_time.elapsed();

        emit(AuditEvent::AnalysisComplete {
            vulnerability_count: vulnerabilities.len(),
            elapsed_ms: analysis_elapsed.as_millis() as u64,
        });

        let mut call_graph_nodes: Vec<serde_json::Value> = Vec::new();
        let mut call_graph_edges: Vec<serde_json::Value> = Vec::new();
        let mut attack_paths: Vec<serde_json::Value> = Vec::new();

        for vuln in &vulnerabilities {
            for step in &vuln.attack_path {
                let node_id = format!("{}_{}", step.function_name, step.order);
                let is_vulnerable = step.order == 0;

                call_graph_nodes.push(serde_json::json!({
                    "id": node_id,
                    "type": step.action,
                    "vulnerable": is_vulnerable,
                    "line": step.line_range.as_ref().map(|lr| lr.start),
                    "function": step.function_name,
                }));
            }

            for pair in vuln.attack_path.windows(2) {
                call_graph_edges.push(serde_json::json!({
                    "from": format!("{}_{}", pair[0].function_name, pair[0].order),
                    "to": format!("{}_{}", pair[1].function_name, pair[1].order),
                    "type": "calls",
                    "attack_path": true,
                }));
            }

            if !vuln.attack_path.is_empty() {
                attack_paths.push(serde_json::json!({
                    "name": format!("{:?} via {}", vuln.vuln_class, vuln.affected_functions.first().unwrap_or(&"unknown".into())),
                    "steps": vuln.attack_path,
                }));
            }
        }

        emit(AuditEvent::CallGraphReady {
            node_count: call_graph_nodes.len(),
            edge_count: call_graph_edges.len(),
        });

        let mut high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;
        let mut informational = 0usize;

        for vuln in &vulnerabilities {
            match vuln.severity {
                FindingSeverity::High => high += 1,
                FindingSeverity::Medium => medium += 1,
                FindingSeverity::Low => low += 1,
                FindingSeverity::Informational => informational += 1,
            }
        }

        let total = vulnerabilities.len();

        emit(AuditEvent::PatternExtracted {
            node_count: call_graph_nodes.len(),
            edge_count: call_graph_edges.len(),
        });

        let bounty_estimator = BountyEstimator::default();
        let bounty_total = bounty_estimator.estimate(&vulnerabilities);

        for (idx, vuln) in vulnerabilities.iter().enumerate() {
            emit(AuditEvent::EnrichmentStarted {
                finding_index: idx,
                total,
            });

            let source_snippet = vuln.affected_lines.first().map(|lr| {
                extract_lines(&job.source_code, lr.start, lr.end)
            }).unwrap_or_default();

            let plain_english = self
                .state
                .llm_client
                .explain_vulnerability(vuln, &source_snippet)
                .await
                .ok();

            let llm_fix = self
                .state
                .llm_client
                .suggest_fix(vuln, &source_snippet)
                .await
                .ok();

            let suggested_fix_json = llm_fix
                .as_ref()
                .and_then(|f| serde_json::to_value(f).ok())
                .or_else(|| vuln.suggested_fix.as_ref().and_then(|f| serde_json::to_value(f).ok()));

            let attack_path_json = serde_json::to_value(&vuln.attack_path).ok();
            let bounty_per = bounty_estimator.per_finding(&vuln.severity) as i64;

            sqlx::query(
                r#"
                INSERT INTO findings
                    (audit_id, tenant_id, vuln_class, severity, description,
                     affected_functions, plain_english, suggested_fix, attack_path,
                     bounty_estimate_usd, confidence)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                "#,
            )
            .bind(audit_id)
            .bind(job.tenant_id)
            .bind(&vuln.check_name)
            .bind(vuln.severity.as_ref())
            .bind(&vuln.description)
            .bind(sqlx::types::Json(serde_json::to_value(&vuln.affected_functions).unwrap_or_else(|_| serde_json::json!([]))))
            .bind(plain_english)
            .bind(suggested_fix_json.map(sqlx::types::Json))
            .bind(attack_path_json.map(sqlx::types::Json))
            .bind(bounty_per)
            .bind(vuln.confidence)
            .execute(&self.state.pool)
            .await?;

            emit(AuditEvent::EnrichmentComplete { finding_index: idx });
        }

        let call_graph = serde_json::json!({
            "nodes": call_graph_nodes,
            "edges": call_graph_edges,
            "attack_paths": attack_paths,
        });

        let report = AuditReport {
            vulnerability_count: total,
            severity_breakdown: SeverityBreakdown {
                high,
                medium,
                low,
                informational,
            },
            call_graph: call_graph.clone(),
            bounty_estimate_usd: bounty_total,
            badge_id: None,
            chain: language.to_string(),
        };
        let report_json = serde_json::to_value(&report)
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

        let badge_id = BadgeIssuer::issue(
            &self.state.pool,
            audit_id,
            job.tenant_id,
            &job.contract_name,
            &language.to_string(),
            &report_json,
            total as i32,
            high as i32,
            medium as i32,
        )
        .await
        .ok();

        let final_report = AuditReport {
            badge_id,
            ..report
        };
        let final_report_json = serde_json::to_value(&final_report)
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

        sqlx::query!(
            "UPDATE audits SET report = $1, status = $2, completed_at = NOW() WHERE id = $3",
            final_report_json,
            AuditStatus::Complete.as_ref(),
            audit_id
        )
        .execute(&self.state.pool)
        .await?;

        emit(AuditEvent::ReportReady { audit_id });

        self.state.audit_events.remove(&audit_id);

        tracing::info!(
            audit_id = %audit_id,
            vulns = total,
            grade = ?badge_id.map(|_| "issued"),
            elapsed = ?start_time.elapsed(),
            "Audit completed"
        );

        Ok(())
    }

    pub async fn fail_audit(&self, audit_id: Uuid, error_msg: &str) -> Result<(), crate::error::AppError> {
        sqlx::query!(
            "UPDATE audits SET status = $1, error_message = $2 WHERE id = $3",
            AuditStatus::Failed.as_ref(),
            error_msg,
            audit_id
        )
        .execute(&self.state.pool)
        .await?;

        self.state.audit_events.remove(&audit_id);
        Ok(())
    }
}

fn extract_lines(source: &str, start: u32, end: u32) -> String {
    source
        .lines()
        .skip(start.saturating_sub(1) as usize)
        .take((end.saturating_sub(start) + 1) as usize)
        .collect::<Vec<_>>()
        .join("\n")
}
