use std::time::Instant;

use crate::models::audit::{AuditJob, AuditReport, AuditStatus};
use crate::models::finding::FindingSeverity;
use crate::services::pattern::PatternAbstractor;
use crate::state::AppState;
use crate::routes::audits::AuditEvent;

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
        
        // Helper to emit events if there is a listener
        let emit_event = |event: AuditEvent| {
            if let Some(sender) = self.state.audit_events.get(&audit_id) {
                let _ = sender.send(event);
            }
        };

        // 1. DB: update audit status -> "running"
        sqlx::query!(
            "UPDATE audits SET status = $1 WHERE id = $2",
            AuditStatus::Running.as_ref(),
            audit_id
        )
        .execute(&self.state.pool)
        .await?;

        emit_event(AuditEvent::StatusUpdate {
            stage: "starting".to_string(),
            message: "Audit initiated".to_string(),
        });

        // 2. sidecar_client.audit
        let node_set: Vec<&str> = job.vuln_class_tags.iter().map(|s| s.as_str()).collect();
        let sidecar_result = match self
            .state
            .sidecar_client
            .audit(
                &job.source_code,
                &job.contract_name,
                "wyrmkeep:shared:patterns",
                &node_set,
            )
            .await
        {
            Ok(res) => res,
            Err(e) => {
                self.fail_audit(audit_id, &e.to_string()).await?;
                emit_event(AuditEvent::Error {
                    message: e.to_string(),
                });
                return Err(e);
            }
        };

        let finding_count = sidecar_result.slither_report.detectors.len();
        emit_event(AuditEvent::SlitherComplete { finding_count });
        emit_event(AuditEvent::CognifyComplete {
            elapsed_ms: sidecar_result.elapsed_ms,
        });

        let slither_raw = serde_json::to_value(&sidecar_result.slither_report).unwrap();
        sqlx::query!(
            "UPDATE audits SET slither_raw = $1 WHERE id = $2",
            slither_raw,
            audit_id
        )
        .execute(&self.state.pool)
        .await?;

        // 3. PatternAbstractor::extract
        let patterns = PatternAbstractor::extract(&sidecar_result.slither_report);
        let node_count = patterns.iter().map(|p| p.nodes.len()).sum();
        let edge_count = patterns.iter().map(|p| p.edges.len()).sum();
        
        emit_event(AuditEvent::PatternExtracted { node_count, edge_count });
        
        let abstract_pattern_json = serde_json::to_value(&patterns).unwrap();
        sqlx::query!(
            "UPDATE audits SET abstract_pattern = $1 WHERE id = $2",
            abstract_pattern_json,
            audit_id
        )
        .execute(&self.state.pool)
        .await?;

        // 4 & 5. Serialize and cognee_client.add
        let mut match_count = 0;
        let mut memory_matches = Vec::new();
        
        for pattern in patterns {
            let anonymized_vars: Vec<String> = pattern.nodes.iter().filter(|n| n.node_type == crate::models::vuln_ontology::VulnNodeType::StateVariable).map(|n| n.label.clone()).collect();
            let anonymized_fns: Vec<String> = pattern.nodes.iter().filter(|n| n.node_type == crate::models::vuln_ontology::VulnNodeType::Function).map(|n| n.label.clone()).collect();
            
            let text = format!(
                "VulnClass: {:?}\nSeverity: {}\nCallChain: {:?}\nViolatedInvariant: {:?}\nStateVariables: {:?}",
                pattern.vuln_class, pattern.severity, anonymized_fns, "None", anonymized_vars
            );

            let tags = [format!("{:?}", pattern.vuln_class)];
            
            if let Err(e) = self.state.cognee_client.add(&text, "wyrmkeep:shared:patterns", &tags.iter().map(|s| s.as_str()).collect::<Vec<&str>>()).await {
                tracing::warn!("Failed to add to memory: {}", e);
            }

            emit_event(AuditEvent::MemoryIngested {
                dataset: "wyrmkeep:shared:patterns".to_string(),
            });

            // 6. cognee_client.recall
            let query = format!("exploit pattern: {:?}", pattern.vuln_class);
            if let Ok(matches) = self.state.cognee_client.recall(&query, "wyrmkeep:shared:patterns", 5).await {
                match_count += matches.len();
                memory_matches.extend(matches);
            }
        }

        emit_event(AuditEvent::RecallComplete { match_count });

        // 7. Merge and Report
        let memory_matches_json = serde_json::to_value(&memory_matches).unwrap();
        
        let report = AuditReport {
            slither_findings_count: finding_count,
            memory_matches_count: match_count,
        };
        let report_json = serde_json::to_value(&report).unwrap();

        sqlx::query!(
            "UPDATE audits SET memory_matches = $1, report = $2 WHERE id = $3",
            memory_matches_json,
            report_json,
            audit_id
        )
        .execute(&self.state.pool)
        .await?;

        // Insert Findings
        for detector in sidecar_result.slither_report.detectors {
            let severity: FindingSeverity = detector.impact.parse().unwrap_or(FindingSeverity::Informational);
            
            sqlx::query!(
                "INSERT INTO findings (audit_id, tenant_id, vuln_class, severity, description, affected_functions) VALUES ($1, $2, $3, $4, $5, $6)",
                audit_id,
                job.tenant_id,
                detector.check,
                severity.as_ref(),
                detector.description,
                serde_json::to_value(&detector.elements).unwrap()
            )
            .execute(&self.state.pool)
            .await?;
        }

        // 8. Forget private dataset
        let private_dataset = format!("wyrmkeep:{}:private", job.tenant_id);
        let _ = self.state.cognee_client.forget_dataset(&private_dataset).await;

        // 9. Update audit status -> "complete"
        sqlx::query!(
            "UPDATE audits SET status = $1, completed_at = NOW() WHERE id = $2",
            AuditStatus::Complete.as_ref(),
            audit_id
        )
        .execute(&self.state.pool)
        .await?;

        emit_event(AuditEvent::ReportReady { audit_id });

        // Clean up SSE sender
        self.state.audit_events.remove(&audit_id);

        tracing::info!("Audit {} completed in {:?}", audit_id, start_time.elapsed());
        Ok(())
    }

    async fn fail_audit(&self, audit_id: uuid::Uuid, error_msg: &str) -> Result<(), crate::error::AppError> {
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
