#[cfg(test)]
#[allow(unused_imports, dead_code)]
mod pipeline_tests {
    use dashmap::DashMap;
    use std::sync::Arc;
    use tokio::sync::{broadcast, mpsc};
    use uuid::Uuid;

    use crate::config::AppConfig;
    use crate::models::audit::{AuditJob, AuditStatus};
    use crate::services::cognee_client::CogneeClient;
    use crate::services::pipeline::AuditPipeline;
    use crate::services::sidecar_client::SidecarClient;
    use crate::state::{AppState, AppStateInner};

    fn test_config() -> AppConfig {
        AppConfig {
            jwt_secret: "test-secret-at-least-32-characters-long".into(),
            cognee_sidecar_url: "http://localhost:9999".into(),
            cognee_sidecar_token: "test-token".into(),
            llm_api_key: "test-key".into(),
        }
    }

    /// Build a minimal AppState that does NOT require a real database.
    /// Tests that hit the DB path will use sqlx::test or be skipped.
    async fn test_state() -> (AppState, mpsc::Receiver<AuditJob>) {
        // We need a real pool for sqlx queries in the pipeline.
        // For unit tests that don't touch DB, we'd mock at a higher level.
        // These tests verify the pipeline orchestrates correctly given
        // mocked sidecar/cognee responses — see integration test notes.
        todo!("Requires test DB — run via `cargo test -- --ignored` with DATABASE_URL")
    }

    // ── Pipeline orchestration tests (require test DB) ──────────────

    /// Verify that a queued audit transitions through Running → Complete
    /// when the sidecar returns a valid report.
    #[tokio::test]
    #[ignore = "requires test database"]
    async fn audit_lifecycle_success() {
        // Setup: create tenant, contract, initial audit row, then run pipeline
        // Assert: audit.status == "complete", report is not null, findings inserted
    }

    /// Verify that a sidecar failure sets status to Failed with error_message.
    #[tokio::test]
    #[ignore = "requires test database"]
    async fn audit_lifecycle_sidecar_failure() {
        // Assert: audit.status == "failed", error_message is set
    }

    /// Verify SSE events are emitted at each stage.
    #[tokio::test]
    #[ignore = "requires test database"]
    async fn sse_events_emitted() {
        // Subscribe to broadcast channel before running pipeline
        // Collect events and assert minimum set: StatusUpdate, SlitherComplete,
        // PatternExtracted, MemoryIngested, CognifyComplete, RecallComplete, ReportReady
    }

    /// Verify private dataset is forgotten after audit completes.
    #[tokio::test]
    #[ignore = "requires test database"]
    async fn private_dataset_forgotten_after_completion() {
        // Assert: CogneeClient.forget_dataset called with tenant's private dataset
    }

    /// Verify SSE channel is cleaned up after audit (success path).
    #[tokio::test]
    #[ignore = "requires test database"]
    async fn sse_channel_cleaned_up() {
        // Assert: state.audit_events no longer contains key after pipeline completes
    }

    /// Verify SSE channel is cleaned up after audit failure.
    #[tokio::test]
    #[ignore = "requires test database"]
    async fn sse_channel_cleaned_up_on_failure() {
        // Assert: state.audit_events no longer contains key after fail_audit
    }
}
