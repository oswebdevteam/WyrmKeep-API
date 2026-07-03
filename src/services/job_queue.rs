use tokio::sync::mpsc;
use crate::models::audit::AuditJob;
use crate::services::pipeline::AuditPipeline;
use crate::state::AppState;

pub async fn spawn_job_worker(mut rx: mpsc::Receiver<AuditJob>, state: AppState) {
    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = AuditPipeline::new(state).run(job).await {
                    tracing::error!(error = %e, "audit pipeline failed");
                }
            });
        }
    });
}
