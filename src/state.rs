use std::sync::Arc;
use dashmap::DashMap;
use sqlx::PgPool;
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::models::audit::AuditJob;
use crate::routes::audits::AuditEvent;
use crate::services::llm_client::LlmClient;

pub struct AppStateInner {
    pub pool: PgPool,
    pub config: Arc<AppConfig>,
    pub llm_client: LlmClient,
    pub job_tx: mpsc::Sender<AuditJob>,
    pub audit_events: DashMap<Uuid, broadcast::Sender<AuditEvent>>,
}

#[derive(Clone)]
pub struct AppState(Arc<AppStateInner>);

impl AppState {
    pub fn new(
        pool: PgPool,
        config: AppConfig,
        job_tx: mpsc::Sender<AuditJob>,
    ) -> Self {
        let config = Arc::new(config);
        let llm_client = LlmClient::new(Arc::clone(&config));

        let inner = AppStateInner {
            pool,
            config,
            llm_client,
            job_tx,
            audit_events: DashMap::new(),
        };

        Self(Arc::new(inner))
    }
}

impl std::ops::Deref for AppState {
    type Target = AppStateInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
