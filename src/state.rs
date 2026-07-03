use std::sync::Arc;
use dashmap::DashMap;
use sqlx::PgPool;
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::models::audit::AuditJob;
use crate::services::{cognee_client::CogneeClient, sidecar_client::SidecarClient};

// We will define AuditEvent in routes/audits.rs as requested or here if needed,
// but let's define it here or import it. The prompt says it's in routes/audits.rs.
use crate::routes::audits::AuditEvent;

pub struct AppStateInner {
    pub pool: PgPool,
    pub config: Arc<AppConfig>,
    pub cognee_client: CogneeClient,
    pub sidecar_client: SidecarClient,
    pub job_tx: mpsc::Sender<AuditJob>,
    pub audit_events: DashMap<Uuid, broadcast::Sender<AuditEvent>>,
}

#[derive(Clone)]
pub struct AppState(Arc<AppStateInner>);

impl AppState {
    pub async fn new(
        pool: PgPool,
        config: AppConfig,
        job_tx: mpsc::Sender<AuditJob>,
    ) -> Result<Self, AppError> {
        let config_arc = Arc::new(config.clone());
        let sidecar_client = SidecarClient::new(&config);
        let cognee_client = CogneeClient::new(&config).await?;

        let inner = AppStateInner {
            pool,
            config: config_arc,
            cognee_client,
            sidecar_client,
            job_tx,
            audit_events: DashMap::new(),
        };

        Ok(Self(Arc::new(inner)))
    }
}

impl std::ops::Deref for AppState {
    type Target = AppStateInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
