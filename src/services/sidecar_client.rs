use reqwest::Client;
use std::time::Duration;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::models::sidecar::{SidecarAuditRequest, SidecarAuditResult};

pub struct SidecarClient {
    http: Client,
    base_url: String,
    token: String,
}

impl SidecarClient {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            http: Client::builder()
                .timeout(Duration::from_secs(120)) // sidecar may take a while
                .build()
                .expect("Failed to build HTTP client"),
            base_url: config.cognee_sidecar_url.clone(),
            token: config.cognee_sidecar_token.clone(),
        }
    }

    pub async fn audit(
        &self,
        source_code: &str,
        contract_name: &str,
        dataset: &str,
        node_set: &[&str],
    ) -> Result<SidecarAuditResult, AppError> {
        let request = SidecarAuditRequest {
            source_code: source_code.to_string(),
            contract_name: contract_name.to_string(),
            dataset: dataset.to_string(),
            node_set: node_set.iter().map(|s| s.to_string()).collect(),
        };

        let response = self
            .http
            .post(&format!("{}/audit", self.base_url))
            .bearer_auth(&self.token)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Sidecar network error: {}", e);
                AppError::Sidecar(format!("Failed to connect to sidecar: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            tracing::error!("Sidecar returned {}: {}", status, body);
            return Err(AppError::Sidecar(format!(
                "Sidecar error ({}): {}",
                status, body
            )));
        }

        response.json::<SidecarAuditResult>().await.map_err(|e| {
            tracing::error!("Failed to parse sidecar response: {}", e);
            AppError::Sidecar(format!("Invalid JSON from sidecar: {}", e))
        })
    }
}
