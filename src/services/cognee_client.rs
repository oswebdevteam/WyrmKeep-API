use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::error::AppError;


#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryMatch {
    pub id: Uuid,
    pub content: String,
    pub score: f32,
}

#[derive(Debug, Serialize)]
struct AddRequest<'a> {
    content: &'a str,
    dataset: &'a str,
    tags: &'a [&'a str],
}

#[derive(Debug, Deserialize)]
struct AddResponse {
    id: Uuid,
}

#[derive(Debug, Serialize)]
struct RecallRequest<'a> {
    query: &'a str,
    dataset: &'a str,
    top_k: usize,
}

#[derive(Debug, Deserialize)]
struct RecallResponse {
    matches: Vec<MemoryMatch>,
}

#[derive(Debug, Deserialize)]
struct StatsResponse {
    nodes: usize,
    edges: usize,
}


#[derive(Clone)]
pub struct CogneeClient {
    http: Client,
    config: Arc<AppConfig>,
}

impl CogneeClient {
    pub async fn new(config: &AppConfig) -> Result<Self, AppError> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Cognee(anyhow::anyhow!("HTTP client build failed: {}", e)))?;

        // Verify connectivity to the sidecar on startup
        let client = Self {
            http,
            config: Arc::new(config.clone()),
        };
        client.ping().await?;

        Ok(client)
    }

    /// Verify the sidecar memory API is reachable.
    async fn ping(&self) -> Result<(), AppError> {
        let url = format!("{}/memory/ping", self.config.cognee_sidecar_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.config.cognee_sidecar_token)
            .send()
            .await
            .map_err(|e| {
                AppError::Cognee(anyhow::anyhow!(
                    "Cognee sidecar unreachable at {}: {}",
                    self.config.cognee_sidecar_url,
                    e
                ))
            })?;

        if !resp.status().is_success() {
            return Err(AppError::Cognee(anyhow::anyhow!(
                "Cognee sidecar ping returned {}",
                resp.status()
            )));
        }

        tracing::info!("Cognee sidecar memory API verified");
        Ok(())
    }

    /// Add content to a dataset. Returns the node UUID.
    pub async fn add(
        &self,
        content: &str,
        dataset: &str,
        tags: &[&str],
    ) -> Result<Uuid, AppError> {
        let url = format!("{}/memory/add", self.config.cognee_sidecar_url);
        let body = AddRequest {
            content,
            dataset,
            tags,
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.config.cognee_sidecar_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Cognee(anyhow::anyhow!("memory/add request failed: {}", e)))?;

        if !resp.status().is_success() {
            return Self::error_from_response(resp).await;
        }

        let result: AddResponse = resp.json().await.map_err(|e| {
            AppError::Cognee(anyhow::anyhow!("Failed to parse memory/add response: {}", e))
        })?;

        tracing::debug!(
            "Added content to dataset '{}' → node {}",
            dataset,
            result.id
        );
        Ok(result.id)
    }

    /// Recall similar content from a dataset.
    pub async fn recall(
        &self,
        query: &str,
        dataset: &str,
        top_k: usize,
    ) -> Result<Vec<MemoryMatch>, AppError> {
        let url = format!("{}/memory/recall", self.config.cognee_sidecar_url);
        let body = RecallRequest {
            query,
            dataset,
            top_k,
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.config.cognee_sidecar_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                AppError::Cognee(anyhow::anyhow!("memory/recall request failed: {}", e))
            })?;

        if !resp.status().is_success() {
            return Self::error_from_response(resp).await;
        }

        let result: RecallResponse = resp.json().await.map_err(|e| {
            AppError::Cognee(anyhow::anyhow!("Failed to parse memory/recall response: {}", e))
        })?;

        tracing::debug!(
            "Recall from '{}' returned {} matches",
            dataset,
            result.matches.len()
        );
        Ok(result.matches)
    }

    /// Forget (delete) an entire dataset.
    pub async fn forget_dataset(&self, dataset: &str) -> Result<(), AppError> {
        let url = format!(
            "{}/memory/dataset/{}",
            self.config.cognee_sidecar_url,
            urlencoding(dataset)
        );

        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.config.cognee_sidecar_token)
            .send()
            .await
            .map_err(|e| {
                AppError::Cognee(anyhow::anyhow!("dataset delete failed: {}", e))
            })?;

        if !resp.status().is_success() {
            return Self::error_from_response(resp).await;
        }

        tracing::info!("Forgot dataset '{}'", dataset);
        Ok(())
    }

    /// Send improvement feedback to a dataset.
    pub async fn improve(
        &self,
        dataset: &str,
        feedback: &str,
    ) -> Result<(), AppError> {
        let url = format!("{}/memory/improve", self.config.cognee_sidecar_url);
        let body = serde_json::json!({
            "dataset": dataset,
            "feedback": feedback,
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.config.cognee_sidecar_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                AppError::Cognee(anyhow::anyhow!("memory/improve request failed: {}", e))
            })?;

        if !resp.status().is_success() {
            return Self::error_from_response(resp).await;
        }

        tracing::debug!("Improvement feedback sent to dataset '{}'", dataset);
        Ok(())
    }

    /// Get statistics for a dataset (node count, edge count).
    pub async fn get_dataset_stats(
        &self,
        dataset: &str,
    ) -> Result<(usize, usize), AppError> {
        let url = format!(
            "{}/memory/stats/{}",
            self.config.cognee_sidecar_url,
            urlencoding(dataset)
        );

        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.config.cognee_sidecar_token)
            .send()
            .await
            .map_err(|e| {
                AppError::Cognee(anyhow::anyhow!("stats request failed: {}", e))
            })?;

        if !resp.status().is_success() {
            return Self::error_from_response(resp).await;
        }

        let stats: StatsResponse = resp.json().await.map_err(|e| {
            AppError::Cognee(anyhow::anyhow!("Failed to parse stats response: {}", e))
        })?;

        Ok((stats.nodes, stats.edges))
    }

    //helpers

    async fn error_from_response<T>(
        resp: reqwest::Response,
    ) -> Result<T, AppError> {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(AppError::Cognee(anyhow::anyhow!(
            "Cognee memory API error {}: {}",
            status.as_u16(),
            body
        )))
    }
}

/// Minimal percent-encoding for dataset names (UUID-safe already, but
/// colons are technically reserved in URI paths).
fn urlencoding(s: &str) -> String {
    s.replace(':', "%3A")
}

