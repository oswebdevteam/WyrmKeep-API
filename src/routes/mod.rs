pub mod audits;
pub mod contracts;
pub mod findings;
pub mod health;
pub mod memory;
pub mod tenants;

use axum::{
    http,
    routing::{delete, get, post},
    Router,
};
use std::time::Duration;
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::{KeyExtractor, SmartIpKeyExtractor},
    GovernorLayer,
};
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, request_id::MakeRequestUuid,
    timeout::TimeoutLayer, trace::TraceLayer, ServiceBuilderExt,
};

use crate::state::AppState;

// ── Rate-limit key extractor (per tenant)

#[derive(Clone)]
pub struct TenantRateLimitKey;

impl KeyExtractor for TenantRateLimitKey {
    type Key = String;

    fn extract<B>(&self, req: &http::Request<B>) -> Result<Self::Key, tower_governor::errors::GovernorError> {
        // Try X-API-Key header with tenant prefix
        if let Some(api_key) = req.headers().get("X-API-Key") {
            if let Ok(value) = api_key.to_str() {
                return Ok(value.split('.').next().unwrap_or("anon").to_string());
            }
        }
        // Try Bearer token — use truncated token as key for uniqueness
        if let Ok(auth_value) = std::str::from_utf8(
            req.headers()
                .get(http::header::AUTHORIZATION)
                .map(|v| v.as_bytes())
                .unwrap_or(b""),
        ) {
            if let Some(token) = auth_value.strip_prefix("Bearer ") {
                return Ok(format!("jwt:{}", &token[..token.len().min(32)]));
            }
        }
        SmartIpKeyExtractor
            .extract(req)
            .map(|ip| ip.to_string())
    }
}

// ── Router builder

pub fn build(state: AppState) -> Router {
    let governor_conf = std::sync::Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1) // ≈ 60 req/min steady
            .burst_size(10)
            .key_extractor(TenantRateLimitKey)
            .finish()
            .unwrap(),
    );
    let governor_limiter = governor_conf.limiter().clone();

    // Evict stale entries every 60s
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            governor_limiter.retain_recent();
        }
    });

    Router::new()
        .route("/health", get(health::health_check))
        // Tenants
        .route("/v1/tenants", post(tenants::create_tenant))
        .route("/v1/tenants/me", get(tenants::get_me))
        // Contracts
        .route("/v1/contracts", post(contracts::upload_contract))
        .route("/v1/contracts", get(contracts::list_contracts))
        .route("/v1/contracts/:id", get(contracts::get_contract))
        // Audits
        .route("/v1/audits", post(audits::create_audit))
        .route("/v1/audits", get(audits::list_audits))
        .route("/v1/audits/:id/stream", get(audits::stream_audit))
        .route("/v1/audits/:id/report", get(audits::get_report))
        // Findings
        .route("/v1/findings", get(findings::list_findings))
        .route("/v1/findings/:id/chain", get(findings::get_causal_chain))
        // Memory
        .route("/v1/memory/recall", post(memory::recall_memory))
        .route("/v1/memory/prune", delete(memory::prune_memory))
        .route("/v1/memory/stats", get(memory::memory_stats))
        .with_state(state)
        .layer(
            tower::ServiceBuilder::new()
                .set_x_request_id(MakeRequestUuid)
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(TimeoutLayer::new(Duration::from_secs(30)))
                .layer(CorsLayer::permissive())
                .layer(GovernorLayer {
                    config: governor_conf,
                }),
        )
}
