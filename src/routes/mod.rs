pub mod health;
pub mod contracts;
pub mod audits;
pub mod findings;
pub mod memory;
pub mod tenants;

use axum::{
    routing::{get, post, delete},
    Router,
};
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    request_id::MakeRequestUuid,
    timeout::TimeoutLayer,
    trace::TraceLayer,
    ServiceBuilderExt,
};
use std::time::Duration;

use crate::state::AppState;

pub fn build(state: AppState) -> Router {
    Router::new()
        // Health
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
                .layer(CorsLayer::permissive()),
        )
}
