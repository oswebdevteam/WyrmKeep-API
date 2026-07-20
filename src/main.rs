use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use wyrmkeep_api::config::AppConfig;
use wyrmkeep_api::models::audit::AuditJob;
use wyrmkeep_api::routes;
use wyrmkeep_api::services::job_queue::spawn_job_worker;
use wyrmkeep_api::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wyrmkeep_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables from .env file (if present)
    dotenv::dotenv().ok();

    // Get configuration from environment variables
    let config = AppConfig::from_env();
    
    // Database connection
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .max_lifetime(Duration::from_secs(30 * 60)) 
        .idle_timeout(Duration::from_secs(10 * 60))   
        .test_before_acquire(true)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    // Run database migrations on startup
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Migrations failed");

    tracing::info!("Database migrations completed");

    // Create job queue channel
    let (job_tx, job_rx) = mpsc::channel::<AuditJob>(100);

    let state = AppState::new(pool, config, job_tx)
        .await
        .expect("Failed to initialize AppState");

    // Spawn the background worker for processing audit jobs
    spawn_job_worker(job_rx, state.clone()).await;

    let router = routes::build(state);

    // Get port from environment or default to 8000
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);
    
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    
    tracing::info!("Server starting on {}", addr);

    axum::serve(listener, router)
        .await?;

    Ok(())
}
