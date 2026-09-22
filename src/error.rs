use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("analysis error: {0}")]
    Analysis(String),
    #[error("llm error: {0}")]
    Llm(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("validation error: {0}")]
    Validation(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AppError::Database(e) => {
                tracing::error!("Database error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DATABASE_ERROR",
                    "Internal server error".to_string(),
                )
            }
            AppError::Analysis(msg) => {
                tracing::error!("Analysis error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ANALYSIS_ERROR",
                    "Contract analysis failed".to_string(),
                )
            }
            AppError::Llm(msg) => {
                tracing::error!("LLM error: {}", msg);
                (
                    StatusCode::BAD_GATEWAY,
                    "LLM_ERROR",
                    "LLM enrichment failed".to_string(),
                )
            }
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized".to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "FORBIDDEN", "Forbidden".to_string()),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg),
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Internal server error".to_string(),
                )
            }
        };

        let body = Json(ErrorResponse {
            code,
            message,
        });

        (status, body).into_response()
    }
}
