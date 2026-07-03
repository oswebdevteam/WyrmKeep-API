#[derive(Clone)]
pub struct AppConfig {
    pub jwt_secret: String,
    pub cognee_sidecar_url: String,
    pub cognee_sidecar_token: String,
    pub llm_api_key: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            jwt_secret: std::env::var("JWT_SECRET")
                .expect("JWT_SECRET must be set"),
            cognee_sidecar_url: std::env::var("COGNEE_SIDECAR_URL")
                .expect("COGNEE_SIDECAR_URL must be set"),
            cognee_sidecar_token: std::env::var("COGNEE_SIDECAR_TOKEN")
                .expect("COGNEE_SIDECAR_TOKEN must be set"),
            llm_api_key: std::env::var("LLM_API_KEY")
                .expect("LLM_API_KEY must be set"),
        }
    }
}
