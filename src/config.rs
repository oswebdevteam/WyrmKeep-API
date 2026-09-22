#[derive(Clone)]
pub struct AppConfig {
    pub jwt_secret: String,
    pub llm_api_key: String,
    pub llm_base_url: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            jwt_secret: std::env::var("JWT_SECRET")
                .expect("JWT_SECRET must be set"),
            llm_api_key: std::env::var("LLM_API_KEY")
                .expect("LLM_API_KEY must be set"),
            llm_base_url: std::env::var("LLM_BASE_URL")
                .unwrap_or_else(|_| "https://openrouter.ai/api/v1".into()),
        }
    }
}
