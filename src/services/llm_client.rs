use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::models::vuln_ontology::CodeDiff;
use crate::services::analyzer::engine::DetectedVulnerability;

#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Debug, Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
}

#[derive(Debug, Deserialize)]
struct ChatChoiceMessage {
    content: String,
}

#[derive(Clone)]
pub struct LlmClient {
    http: Client,
    config: Arc<AppConfig>,
}

impl LlmClient {
    pub fn new(config: Arc<AppConfig>) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("LLM HTTP client build should not fail with default config");

        Self { http, config }
    }

    pub async fn explain_vulnerability(
        &self,
        vuln: &DetectedVulnerability,
        source_snippet: &str,
    ) -> Result<String, AppError> {
        let prompt = format!(
            "You are a smart contract security expert. Explain this vulnerability in plain English \
             that a non-technical project manager can understand. Include: what the risk is, \
             what an attacker could do, and how much money could be at risk.\n\n\
             Vulnerability: {:?}\n\
             Severity: {:?}\n\
             Technical description: {}\n\n\
             Relevant code:\n```\n{}\n```\n\n\
             Respond with ONLY the plain-English explanation, no markdown headers.",
            vuln.vuln_class, vuln.severity, vuln.description, source_snippet
        );

        self.chat(&prompt).await
    }

    pub async fn suggest_fix(
        &self,
        vuln: &DetectedVulnerability,
        source_snippet: &str,
    ) -> Result<CodeDiff, AppError> {
        let prompt = format!(
            "You are a smart contract security expert. Provide a minimal code fix for this vulnerability.\n\n\
             Vulnerability: {:?}\n\
             Severity: {:?}\n\
             Description: {}\n\n\
             Original code:\n```\n{}\n```\n\n\
             Respond with EXACTLY this format (no other text):\n\
             PATCHED:\n```\n<fixed code here>\n```\n\
             EXPLANATION: <one sentence explaining the fix>",
            vuln.vuln_class, vuln.severity, vuln.description, source_snippet
        );

        let response = self.chat(&prompt).await?;

        let patched = response
            .split("```")
            .nth(1)
            .unwrap_or(&response)
            .trim()
            .to_string();

        let explanation = response
            .split("EXPLANATION:")
            .nth(1)
            .unwrap_or("Apply the suggested code changes to fix this vulnerability.")
            .trim()
            .to_string();

        Ok(CodeDiff {
            original: source_snippet.to_string(),
            patched,
            description: explanation,
        })
    }

    async fn chat(&self, prompt: &str) -> Result<String, AppError> {
        let url = format!("{}/chat/completions", self.config.llm_base_url);

        let body = ChatRequest {
            model: "google/gemini-2.5-flash",
            messages: vec![ChatMessage {
                role: "user",
                content: prompt,
            }],
            max_tokens: 1024,
            temperature: 0.3,
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.config.llm_api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Llm(format!("LLM request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::Llm(format!("LLM API error {}: {}", status, body)));
        }

        let result: ChatResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Llm(format!("Failed to parse LLM response: {}", e)))?;

        result
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| AppError::Llm("LLM returned no choices".into()))
    }
}
