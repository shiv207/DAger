//! Thin client for Groq's OpenAI-compatible chat completions API, used only
//! as the fallback remediation path when OSV has no patched version to bump
//! to (see `remediation.rs`).
//!
//! Deliberately scoped to *mitigation guidance*, not a generated source
//! diff: v1's reachability pass (`ast_parser.rs`) is import-level, not a
//! call graph, so DAGger doesn't know the exact call site a fix would need
//! to touch. Asking an LLM to fabricate a line-level patch against context
//! it was never given is exactly the "AI slop" this tool exists to avoid —
//! so it's asked for a human-readable mitigation writeup instead, applied
//! by a person, not by DAGger.

use crate::error::{DaggerError, Result};
use crate::models::Vulnerability;
use reqwest::Client;
use serde::{Deserialize, Serialize};

const GROQ_CHAT_URL: &str = "https://api.groq.com/openai/v1/chat/completions";
/// Groq's model lineup shifts over time (see `GET /openai/v1/models` with
/// your key for what's currently live). `qwen/qwen3.8-27b` (Apache-licensed)
/// was confirmed live as of last verification, after Groq deprecated
/// `qwen/qwen3-32b` in favor of it and `qwen/qwen3.6-27b`. Override with
/// `--groq-model` if this stops resolving.
pub const DEFAULT_MODEL: &str = "qwen/qwen3.8-27b";

#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    temperature: f32,
}

#[derive(Debug, Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ChatResponseMessage {
    content: String,
}

pub async fn suggest_mitigation(
    client: &Client,
    api_key: &str,
    model: &str,
    vulnerability: &Vulnerability,
) -> Result<String> {
    let prompt = format!(
        "A Rust project depends on `{name}` version {version}, which is affected by \
         {id} (no patched version is listed in OSV yet). Advisory summary: {summary}\n\n\
         DAGger has proven this dependency is structurally reachable (it's referenced via a \
         `use` statement somewhere in the project source), but does not have the exact call \
         site. In 4-6 concise bullet points, explain: (1) the practical risk this poses in a \
         typical Rust codebase, (2) any safe mitigation short of a version bump (config change, \
         feature flag, usage pattern to avoid), and (3) whether removing/replacing this \
         dependency is a reasonable option if the crate has stopped receiving patches. Do not \
         invent specific file names, line numbers, or code you have not been shown.",
        name = vulnerability.package.name,
        version = vulnerability.package.version,
        id = vulnerability.id,
        summary = vulnerability.summary,
    );

    let request = ChatRequest {
        model,
        messages: vec![ChatMessage {
            role: "user",
            content: prompt,
        }],
        temperature: 0.2,
    };

    let response = client
        .post(GROQ_CHAT_URL)
        .bearer_auth(api_key)
        .json(&request)
        .send()
        .await?
        .error_for_status()?
        .json::<ChatResponse>()
        .await?;

    response
        .choices
        .into_iter()
        .next()
        .map(|choice| choice.message.content)
        .ok_or_else(|| DaggerError::Remediation("Groq returned no completion choices".to_string()))
}
