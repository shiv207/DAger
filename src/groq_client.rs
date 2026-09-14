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

/// A chat turn's speaker. `System` primes the model with context (DAGger's
/// live findings, in the chat panel's case) and is never shown in the UI as
/// a message of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    System,
    User,
    Assistant,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
        }
    }
}

#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<WireMessage<'a>>,
    temperature: f32,
}

#[derive(Debug, Serialize)]
struct WireMessage<'a> {
    role: &'a str,
    content: &'a str,
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

    chat_completion(client, api_key, model, &[(Role::User, prompt)], 0.2).await
}

/// General multi-turn chat, used both by `suggest_mitigation` (a single
/// user turn) and the TUI's interactive chat panel (`tui/chat.rs`, a full
/// running history with a system turn rebuilt fresh on every call so it
/// always reflects live app state).
pub async fn chat_completion(
    client: &Client,
    api_key: &str,
    model: &str,
    messages: &[(Role, String)],
    temperature: f32,
) -> Result<String> {
    let request = ChatRequest {
        model,
        messages: messages
            .iter()
            .map(|(role, content)| WireMessage {
                role: role.as_str(),
                content,
            })
            .collect(),
        temperature,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PackageId;

    /// Real call against the live Groq API using GROQ_API_KEY from the
    /// environment (or a local .env). Ignored by default so `cargo test`
    /// stays offline and doesn't require a key; run explicitly with
    /// `cargo test -- --ignored` when you want to verify the current
    /// DEFAULT_MODEL is still live and actually returns usable content.
    #[tokio::test]
    #[ignore = "hits the live Groq API; requires GROQ_API_KEY; run with `cargo test -- --ignored`"]
    async fn suggest_mitigation_returns_real_content() {
        let _ = dotenvy::dotenv();
        let api_key = std::env::var("GROQ_API_KEY")
            .expect("GROQ_API_KEY must be set (env var or .env) to run this test");

        let vulnerability = Vulnerability {
            id: "RUSTSEC-2026-0002".to_string(),
            package: PackageId {
                name: "lru".to_string(),
                version: "0.12.5".to_string(),
            },
            summary: "IterMut violates Stacked Borrows by invalidating internal pointer".to_string(),
            severity_score: None,
            raw_severity: None,
            fixed_version: None,
        };

        let client = Client::new();
        let content = suggest_mitigation(&client, &api_key, DEFAULT_MODEL, &vulnerability)
            .await
            .expect("Groq request failed");

        assert!(
            !content.trim().is_empty(),
            "Groq returned an empty completion — likely a max_tokens/reasoning-budget issue"
        );
    }
}
