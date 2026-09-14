//! Chat panel: live Q&A with the configured Groq model, grounded in
//! DAGger's actual findings for the current run — not generic chit-chat.
//! `build_system_prompt` is rebuilt fresh on every send from the live
//! `App` state, so "what's wrong" always reflects the real vulnerability
//! list, never a stale snapshot from when the chat was first opened.

use super::App;
use crate::groq_client::Role;

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: Role,
    pub content: String,
}

#[derive(Default)]
pub struct ChatState {
    pub open: bool,
    pub input: String,
    pub messages: Vec<ChatMessage>,
    pub in_flight: bool,
}

/// Grounds the model in what DAGger actually found and how its own numbers
/// are computed, and is explicit about the tool's real limits (import-level
/// reachability, not a call graph) so it doesn't fabricate precision DAGger
/// doesn't have.
pub fn build_system_prompt(app: &App) -> String {
    let weight = app
        .assessments
        .first()
        .map(|a| a.centrality_weight)
        .unwrap_or(0.5);

    let mut prompt = format!(
        "You are embedded inside DAGger, a Rust CLI/TUI tool the user is running right now. \
         Explain things in super simple, plain words with no jargon — the user explicitly asked \
         for this. Ground every answer in the ACTUAL data below; never invent file names, line \
         numbers, or vulnerabilities that aren't listed.\n\n\
         How DAGger's risk score works: risk = base_severity * reachable(1 or 0) * (1 + {weight} * centrality). \
         'reachable' means the vulnerable crate is actually referenced somewhere in this project's \
         source code via a `use` statement (not just listed as a dependency) — this is a \
         syntactic check, not a full call graph, so DAGger cannot point to an exact vulnerable \
         line or function; say so plainly if asked for that instead of guessing. 'centrality' is \
         PageRank over the dependency graph — how structurally important that package is.\n\n\
         Current run: {found} vulnerabilities found, {exploitable} proven exploitable (reachable).\n\n",
        found = app.total_found,
        exploitable = app.exploitable_count(),
    );

    if app.assessments.is_empty() {
        prompt.push_str("No vulnerabilities were found in this run.\n");
    } else {
        prompt.push_str("Vulnerabilities found:\n");
        for a in &app.assessments {
            prompt.push_str(&format!(
                "- {id} in {pkg}@{ver}: reachable={reachable}, risk_score={risk:.2}, fixed_version={fixed}, summary: {summary}\n",
                id = a.vulnerability.id,
                pkg = a.vulnerability.package.name,
                ver = a.vulnerability.package.version,
                reachable = a.reachable,
                risk = a.risk_score,
                fixed = a.vulnerability.fixed_version.as_deref().unwrap_or("none listed"),
                summary = a.vulnerability.summary,
            ));
        }
    }

    prompt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{PackageId, RiskAssessment, Vulnerability};

    fn assessment(name: &str, reachable: bool) -> RiskAssessment {
        RiskAssessment {
            vulnerability: Vulnerability {
                id: "RUSTSEC-TEST-0001".to_string(),
                package: PackageId {
                    name: name.to_string(),
                    version: "1.2.3".to_string(),
                },
                summary: "a made-up test advisory".to_string(),
                severity_score: Some(7.0),
                raw_severity: None,
                fixed_version: Some("1.2.4".to_string()),
            },
            reachable,
            base_severity: 7.0,
            centrality: 0.4,
            centrality_weight: 0.5,
            risk_score: if reachable { 8.4 } else { 0.0 },
        }
    }

    #[test]
    fn includes_every_finding_by_id_and_package() {
        let mut app = App::new();
        app.total_found = 1;
        app.assessments = vec![assessment("lru", true)];

        let prompt = build_system_prompt(&app);
        assert!(prompt.contains("RUSTSEC-TEST-0001"));
        assert!(prompt.contains("lru@1.2.3"));
        assert!(prompt.contains("reachable=true"));
    }

    #[test]
    fn explains_the_real_formula_not_a_placeholder() {
        let app = App::new();
        let prompt = build_system_prompt(&app);
        assert!(prompt.contains("base_severity"));
        assert!(prompt.contains("PageRank"));
    }

    #[test]
    fn says_plainly_when_nothing_was_found_instead_of_fabricating() {
        let app = App::new();
        let prompt = build_system_prompt(&app);
        assert!(prompt.contains("No vulnerabilities were found"));
    }
}
