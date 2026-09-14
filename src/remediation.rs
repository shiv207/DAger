//! Turns a proven-reachable `RiskAssessment` into a concrete fix.
//!
//! Two tiers, tried in order (per the "version bump first" scoping
//! decision):
//! 1. **Version bump** — if OSV lists a patched version (`osv_client`
//!    already extracted this deterministically), that's the fix. Fully
//!    mechanical, no LLM involved, and the only tier this module will
//!    write to disk.
//! 2. **Mitigation suggestion** — if no patched version exists yet, ask
//!    Groq for human-readable guidance (`groq_client`). This is advisory
//!    only: DAGger never auto-applies LLM-generated code, because v1's
//!    reachability pass doesn't have the call-site precision to ground a
//!    real patch (see the module doc on `groq_client`).

use crate::error::Result;
use crate::models::RiskAssessment;
use reqwest::Client;
use std::path::{Path, PathBuf};
use toml_edit::{value, DocumentMut, Item};

#[derive(Debug, Clone)]
pub enum FixKind {
    VersionBump {
        package: String,
        from_version: String,
        to_version: String,
    },
    MitigationSuggestion {
        explanation: String,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct ProposedFix {
    pub kind: FixKind,
}

impl ProposedFix {
    /// True only for fixes this module knows how to write to disk itself.
    pub fn is_auto_applicable(&self) -> bool {
        matches!(self.kind, FixKind::VersionBump { .. })
    }

    pub fn display_lines(&self) -> Vec<String> {
        match &self.kind {
            FixKind::VersionBump {
                package,
                from_version,
                to_version,
            } => vec![
                "Version bump available (from OSV, no LLM involved):".to_string(),
                format!("  {package} {from_version} -> {to_version}"),
                String::new(),
                "Applying will edit Cargo.toml and run `cargo update`.".to_string(),
            ],
            FixKind::MitigationSuggestion { explanation } => {
                let mut lines = vec![
                    "No patched version listed yet. Groq-suggested mitigation".to_string(),
                    "(advisory only — review before acting, not auto-applied):".to_string(),
                    String::new(),
                ];
                lines.extend(explanation.lines().map(|l| l.to_string()));
                lines
            }
            FixKind::Unavailable { reason } => vec![format!("No fix available: {reason}")],
        }
    }
}

/// Tier 1 only, synchronous, no network call — `fixed_version` was already
/// pulled from OSV during ingestion. Returns `None` when a version bump
/// isn't possible, so the caller knows to fall through to Groq.
pub fn propose_version_bump(assessment: &RiskAssessment) -> Option<ProposedFix> {
    let to_version = assessment.vulnerability.fixed_version.clone()?;
    Some(ProposedFix {
        kind: FixKind::VersionBump {
            package: assessment.vulnerability.package.name.clone(),
            from_version: assessment.vulnerability.package.version.clone(),
            to_version,
        },
    })
}

/// Tier 2: only called when tier 1 returns `None`.
pub async fn propose_mitigation_via_groq(
    client: &Client,
    api_key: &str,
    model: &str,
    assessment: &RiskAssessment,
) -> ProposedFix {
    match crate::groq_client::suggest_mitigation(client, api_key, model, &assessment.vulnerability)
        .await
    {
        Ok(explanation) => ProposedFix {
            kind: FixKind::MitigationSuggestion { explanation },
        },
        Err(err) => ProposedFix {
            kind: FixKind::Unavailable {
                reason: format!("Groq request failed: {err}"),
            },
        },
    }
}

/// Applies a `VersionBump` fix: edits Cargo.toml in place (preserving
/// formatting/comments via `toml_edit`), then shells out to
/// `cargo update -p <package> --precise <version>` to refresh Cargo.lock.
/// Returns an error (never panics) if the fix isn't actually a VersionBump —
/// callers should check `is_auto_applicable()` first.
pub async fn apply_version_bump(project_path: &Path, fix: &ProposedFix) -> Result<String> {
    let FixKind::VersionBump {
        package,
        to_version,
        ..
    } = &fix.kind
    else {
        return Err(crate::error::DaggerError::Remediation(
            "apply_version_bump called on a non-version-bump fix".to_string(),
        ));
    };

    let manifest_path: PathBuf = project_path.join("Cargo.toml");
    let raw = tokio::fs::read_to_string(&manifest_path).await?;
    let mut doc: DocumentMut = raw
        .parse()
        .map_err(|e| crate::error::DaggerError::Remediation(format!("failed to parse Cargo.toml: {e}")))?;

    let updated = set_dependency_version(&mut doc, package, to_version);
    if !updated {
        return Err(crate::error::DaggerError::Remediation(format!(
            "could not find `{package}` in [dependencies]/[dev-dependencies]/[build-dependencies]"
        )));
    }

    tokio::fs::write(&manifest_path, doc.to_string()).await?;

    let output = tokio::process::Command::new("cargo")
        .arg("update")
        .arg("-p")
        .arg(package)
        .arg("--precise")
        .arg(to_version)
        .current_dir(project_path)
        .output()
        .await?;

    if !output.status.success() {
        return Err(crate::error::DaggerError::Remediation(format!(
            "Cargo.toml updated, but `cargo update` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(format!("{package} -> {to_version} (Cargo.toml + Cargo.lock updated)"))
}

fn set_dependency_version(doc: &mut DocumentMut, package: &str, new_version: &str) -> bool {
    for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = doc.get_mut(table_name).and_then(Item::as_table_like_mut) else {
            continue;
        };
        let Some(entry) = table.get_mut(package) else {
            continue;
        };

        if entry.is_str() {
            *entry = value(new_version);
            return true;
        }
        if let Some(inline) = entry.as_inline_table_mut() {
            inline.insert("version", new_version.into());
            return true;
        }
        if let Some(dep_table) = entry.as_table_like_mut() {
            dep_table.insert("version", value(new_version));
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bumps_a_bare_string_dependency() {
        let mut doc: DocumentMut = "[dependencies]\nserde = \"1.0\"\n".parse().unwrap();
        assert!(set_dependency_version(&mut doc, "serde", "1.0.219"));
        assert!(doc.to_string().contains("serde = \"1.0.219\""));
    }

    #[test]
    fn bumps_an_inline_table_dependency_and_keeps_other_keys() {
        let mut doc: DocumentMut =
            "[dependencies]\ntokio = { version = \"1\", features = [\"full\"] }\n"
                .parse()
                .unwrap();
        assert!(set_dependency_version(&mut doc, "tokio", "1.40.0"));
        let rendered = doc.to_string();
        assert!(rendered.contains("version = \"1.40.0\""));
        assert!(rendered.contains("\"full\""));
    }

    #[test]
    fn checks_dev_and_build_dependencies_too() {
        let mut doc: DocumentMut = "[dev-dependencies]\nproptest = \"1\"\n".parse().unwrap();
        assert!(set_dependency_version(&mut doc, "proptest", "1.5.0"));
        assert!(doc.to_string().contains("proptest = \"1.5.0\""));
    }

    #[test]
    fn returns_false_for_a_dependency_that_is_not_present() {
        let mut doc: DocumentMut = "[dependencies]\nserde = \"1.0\"\n".parse().unwrap();
        assert!(!set_dependency_version(&mut doc, "not-a-real-crate", "1.0.0"));
    }
}
