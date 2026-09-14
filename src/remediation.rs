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

    match set_dependency_version(&mut doc, package, to_version) {
        SetVersionOutcome::Updated => {}
        SetVersionOutcome::NotFound => {
            return Err(crate::error::DaggerError::Remediation(format!(
                "could not find `{package}` in [dependencies]/[dev-dependencies]/[build-dependencies]"
            )));
        }
        SetVersionOutcome::WorkspaceInherited => {
            return Err(crate::error::DaggerError::Remediation(format!(
                "`{package}` is inherited from [workspace.dependencies] in this manifest — \
                 bump it in the workspace root's Cargo.toml instead"
            )));
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetVersionOutcome {
    Updated,
    /// Found the dependency, but it inherits from `[workspace.dependencies]`
    /// (`{ workspace = true }`) — writing `version` into it alongside
    /// `workspace = true` produces invalid Cargo.toml that `cargo update`
    /// then rejects, so this is refused rather than attempted. The real fix
    /// belongs in the workspace root's Cargo.toml, which this function
    /// doesn't have access to (`apply_version_bump` only opens the manifest
    /// at the analyzed project's own path).
    WorkspaceInherited,
    NotFound,
}

/// `package` is `RiskAssessment.vulnerability.package.name` — the
/// crates.io/OSV canonical crate name — which is not always the manifest
/// key: a renamed dependency (`lru_cache = { package = "lru", version =
/// "0.12.5" }`) keys the table by the local alias, not the crate name. So
/// lookup tries the direct key first (the common case, and the only shape
/// a plain string dependency can have), then falls back to scanning each
/// table's entries for an explicit `package = "..."` field matching.
fn set_dependency_version(doc: &mut DocumentMut, package: &str, new_version: &str) -> SetVersionOutcome {
    for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = doc.get_mut(table_name).and_then(Item::as_table_like_mut) else {
            continue;
        };

        if let Some(entry) = table.get_mut(package) {
            let outcome = write_version_into(entry, new_version);
            if outcome != SetVersionOutcome::NotFound {
                return outcome;
            }
        }

        for (_key, entry) in table.iter_mut() {
            let renamed_from = entry
                .as_table_like()
                .and_then(|t| t.get("package"))
                .and_then(|v| v.as_str());
            if renamed_from == Some(package) {
                return write_version_into(entry, new_version);
            }
        }
    }
    SetVersionOutcome::NotFound
}

/// Writes `new_version` into an already-located dependency entry, refusing
/// (rather than corrupting) a workspace-inherited one.
fn write_version_into(entry: &mut Item, new_version: &str) -> SetVersionOutcome {
    if entry
        .as_table_like()
        .and_then(|t| t.get("workspace"))
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return SetVersionOutcome::WorkspaceInherited;
    }

    if entry.is_str() {
        *entry = value(new_version);
        return SetVersionOutcome::Updated;
    }
    if let Some(inline) = entry.as_inline_table_mut() {
        inline.insert("version", new_version.into());
        return SetVersionOutcome::Updated;
    }
    if let Some(dep_table) = entry.as_table_like_mut() {
        dep_table.insert("version", value(new_version));
        return SetVersionOutcome::Updated;
    }
    SetVersionOutcome::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bumps_a_bare_string_dependency() {
        let mut doc: DocumentMut = "[dependencies]\nserde = \"1.0\"\n".parse().unwrap();
        assert_eq!(set_dependency_version(&mut doc, "serde", "1.0.219"), SetVersionOutcome::Updated);
        assert!(doc.to_string().contains("serde = \"1.0.219\""));
    }

    #[test]
    fn bumps_an_inline_table_dependency_and_keeps_other_keys() {
        let mut doc: DocumentMut =
            "[dependencies]\ntokio = { version = \"1\", features = [\"full\"] }\n"
                .parse()
                .unwrap();
        assert_eq!(set_dependency_version(&mut doc, "tokio", "1.40.0"), SetVersionOutcome::Updated);
        let rendered = doc.to_string();
        assert!(rendered.contains("version = \"1.40.0\""));
        assert!(rendered.contains("\"full\""));
    }

    #[test]
    fn checks_dev_and_build_dependencies_too() {
        let mut doc: DocumentMut = "[dev-dependencies]\nproptest = \"1\"\n".parse().unwrap();
        assert_eq!(set_dependency_version(&mut doc, "proptest", "1.5.0"), SetVersionOutcome::Updated);
        assert!(doc.to_string().contains("proptest = \"1.5.0\""));
    }

    #[test]
    fn returns_not_found_for_a_dependency_that_is_not_present() {
        let mut doc: DocumentMut = "[dependencies]\nserde = \"1.0\"\n".parse().unwrap();
        assert_eq!(
            set_dependency_version(&mut doc, "not-a-real-crate", "1.0.0"),
            SetVersionOutcome::NotFound
        );
    }

    /// Regression test for the reported bug: pressing `f`/`y` showed a
    /// message but left the manifest untouched. Root cause — lookup was by
    /// manifest key only, but `RiskAssessment.vulnerability.package.name` is
    /// the crates.io/OSV canonical name, which a renamed dependency
    /// (`lru_cache = { package = "lru", ... }`) doesn't share with its key.
    #[test]
    fn bumps_a_renamed_dependency_by_its_crates_io_name() {
        let mut doc: DocumentMut =
            "[dependencies]\nlru_cache = { package = \"lru\", version = \"0.12.5\" }\n"
                .parse()
                .unwrap();
        assert_eq!(set_dependency_version(&mut doc, "lru", "0.16.3"), SetVersionOutcome::Updated);
        let rendered = doc.to_string();
        assert!(rendered.contains("version = \"0.16.3\""), "manifest was not bumped:\n{rendered}");
        assert!(rendered.contains("package = \"lru\""), "rename should be preserved:\n{rendered}");
        assert!(rendered.contains("lru_cache ="), "manifest key (alias) must not change:\n{rendered}");
    }

    /// A workspace-inherited dependency can't be bumped in the member's own
    /// Cargo.toml — the version lives in the workspace root's
    /// `[workspace.dependencies]`, which `apply_version_bump` doesn't have
    /// (it only opens the analyzed project's own manifest). Refusing must
    /// leave the manifest byte-for-byte unchanged rather than writing an
    /// invalid `{ workspace = true, version = "..." }` that `cargo update`
    /// would then reject.
    #[test]
    fn refuses_a_workspace_inherited_dependency_without_corrupting_it() {
        let original = "[dependencies]\nlru = { workspace = true }\n";
        let mut doc: DocumentMut = original.parse().unwrap();
        assert_eq!(
            set_dependency_version(&mut doc, "lru", "0.16.3"),
            SetVersionOutcome::WorkspaceInherited
        );
        assert_eq!(doc.to_string(), original, "manifest must be left untouched when the bump is refused");
    }

    /// Real end-to-end check of `apply_version_bump`: writes a throwaway
    /// fixture project to the OS temp dir (never the DAGger repo itself),
    /// applies a real version bump, and confirms both Cargo.toml and
    /// Cargo.lock actually changed on disk. Ignored by default since it
    /// shells out to `cargo update` (network + crates.io index) — run with
    /// `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "hits the network via `cargo update`; run explicitly with `cargo test -- --ignored`"]
    async fn apply_version_bump_against_a_scratch_project() {
        let dir = std::env::temp_dir().join(format!(
            "dagger-remediation-fixture-{}",
            std::process::id()
        ));
        tokio::fs::create_dir_all(dir.join("src")).await.unwrap();
        tokio::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nlru = \"0.12.5\"\n",
        )
        .await
        .unwrap();
        tokio::fs::write(dir.join("src/main.rs"), "fn main() {}\n")
            .await
            .unwrap();

        let fix = ProposedFix {
            kind: FixKind::VersionBump {
                package: "lru".to_string(),
                from_version: "0.12.5".to_string(),
                to_version: "0.16.3".to_string(),
            },
        };

        let result = apply_version_bump(&dir, &fix).await;
        assert!(result.is_ok(), "apply_version_bump failed: {:?}", result.err());

        let updated_manifest = tokio::fs::read_to_string(dir.join("Cargo.toml")).await.unwrap();
        assert!(updated_manifest.contains("0.16.3"), "manifest was not bumped:\n{updated_manifest}");
        assert!(dir.join("Cargo.lock").exists(), "cargo update did not produce a lockfile");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
