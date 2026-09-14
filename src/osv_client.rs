//! Step 2: OSV.dev querying.
//!
//! `POST /v1/querybatch` only returns vulnerability *ids* per package (plus
//! a `modified` timestamp) — no severity, no summary. Full details require a
//! follow-up `GET /v1/vulns/{id}` per id, which this module fans out
//! concurrently via a `JoinSet` rather than sequentially.

use crate::error::Result;
use crate::models::{PackageId, Vulnerability};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

const OSV_ECOSYSTEM: &str = "crates.io";
const BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const VULN_URL: &str = "https://api.osv.dev/v1/vulns";

#[derive(Debug, Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvBatchResult>,
}

#[derive(Debug, Deserialize, Default)]
struct OsvBatchResult {
    #[serde(default)]
    vulns: Vec<OsvVulnStub>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnStub {
    id: String,
}

#[derive(Debug, Deserialize)]
struct OsvVulnDetail {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

/// Batch-queries OSV for every package in `packages`, then hydrates every
/// resulting vulnerability id with its full detail record concurrently.
pub async fn fetch_vulnerabilities_for_packages(
    client: &Client,
    packages: &[PackageId],
) -> Result<Vec<Vulnerability>> {
    if packages.is_empty() {
        return Ok(Vec::new());
    }

    let batch = OsvBatchQuery {
        queries: packages
            .iter()
            .map(|p| OsvQuery {
                package: OsvPackage {
                    name: p.name.clone(),
                    ecosystem: OSV_ECOSYSTEM.to_string(),
                },
                version: p.version.clone(),
            })
            .collect(),
    };

    let response: OsvBatchResponse = client
        .post(BATCH_URL)
        .json(&batch)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut join_set: JoinSet<Result<Vulnerability>> = JoinSet::new();
    for (pkg, result) in packages.iter().zip(response.results) {
        for stub in result.vulns {
            let client = client.clone();
            let pkg = pkg.clone();
            join_set.spawn(async move { fetch_vuln_detail(&client, &stub.id, pkg).await });
        }
    }

    let mut vulnerabilities = Vec::new();
    while let Some(joined) = join_set.join_next().await {
        // A panicked or failed detail fetch drops that one vulnerability
        // rather than failing the whole scan — OSV.dev occasionally 404s on
        // an id that was just returned by querybatch (index lag).
        if let Ok(Ok(vuln)) = joined {
            vulnerabilities.push(vuln);
        }
    }

    Ok(vulnerabilities)
}

async fn fetch_vuln_detail(client: &Client, id: &str, package: PackageId) -> Result<Vulnerability> {
    let url = format!("{VULN_URL}/{id}");
    let detail: OsvVulnDetail = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let (severity_score, raw_severity) = extract_base_severity(&detail);

    Ok(Vulnerability {
        id: detail.id,
        package,
        summary: detail.summary.unwrap_or_default(),
        severity_score,
        raw_severity,
    })
}

fn extract_base_severity(detail: &OsvVulnDetail) -> (Option<f64>, Option<String>) {
    if let Some(sev) = detail.severity.iter().find(|s| s.kind.starts_with("CVSS")) {
        return (
            parse_cvss_vector_to_base_score(&sev.score),
            Some(sev.score.clone()),
        );
    }

    if let Some(database_specific) = &detail.database_specific {
        if let Some(category) = database_specific.get("severity").and_then(|v| v.as_str()) {
            return (
                severity_category_to_score(category),
                Some(category.to_string()),
            );
        }
    }

    (None, None)
}

/// Coarse fallback for advisories that carry a category (`LOW`/`MODERATE`/
/// `HIGH`/`CRITICAL`) instead of a numeric CVSS score, using the midpoint of
/// each CVSS v3 severity band from the spec's qualitative rating table.
fn severity_category_to_score(category: &str) -> Option<f64> {
    match category.to_uppercase().as_str() {
        "CRITICAL" => Some(9.5),
        "HIGH" => Some(7.5),
        "MODERATE" | "MEDIUM" => Some(5.0),
        "LOW" => Some(2.5),
        _ => None,
    }
}

/// TODO(algorithm): parse a CVSS v3.1 vector string (e.g.
/// `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`) into its numeric base
/// score per the official formula (Impact + Exploitability sub-scores,
/// scope-changed variant) — see
/// https://www.first.org/cvss/v3.1/specification-document section 7.4.
///
/// This is the one genuinely hard algorithmic core in the ingestion path,
/// and it's the deliberate placeholder: implementing it approximately would
/// be exactly the "confident heuristic" this tool exists to avoid, so for
/// now it returns `None` and the pipeline falls back to
/// `scoring::UNSCORED_SEVERITY_PLACEHOLDER`, with the raw vector still
/// surfaced in the scorecard so nothing is hidden.
///
/// Deliberately *not* `todo!()`: most real crates.io/RUSTSEC advisories do
/// carry a CVSS vector, so panicking here would crash the CLI on the common
/// path instead of the scaffold running end-to-end with an honestly-labeled
/// gap.
fn parse_cvss_vector_to_base_score(_vector: &str) -> Option<f64> {
    None
}
