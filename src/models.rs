use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageId {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencyKind {
    Normal,
    Dev,
    Build,
}

/// A node in the resolved dependency graph (one per package in the
/// `cargo metadata` resolve, including the workspace root package itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageNode {
    pub id: PackageId,
    pub dependency_kind: DependencyKind,
    /// Set by `ast_parser::scan_used_crates` during the reachability pass:
    /// true if a `use`/`extern crate` referencing this package's identifier
    /// was found anywhere in the project's `.rs` files. This is the
    /// syntactic half of "reachable" (see Q7 in the design discussion) —
    /// it is not a call graph.
    pub source_used: bool,
    /// Normalized PageRank centrality (see `graph_math::normalize`), written
    /// back onto each node after `pipeline::run` computes it. Lives on the
    /// node itself (rather than a separate `HashMap<NodeIndex, f64>` the
    /// caller has to keep threading around) so anything holding the graph —
    /// the TUI's dependency-graph canvas included — has it for free.
    pub centrality: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// OSV id, e.g. `RUSTSEC-2023-0001` or a `GHSA-...` id.
    pub id: String,
    pub package: PackageId,
    pub summary: String,
    /// CVSS base score (0.0-10.0), when we could determine one. `None` if
    /// OSV gave no severity data at all, or gave a CVSS vector we don't yet
    /// parse (see `osv_client::parse_cvss_vector_to_base_score`).
    pub severity_score: Option<f64>,
    /// The raw severity string as OSV reported it (a CVSS vector, or a
    /// category like "HIGH"), kept for display even when we couldn't turn
    /// it into a number.
    pub raw_severity: Option<String>,
    /// The lowest patched version OSV's `affected[].ranges[].events` lists
    /// above the currently-resolved version, if any. Drives the version-bump
    /// remediation path — no LLM involved, this is a direct read of OSV data.
    pub fixed_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub vulnerability: Vulnerability,
    pub reachable: bool,
    pub base_severity: f64,
    pub centrality: f64,
    pub centrality_weight: f64,
    pub risk_score: f64,
}
