//! Orchestrates steps 1-5 end to end. Shared by both the plain CLI report
//! path and the TUI, so the two interfaces can never disagree about what
//! the pipeline actually computed.

use crate::error::Result;
use crate::models::{PackageId, PackageNode, RiskAssessment};
use crate::{ast_parser, graph_math, ingestion, osv_client, scoring};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;
use std::path::PathBuf;

pub struct PipelineConfig {
    pub project_path: PathBuf,
    pub centrality_weight: f64,
}

pub struct PipelineOutput {
    // Kept on the output (not just consumed internally) for the real
    // force-directed graph layout that will replace the TUI canvas
    // placeholder in tui/ui.rs — not wired up to anything yet.
    #[allow(dead_code)]
    pub graph: DiGraph<PackageNode, ()>,
    pub assessments: Vec<RiskAssessment>,
    pub total_vulns_found: usize,
}

pub async fn run(config: &PipelineConfig, mut log: impl FnMut(&str)) -> Result<PipelineOutput> {
    log("[OK] Reading cargo metadata...");
    let (mut graph, source_root) = ingestion::build_dependency_graph(&config.project_path)?;
    log(&format!(
        "[OK] Resolved {} packages in the dependency graph.",
        graph.node_count()
    ));

    log("[EXEC] Tracing use-declarations for reachability...");
    let used_crates = ast_parser::scan_used_crates(&source_root)?;
    for idx in graph.node_indices().collect::<Vec<_>>() {
        let normalized_ident = graph[idx].id.name.replace('-', "_");
        graph[idx].source_used = used_crates.contains(&normalized_ident);
    }

    log("[EXEC] Querying OSV.dev for known vulnerabilities...");
    let client = reqwest::Client::new();
    let package_ids: Vec<PackageId> = graph.node_weights().map(|n| n.id.clone()).collect();
    let vulnerabilities = osv_client::fetch_vulnerabilities_for_packages(&client, &package_ids).await?;
    let total_vulns_found = vulnerabilities.len();
    log(&format!(
        "[OK] OSV.dev returned {total_vulns_found} known vulnerabilities."
    ));

    log("[EXEC] Computing PageRank centrality over the dependency graph...");
    let raw_scores = graph_math::pagerank(&graph, 0.85, 50);
    let normalized_scores = graph_math::normalize(&raw_scores);

    log("[EXEC] Scoring reachable vulnerabilities...");
    let index_by_name: HashMap<String, NodeIndex> = graph
        .node_indices()
        .map(|i| (graph[i].id.name.clone(), i))
        .collect();

    let mut assessments: Vec<RiskAssessment> = vulnerabilities
        .iter()
        .map(|vuln| {
            let (reachable, centrality) = match index_by_name.get(&vuln.package.name) {
                Some(&idx) => (
                    graph[idx].source_used,
                    *normalized_scores.get(&idx).unwrap_or(&0.0),
                ),
                None => (false, 0.0),
            };
            scoring::compute_risk_score(vuln, reachable, centrality, config.centrality_weight)
        })
        .collect();

    assessments.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let exploitable = assessments.iter().filter(|a| a.reachable).count();
    log(&format!(
        "[DONE] {total_vulns_found} found -> {exploitable} proven exploitable."
    ));

    Ok(PipelineOutput {
        graph,
        assessments,
        total_vulns_found,
    })
}
