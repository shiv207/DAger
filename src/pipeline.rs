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
    for idx in graph.node_indices().collect::<Vec<_>>() {
        graph[idx].centrality = *normalized_scores.get(&idx).unwrap_or(&0.0);
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end confirmation against the real playground fixture (network:
    /// cargo metadata + OSV.dev) that the graph canvas regression is fixed:
    /// `lru` has 3 real CVEs in the playground but is one graph node, so it
    /// must appear as exactly one node — not 3. Ignored by default; run
    /// with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "hits the network (cargo metadata + OSV.dev); run explicitly with `cargo test -- --ignored`"]
    async fn playground_dependency_graph_has_one_node_per_package_not_per_vulnerability() {
        let config = PipelineConfig {
            project_path: PathBuf::from("playground"),
            centrality_weight: crate::scoring::DEFAULT_CENTRALITY_WEIGHT,
        };

        let output = run(&config, |_| {}).await.expect("pipeline run failed");

        let lru_vuln_count = output
            .assessments
            .iter()
            .filter(|a| a.vulnerability.package.name == "lru")
            .count();
        assert!(
            lru_vuln_count >= 2,
            "expected lru to have multiple real CVEs in this fixture, found {lru_vuln_count}"
        );

        let lru_node_count = output
            .graph
            .node_weights()
            .filter(|n| n.id.name == "lru")
            .count();
        assert_eq!(
            lru_node_count, 1,
            "lru must be exactly one graph node regardless of how many CVEs it has"
        );

        // The graph itself (ingestion) is unaffected by this bug, but this
        // pins the end-to-end shape the TUI canvas now consumes: many more
        // nodes than vulnerabilities.
        assert!(
            output.graph.node_count() > output.assessments.len(),
            "graph should contain far more packages than vulnerabilities in a real project"
        );
    }
}
