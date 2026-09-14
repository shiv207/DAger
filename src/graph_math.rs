//! Step 4: topological blast radius.
//!
//! PageRank over the resolved dependency graph, used as the "how structurally
//! important is this node" signal for the risk formula (`scoring.rs`).
//! PageRank rather than raw eigenvector centrality: dependency graphs are
//! directed and not guaranteed strongly connected (leaf dependencies are
//! dangling nodes), which is exactly the case PageRank's damping factor and
//! dangling-mass redistribution were designed to handle cleanly.
//!
//! `petgraph` doesn't ship a centrality implementation, so this is a
//! straightforward power-iteration PageRank rather than a stub — it's not
//! the hard part of this pipeline; CVSS vector parsing (`osv_client.rs`) is.

use crate::models::PackageNode;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use std::collections::HashMap;

pub fn pagerank(
    graph: &DiGraph<PackageNode, ()>,
    damping: f64,
    iterations: usize,
) -> HashMap<NodeIndex, f64> {
    let n = graph.node_count();
    if n == 0 {
        return HashMap::new();
    }
    let n_f64 = n as f64;

    let out_degree: HashMap<NodeIndex, usize> = graph
        .node_indices()
        .map(|i| {
            (
                i,
                graph.neighbors_directed(i, Direction::Outgoing).count(),
            )
        })
        .collect();

    let mut scores: HashMap<NodeIndex, f64> =
        graph.node_indices().map(|i| (i, 1.0 / n_f64)).collect();

    for _ in 0..iterations {
        let dangling_mass: f64 = graph
            .node_indices()
            .filter(|i| out_degree[i] == 0)
            .map(|i| scores[&i])
            .sum();

        let mut next: HashMap<NodeIndex, f64> = graph
            .node_indices()
            .map(|i| {
                let base = (1.0 - damping) / n_f64;
                let redistributed_dangling = damping * dangling_mass / n_f64;
                (i, base + redistributed_dangling)
            })
            .collect();

        for i in graph.node_indices() {
            let od = out_degree[&i];
            if od == 0 {
                continue;
            }
            let share = damping * scores[&i] / od as f64;
            for neighbor in graph.neighbors_directed(i, Direction::Outgoing) {
                *next.get_mut(&neighbor).unwrap() += share;
            }
        }

        scores = next;
    }

    scores
}

/// Rescales raw PageRank mass (which sums to ~1.0 across the whole graph) to
/// `[0, 1]` relative to the highest-scoring node, since the risk formula
/// wants "how central is this node relative to its peers," not an absolute
/// probability mass.
pub fn normalize(scores: &HashMap<NodeIndex, f64>) -> HashMap<NodeIndex, f64> {
    let max = scores.values().cloned().fold(0.0_f64, f64::max);
    if max <= 0.0 {
        return scores.clone();
    }
    scores.iter().map(|(k, v)| (*k, v / max)).collect()
}
