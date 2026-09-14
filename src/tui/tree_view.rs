//! Renders the resolved dependency graph as an indented tree (the same
//! mental model `cargo tree` uses) instead of a 2D dot-scatter — a text
//! tree with real connectors is legible on any terminal at any size and
//! matches how Rust developers already read dependency structure; a
//! force-directed graph squeezed into a Canvas of braille dots does not.
//!
//! Deduplication follows `cargo tree`'s convention: a package is fully
//! expanded the first time it's reached, and every later encounter (shared
//! by multiple parents, which is the overwhelmingly common case in a real
//! dependency graph) renders as a leaf marked `(*)` instead of re-expanding
//! its whole subtree again. Without this, a graph with heavy fan-in to a
//! handful of common crates would blow up combinatorially.

use crate::models::PackageNode;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Safe,
    VulnerableUnreachable,
    VulnerableReachable,
}

fn status_rank(status: NodeStatus) -> u8 {
    match status {
        NodeStatus::VulnerableReachable => 0,
        NodeStatus::VulnerableUnreachable => 1,
        NodeStatus::Safe => 2,
    }
}

fn classify(name: &str, vulnerable_names: &HashSet<String>, reachable_vulnerable_names: &HashSet<String>) -> NodeStatus {
    if reachable_vulnerable_names.contains(name) {
        NodeStatus::VulnerableReachable
    } else if vulnerable_names.contains(name) {
        NodeStatus::VulnerableUnreachable
    } else {
        NodeStatus::Safe
    }
}

#[derive(Debug, Clone)]
pub struct TreeLine {
    /// Pre-built connector prefix, e.g. "│   ├── " — ready to render as-is.
    pub prefix: String,
    pub name: String,
    pub version: String,
    pub status: NodeStatus,
    pub centrality: f64,
    /// True if this package was already expanded earlier in the tree; this
    /// line is a leaf marker (`(*)`), not a re-expansion of its subtree.
    pub is_repeat: bool,
}

/// Builds the full tree. Vulnerability status lives on `RiskAssessment`,
/// not `PackageNode`, so the caller classifies nodes by package name via
/// the two sets (same contract as the old `graph_view::layout`).
pub fn build_tree(
    graph: &DiGraph<PackageNode, ()>,
    vulnerable_names: &HashSet<String>,
    reachable_vulnerable_names: &HashSet<String>,
) -> Vec<TreeLine> {
    let mut roots: Vec<NodeIndex> = graph
        .node_indices()
        .filter(|&i| graph.neighbors_directed(i, Direction::Incoming).count() == 0)
        .collect();

    // Cargo dependency graphs are DAGs in practice, so this should never be
    // empty for a non-empty graph — but fail safe rather than render
    // nothing if a degenerate/cyclic graph ever has no clear root.
    if roots.is_empty() && graph.node_count() > 0 {
        roots = graph.node_indices().collect();
    }
    roots.sort_by_key(|&i| graph[i].id.name.clone());

    let mut visited = HashSet::new();
    let mut lines = Vec::new();
    let n_roots = roots.len();
    for (i, root) in roots.into_iter().enumerate() {
        walk(
            graph,
            root,
            "",
            i + 1 == n_roots,
            true,
            &mut visited,
            &mut lines,
            vulnerable_names,
            reachable_vulnerable_names,
        );
    }
    lines
}

#[allow(clippy::too_many_arguments)]
fn walk(
    graph: &DiGraph<PackageNode, ()>,
    idx: NodeIndex,
    ancestor_prefix: &str,
    is_last: bool,
    is_root: bool,
    visited: &mut HashSet<NodeIndex>,
    lines: &mut Vec<TreeLine>,
    vulnerable_names: &HashSet<String>,
    reachable_vulnerable_names: &HashSet<String>,
) {
    let node = &graph[idx];
    let status = classify(&node.id.name, vulnerable_names, reachable_vulnerable_names);
    let connector = if is_root {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };
    let is_repeat = !visited.insert(idx);

    lines.push(TreeLine {
        prefix: format!("{ancestor_prefix}{connector}"),
        name: node.id.name.clone(),
        version: node.id.version.clone(),
        status,
        centrality: node.centrality,
        is_repeat,
    });

    if is_repeat {
        return;
    }

    let mut children: Vec<NodeIndex> = graph.neighbors_directed(idx, Direction::Outgoing).collect();
    children.sort_by_key(|&i| {
        let n = &graph[i];
        let s = classify(&n.id.name, vulnerable_names, reachable_vulnerable_names);
        (status_rank(s), n.id.name.clone())
    });

    let child_prefix = format!(
        "{ancestor_prefix}{}",
        if is_root {
            ""
        } else if is_last {
            "    "
        } else {
            "│   "
        }
    );

    let n_children = children.len();
    for (i, child) in children.into_iter().enumerate() {
        walk(
            graph,
            child,
            &child_prefix,
            i + 1 == n_children,
            false,
            visited,
            lines,
            vulnerable_names,
            reachable_vulnerable_names,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DependencyKind, PackageId};

    fn node(name: &str) -> PackageNode {
        PackageNode {
            id: PackageId {
                name: name.to_string(),
                version: "1.0.0".to_string(),
            },
            dependency_kind: DependencyKind::Normal,
            source_used: true,
            centrality: 0.0,
        }
    }

    #[test]
    fn simple_chain_renders_with_correct_connectors() {
        let mut graph = DiGraph::new();
        let root = graph.add_node(node("root"));
        let child = graph.add_node(node("child"));
        let grandchild = graph.add_node(node("grandchild"));
        graph.add_edge(root, child, ());
        graph.add_edge(child, grandchild, ());

        let lines = build_tree(&graph, &HashSet::new(), &HashSet::new());

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].prefix, "");
        assert_eq!(lines[0].name, "root");
        assert_eq!(lines[1].prefix, "└── ");
        assert_eq!(lines[1].name, "child");
        assert_eq!(lines[2].prefix, "    └── ");
        assert_eq!(lines[2].name, "grandchild");
    }

    #[test]
    fn shared_dependency_expands_once_and_repeats_as_a_marked_leaf() {
        // root -> a -> shared
        // root -> b -> shared
        let mut graph = DiGraph::new();
        let root = graph.add_node(node("root"));
        let a = graph.add_node(node("a"));
        let b = graph.add_node(node("b"));
        let shared = graph.add_node(node("shared"));
        graph.add_edge(root, a, ());
        graph.add_edge(root, b, ());
        graph.add_edge(a, shared, ());
        graph.add_edge(b, shared, ());

        let lines = build_tree(&graph, &HashSet::new(), &HashSet::new());

        // root, a, shared (expanded under a), b, shared (repeat under b) = 5 lines,
        // never more — this is the regression a naive full-expansion walk
        // would blow up on with heavy fan-in.
        assert_eq!(lines.len(), 5);
        let shared_lines: Vec<&TreeLine> = lines.iter().filter(|l| l.name == "shared").collect();
        assert_eq!(shared_lines.len(), 2);
        assert!(!shared_lines[0].is_repeat, "first encounter should expand");
        assert!(shared_lines[1].is_repeat, "second encounter should be marked a repeat");
    }

    #[test]
    fn vulnerable_reachable_siblings_sort_before_safe_siblings() {
        let mut graph = DiGraph::new();
        let root = graph.add_node(node("root"));
        let safe = graph.add_node(node("aaa-safe"));
        let vulnerable = graph.add_node(node("zzz-vulnerable"));
        graph.add_edge(root, safe, ());
        graph.add_edge(root, vulnerable, ());

        let reachable = HashSet::from(["zzz-vulnerable".to_string()]);
        let lines = build_tree(&graph, &reachable, &reachable);

        // Alphabetically "aaa-safe" would sort first; vulnerability status
        // must win so the interesting node isn't scrolled off-screen.
        assert_eq!(lines[1].name, "zzz-vulnerable");
        assert_eq!(lines[1].status, NodeStatus::VulnerableReachable);
        assert_eq!(lines[2].name, "aaa-safe");
    }

    #[test]
    fn empty_graph_produces_no_lines_without_panicking() {
        let graph: DiGraph<PackageNode, ()> = DiGraph::new();
        let lines = build_tree(&graph, &HashSet::new(), &HashSet::new());
        assert!(lines.is_empty());
    }
}
