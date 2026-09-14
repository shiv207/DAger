//! Step 1: Ingestion.
//!
//! Builds the in-memory dependency graph from `cargo metadata` rather than
//! hand-parsing `Cargo.lock`. `cargo metadata` runs Cargo's own resolver, so
//! the graph (including feature-gated and dev/build dependency edges) is
//! provably correct instead of a reimplementation of semver/feature
//! resolution guessed at from the lockfile TOML.

use crate::error::Result;
use crate::models::{DependencyKind, PackageId, PackageNode};
use cargo_metadata::{DependencyKind as CmDependencyKind, MetadataCommand};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Returns the resolved dependency graph and the directory that should be
/// treated as the project's source root for the reachability pass.
pub fn build_dependency_graph(project_path: &Path) -> Result<(DiGraph<PackageNode, ()>, PathBuf)> {
    let manifest_path = project_path.join("Cargo.toml");

    let metadata = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .exec()?;

    let mut graph: DiGraph<PackageNode, ()> = DiGraph::new();
    let mut index_by_id: HashMap<cargo_metadata::PackageId, NodeIndex> = HashMap::new();

    for package in &metadata.packages {
        let node = PackageNode {
            id: PackageId {
                name: package.name.clone(),
                version: package.version.to_string(),
            },
            // Refined below once we've walked the resolve graph's edges;
            // defaults to Normal for the root package (which has none).
            dependency_kind: DependencyKind::Normal,
            source_used: false,
            centrality: 0.0,
        };
        let idx = graph.add_node(node);
        index_by_id.insert(package.id.clone(), idx);
    }

    if let Some(resolve) = &metadata.resolve {
        for node in &resolve.nodes {
            let Some(&from_idx) = index_by_id.get(&node.id) else {
                continue;
            };
            for dep in &node.deps {
                let Some(&to_idx) = index_by_id.get(&dep.pkg) else {
                    continue;
                };
                let kind = dep
                    .dep_kinds
                    .first()
                    .map(|k| match k.kind {
                        CmDependencyKind::Normal => DependencyKind::Normal,
                        CmDependencyKind::Development => DependencyKind::Dev,
                        CmDependencyKind::Build => DependencyKind::Build,
                        _ => DependencyKind::Normal,
                    })
                    .unwrap_or(DependencyKind::Normal);
                graph[to_idx].dependency_kind = kind;
                graph.add_edge(from_idx, to_idx, ());
            }
        }
    }

    // v1 scans the whole workspace root for source files rather than just
    // the root package's `src/`, so dependencies only used from
    // `tests/`/`benches/`/`examples/` (or other workspace members) are
    // still picked up by the reachability pass.
    let source_root = metadata.workspace_root.as_std_path().to_path_buf();

    Ok((graph, source_root))
}
