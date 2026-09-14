//! Step 3 (source half): reachability via a syntactic `use`-declaration scan.
//!
//! This is deliberately **not** a call graph. `tree-sitter` gives us a
//! syntax tree with no type resolution, no macro expansion, and no
//! trait-dispatch information — building a real function-level call graph
//! on top of that would be exactly the kind of confident-but-wrong
//! heuristic this tool exists to avoid. Instead this module answers a
//! narrower, fully syntactic question: "does any `use` or `extern crate`
//! statement anywhere in the project reference this dependency's crate
//! name?" That's enough to catch the concrete false-positive case of a
//! dependency that's declared in `Cargo.toml` but never actually referenced
//! anywhere in source (still "resolved" per `cargo metadata`, but dead).
//!
//! Caveat worth knowing before trusting this in anger: the `argument`/`path`
//! field names below are tied to tree-sitter-rust's grammar shape. If a
//! future grammar version renames them, `scan_used_crates` degrades to
//! finding nothing rather than panicking — which would silently mark every
//! dependency unreachable. Worth a smoke test against a project with a
//! known vulnerable-and-used dependency before relying on this for real.

use crate::error::{DaggerError, Result};
use std::collections::HashSet;
use std::path::Path;
use tree_sitter::{Node, Parser};
use walkdir::WalkDir;

pub fn scan_used_crates(root: &Path) -> Result<HashSet<String>> {
    let mut used = HashSet::new();

    let mut parser = Parser::new();
    parser
        .set_language(tree_sitter_rust::language())
        .map_err(|e| DaggerError::Grammar(e.to_string()))?;

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| e.file_name() != "target")
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().map(|ext| ext != "rs").unwrap_or(true) {
            continue;
        }

        let source = std::fs::read(entry.path())?;
        if let Some(tree) = parser.parse(&source, None) {
            collect_used_crate_idents(tree.root_node(), &source, &mut used);
        }
    }

    Ok(used)
}

fn collect_used_crate_idents(node: Node, source: &[u8], out: &mut HashSet<String>) {
    match node.kind() {
        "use_declaration" => {
            if let Some(arg) = node.child_by_field_name("argument") {
                if let Some(name) = leftmost_path_identifier(arg, source) {
                    out.insert(name);
                }
            }
        }
        "extern_crate_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                out.insert(text(name_node, source));
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_used_crate_idents(child, source, out);
    }
}

/// Walks down the left edge of a `use` path to find its root segment, e.g.
/// `serde::Deserialize` -> `serde`, `std::{fs, io}` -> `std`. Returns `None`
/// for relative paths (`crate::`, `self::`, `super::`) since those don't
/// name an external dependency.
fn leftmost_path_identifier(node: Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => Some(text(node, source)),
        "crate" | "self" | "super" | "use_list" => None,
        "scoped_identifier" | "scoped_use_list" | "use_as_clause" => node
            .child_by_field_name("path")
            .and_then(|p| leftmost_path_identifier(p, source)),
        "use_wildcard" => node
            .named_child(0)
            .and_then(|c| leftmost_path_identifier(c, source)),
        _ => None,
    }
}

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or_default().to_string()
}
