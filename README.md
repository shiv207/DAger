# DAGger — Deterministic Reachability Analysis

Prove which vulnerabilities in your Rust dependencies are actually exploitable by analyzing import graphs and AST-level reachability. No heuristics, no guessing—just graph mathematics and deterministic scanning.

## What DAGger Does

DAGger answers: "Of the vulnerabilities OSV.dev found in my dependencies, which ones can my code actually reach?"

**The problem it solves:** A vulnerability listed in `cargo audit` may exist in your dependency tree but never actually be called by your code. DAGger separates reachable (exploitable) from unreachable (noise) by:

1. Resolving your full dependency graph via `cargo metadata`
2. Scanning your source code for `use` declarations (import-level reachability, not full call graphs)
3. Computing dependency centrality via PageRank
4. Querying OSV.dev for known CVEs
5. Scoring risk by severity, reachability, and importance in the graph

Output: a sorted list of vulnerabilities ranked by real risk, not by hype.

## Installation

### From Source

```bash
git clone https://github.com/yourusername/dager.git
cd Dager
cargo build --release
```

The binary lands at `target/release/dagger`.

### Quick Test

```bash
# Add to PATH, or run directly
./target/release/dagger --path ./playground --format table
```

## Usage

### CLI Report (Non-Interactive)

```bash
dagger --path <PROJECT_PATH> [OPTIONS]
```

**Options:**

- `--path <PATH>` — Rust project root (contains `Cargo.toml`). Default: `.`
- `--format <FORMAT>` — Output: `table` (default) or `json`
- `--centrality-weight <WEIGHT>` — Weight for PageRank in risk scoring (0.0–1.0). Default: `0.5`
- `--groq-model <MODEL>` — LLM for mitigation suggestions. Default: `mixtral-8x7b-32768`

**Example:**

```bash
dagger --path ~/my-rust-app --format json
```

Outputs a sorted list of vulnerabilities:

```
Noise reduction: 24 vulnerabilities found -> 12 mathematically proven exploitable

┌────────────────┬──────────────────────┬───────────┬───────────────┬────────────┬────────────┐
│ Package        ┆ Vulnerability        ┆ Reachable ┆ Base Severity ┆ Centrality ┆ Risk Score │
├────────────────┼──────────────────────┼───────────┼───────────────┼────────────┼────────────┤
│ lru@0.12.5     ┆ GHSA-rhfx-m35p-ff5j ┆ true      ┆ 5.0           ┆ 0.644      ┆ 6.61       │
│ lru@0.12.5     ┆ RUSTSEC-2026-0002    ┆ true      ┆ 5.0           ┆ 0.644      ┆ 6.61       │
│ paste@1.0.15   ┆ RUSTSEC-2024-0436    ┆ true      ┆ 5.0           ┆ 0.200      ┆ 5.20       │
└────────────────┴──────────────────────┴───────────┴───────────────┴────────────┴────────────┘
```

### Interactive TUI

Launch the dashboard to explore, fix, and chat:

```bash
dagger --path <PROJECT_PATH> --interactive
```

**Keyboard shortcuts:**

- `j`/`k` — Move through vulnerabilities
- `f` — Propose a fix for the selected vulnerability
- `y` — Confirm and apply the fix (auto-bumps `Cargo.toml`, runs `cargo update`)
- `n` — Dismiss the fix prompt
- `c` — Open chat panel (ask questions about the findings)
- `Esc` — Close chat / return to main view
- `q` — Quit

**What the TUI shows:**

1. **Execution log** (left) — Live scan progress
2. **Dependency tree** (center) — Full graph colored by vulnerability status
   - 🟢 Safe (no CVEs)
   - 🟡 Unreachable (CVEs exist, you don't call them)
   - 🔴 Reachable (CVEs exist, you do call them)
3. **Scorecard** (right) — Risk formula breakdown for the selected vulnerability
4. **Chat panel** (modal) — Ask DAGger about your findings in plain English

## How Reachability Works

DAGger marks a dependency **reachable** when:
- You have an explicit `use` declaration for a crate or its public symbols in your code, **and**
- That crate appears in your dependency graph (direct or transitive)

Example:

```rust
// src/main.rs
use lru::LruCache;  // ✓ lru is reachable
use serde::Serialize;  // ✓ serde is reachable
// No `use paste` anywhere → paste is unreachable
```

**Important:** This is *syntactic* reachability (AST-level `use` declarations), not *semantic* reachability (full call-graph analysis). You may use a crate but never call the vulnerable function—that's a limitation you must verify manually for critical cases.

## Risk Scoring

Risk is computed as:

```
risk_score = base_severity × reachable × (1 + weight × centrality)
```

- **base_severity** — CVSS score or severity category (LOW=2.5, MODERATE=5.0, HIGH=7.5, CRITICAL=9.5)
- **reachable** — 1 if import-reachable, 0 otherwise
- **centrality** — PageRank score (0.0–1.0) measuring how central the dependency is in your graph
- **weight** — User-set parameter (default 0.5) balancing severity vs. importance

High centrality dependencies bubble up (they're used transitively by many of your other packages), so a vulnerability in a core utility affects risk more than one in a leaf dependency.

## Fixing Vulnerabilities

### Auto-Fix (Version Bump)

If OSV.dev lists a patched version for a vulnerability:

1. Open the TUI: `dagger --interactive --path <PROJECT_PATH>`
2. Navigate to the vulnerability (`j`/`k`)
3. Press `f` (fix)
4. Confirm with `y`

DAGger will:
- Edit your `Cargo.toml` to the patched version
- Run `cargo update -p <package> --precise <version>`
- Re-scan your code to confirm the fix took
- Mark the vulnerability as resolved in the TUI

**Note:** If the fix succeeded but you still see the vuln listed, the fix may have introduced other issues. Check the execution log.

### Advisory-Only (No Patch Yet)

For unmaintained crates or vulnerabilities without a published fix:

1. Press `f` (fix)
2. DAGger queries an LLM (Groq by default) for mitigation guidance
3. Review the suggestion (it's advisory, not auto-applied)

Requires `GROQ_API_KEY` environment variable. Set it in `.env`:

```
GROQ_API_KEY=your_key_here
```

The LLM cannot auto-fix advisory suggestions because they often require code changes, not just version bumps.

## Configuration

### Environment Variables

```bash
# Required for mitigation suggestions (interactive mode only)
GROQ_API_KEY=<your-groq-api-key>

# Optional: which LLM to use for mitigation suggestions
GROQ_MODEL=mixtral-8x7b-32768  # default
```

### .env File

Create a `.env` in your project root:

```
GROQ_API_KEY=gsk_...
```

DAGger loads it automatically via `dotenvy`.

## Output Formats

### Table (Default)

Human-readable terminal output with sorted vulnerabilities.

```bash
dagger --path . --format table
```

### JSON

Machine-readable output for CI/CD integration.

```bash
dagger --path . --format json
```

Example:

```json
[
  {
    "vulnerability": {
      "id": "GHSA-rhfx-m35p-ff5j",
      "package": {"name": "lru", "version": "0.12.5"},
      "summary": "...",
      "fixed_version": "0.16.3"
    },
    "reachable": true,
    "base_severity": 5.0,
    "centrality": 0.644,
    "risk_score": 6.61
  }
]
```

## Examples

### Audit Your App

```bash
cd ~/my-rust-app
dagger --path .
```

### Explore and Fix Interactively

```bash
dagger --path ~/my-rust-app --interactive
# Use the TUI to navigate findings and apply fixes
```

### Check a Specific Project with Custom Weight

```bash
dagger --path ./services/auth --centrality-weight 0.8
```

Increases weight on dependency centrality (high centrality = higher risk).

### Export Findings to JSON for CI

```bash
dagger --path . --format json > vulnerabilities.json
# Parse in your CI pipeline to decide on pass/fail
```

## Limitations

1. **Import-level reachability only** — DAGger scans `use` declarations, not full call graphs. A crate may be imported but never call the vulnerable function.
2. **No CVSS vector parsing** — Base severity comes from categorical scores (LOW/MODERATE/HIGH/CRITICAL) or generic fallbacks. Full CVSS vectors are not yet parsed.
3. **Rust-only** — DAGger works only with Cargo projects; JS, Python, etc., are out of scope.
4. **OSV.dev dependency** — Vulnerability data is fetched live from OSV.dev. No offline mode yet.

## Troubleshooting

### "Could not find `<package>` in Cargo.toml"

The version bump failed because the crate name in OSV doesn't match the manifest key. This happens with renamed dependencies:

```toml
[dependencies]
my_alias = { package = "real-name", version = "1.0" }
```

DAGger tried to update `real-name` but the manifest key is `my_alias`. **Workaround:** edit `Cargo.toml` manually, then run `cargo update -p real-name --precise <version>`.

### "GROQ_API_KEY is not set"

Advisory-only suggestions require a Groq API key. Either:
- Set the env var: `export GROQ_API_KEY=gsk_...`
- Add it to `.env` in your project root
- Skip advisory fixes and handle them manually

### Re-scan Still Shows the Same Vuln

The fix was applied to disk but OSV.dev may be lagging. Try:

```bash
rm -rf Cargo.lock
cargo generate-lockfile
dagger --path . --interactive
```

Then re-run the fix flow.

## For Contributors

DAGger is organized as a Rust binary with:

- `src/main.rs` — CLI entry point
- `src/pipeline.rs` — Five-step analysis pipeline
- `src/ast_parser.rs` — tree-sitter AST scanning for `use` declarations
- `src/graph_math.rs` — PageRank centrality computation
- `src/osv_client.rs` — OSV.dev batch API querying
- `src/remediation.rs` — Version bump and Groq fallback logic
- `src/tui/` — Interactive dashboard (ratatui + crossterm)

Run tests with:

```bash
cargo test
```

Tests are fast (all but one marked `#[ignore]` to skip network calls).

## License

See LICENSE file in the repository.
