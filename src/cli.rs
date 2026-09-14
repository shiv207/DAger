use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "dagger",
    version,
    about = "Deterministically prove which vulnerabilities are actually reachable, and how much they matter."
)]
pub struct Cli {
    /// Path to the Rust project to analyze (must contain a Cargo.toml).
    #[arg(long, short, default_value = ".")]
    pub path: PathBuf,

    /// Output format for the non-interactive report.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,

    /// Launch the interactive TUI dashboard instead of printing a report.
    #[arg(long, short)]
    pub interactive: bool,

    /// Weight applied to normalized PageRank centrality in the risk formula:
    /// risk = base_severity * reachable * (1 + centrality_weight * centrality).
    #[arg(long, default_value_t = crate::scoring::DEFAULT_CENTRALITY_WEIGHT)]
    pub centrality_weight: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Json,
    Table,
}
