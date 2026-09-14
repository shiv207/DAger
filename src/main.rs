mod ast_parser;
mod cli;
mod error;
mod graph_math;
mod groq_client;
mod ingestion;
mod models;
mod osv_client;
mod pipeline;
mod remediation;
mod scoring;
mod tui;

use clap::Parser;
use cli::{Cli, OutputFormat};
use comfy_table::{presets::UTF8_FULL, Table};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Best-effort: picks up GROQ_API_KEY (and anything else) from a local
    // .env if present. Silently does nothing if there isn't one — env vars
    // set the normal way still work either way.
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();

    let config = pipeline::PipelineConfig {
        project_path: cli.path.clone(),
        centrality_weight: cli.centrality_weight,
    };

    if cli.interactive {
        tui::run(config, cli.groq_model.clone()).await?;
        return Ok(());
    }

    let output = pipeline::run(&config, |line| eprintln!("{line}")).await?;

    match cli.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&output.assessments)?);
        }
        OutputFormat::Table => print_table(&output),
    }

    Ok(())
}

fn print_table(output: &pipeline::PipelineOutput) {
    let exploitable = output.assessments.iter().filter(|a| a.reachable).count();
    println!(
        "\nNoise reduction: {} vulnerabilities found -> {} mathematically proven exploitable\n",
        output.total_vulns_found, exploitable
    );

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        "Package",
        "Vulnerability",
        "Reachable",
        "Base Severity",
        "Centrality",
        "Risk Score",
    ]);
    for assessment in &output.assessments {
        table.add_row(vec![
            format!(
                "{}@{}",
                assessment.vulnerability.package.name, assessment.vulnerability.package.version
            ),
            assessment.vulnerability.id.clone(),
            assessment.reachable.to_string(),
            format!("{:.1}", assessment.base_severity),
            format!("{:.3}", assessment.centrality),
            format!("{:.2}", assessment.risk_score),
        ]);
    }
    println!("{table}");
}
