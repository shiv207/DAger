mod app;
mod theme;
mod ui;

pub use app::App;

use crate::pipeline::{self, PipelineConfig};
use crate::remediation;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::Backend, backend::CrosstermBackend, Terminal};
use std::io;
use std::path::Path;
use std::time::Duration;

pub async fn run(config: PipelineConfig, groq_model: String) -> anyhow::Result<()> {
    let mut app = App::new();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, &mut app, config, groq_model).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    config: PipelineConfig,
    groq_model: String,
) -> anyhow::Result<()> {
    let project_path = config.project_path.clone();

    // v1 runs the pipeline to completion before the TUI becomes interactive,
    // streaming log lines into `app` as it goes. A live-updating pipeline
    // (spawned as a background tokio task feeding the log/scorecard through
    // a channel while this loop keeps drawing) is the natural follow-up once
    // the pipeline itself is trustworthy end to end.
    let output = pipeline::run(&config, |line| app.push_log(line)).await?;
    app.load_output(output);

    let http_client = reqwest::Client::new();

    loop {
        terminal.draw(|frame| ui::draw(frame, app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if app.fix_prompt.is_some() {
                    match key.code {
                        KeyCode::Char('y') => confirm_fix(app, &project_path).await,
                        KeyCode::Char('n') | KeyCode::Esc => {
                            app.fix_prompt = None;
                            app.push_log("[FIX] dismissed.");
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => app.select_next(),
                    KeyCode::Up | KeyCode::Char('k') => app.select_previous(),
                    KeyCode::Char('f') => {
                        request_fix(app, &http_client, &groq_model, terminal).await
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

async fn request_fix<B: Backend>(
    app: &mut App,
    client: &reqwest::Client,
    groq_model: &str,
    terminal: &mut Terminal<B>,
) {
    let Some(assessment) = app.selected_assessment().cloned() else {
        return;
    };

    if !assessment.reachable {
        app.push_log("[FIX] only proven-exploitable vulnerabilities have a fix flow.");
        return;
    }

    if let Some(fix) = remediation::propose_version_bump(&assessment) {
        app.push_log("[FIX] patched version found via OSV — no LLM needed.");
        app.fix_prompt = Some(fix);
        return;
    }

    let Ok(api_key) = std::env::var("GROQ_API_KEY") else {
        app.push_log(
            "[FIX] no patched version listed yet, and GROQ_API_KEY is not set \
             (needed for an AI-suggested mitigation).",
        );
        return;
    };

    app.push_log(&format!(
        "[FIX] no patched version yet — asking Groq ({groq_model})..."
    ));
    app.fix_in_flight = true;
    // Force a redraw before the (blocking, from the render loop's point of
    // view) network call so "fetching..." actually appears in the footer
    // instead of only flashing on the frame after the request completes.
    let _ = terminal.draw(|frame| ui::draw(frame, app));
    let fix = remediation::propose_mitigation_via_groq(client, &api_key, groq_model, &assessment).await;
    app.fix_in_flight = false;
    app.fix_prompt = Some(fix);
}

async fn confirm_fix(app: &mut App, project_path: &Path) {
    let Some(fix) = app.fix_prompt.take() else {
        return;
    };

    if !fix.is_auto_applicable() {
        app.push_log("[FIX] advisory only — not auto-applied. Suggestion:");
        for line in fix.display_lines() {
            app.push_log(&format!("       {line}"));
        }
        return;
    }

    app.push_log("[FIX] applying version bump...");
    match remediation::apply_version_bump(project_path, &fix).await {
        Ok(summary) => app.push_log(&format!("[FIXED] {summary}. Re-run dagger to confirm.")),
        Err(err) => app.push_log(&format!("[FIX] failed: {err}")),
    }
}
