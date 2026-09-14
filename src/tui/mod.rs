mod ansi_art;
mod app;
mod chat;
mod splash;
mod theme;
mod tree_view;
mod ui;

pub use app::App;

use crate::groq_client::Role;
use crate::pipeline::{self, PipelineConfig};
use crate::remediation;
use chat::ChatMessage;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::Backend, backend::CrosstermBackend, Terminal};
use std::io;
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
    show_splash(terminal)?;

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
                        KeyCode::Char('y') => confirm_fix(app, &config, terminal).await,
                        KeyCode::Char('n') | KeyCode::Esc => {
                            app.fix_prompt = None;
                            app.push_log("[FIX] dismissed.");
                        }
                        _ => {}
                    }
                    continue;
                }

                if app.chat.open {
                    match key.code {
                        KeyCode::Esc => app.chat.open = false,
                        KeyCode::Enter if !app.chat.in_flight => {
                            send_chat_message(app, &http_client, &groq_model, terminal).await
                        }
                        KeyCode::Backspace => {
                            app.chat.input.pop();
                        }
                        KeyCode::Char(c) if !app.chat.in_flight => app.chat.input.push(c),
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
                    KeyCode::Char('c') => app.chat.open = true,
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

const SPLASH_TIMEOUT: Duration = Duration::from_millis(1800);
const SPLASH_POLL_INTERVAL: Duration = Duration::from_millis(50);

fn show_splash<B: Backend>(terminal: &mut Terminal<B>) -> anyhow::Result<()> {
    terminal.draw(splash::draw)?;

    let mut waited = Duration::ZERO;
    while waited < SPLASH_TIMEOUT {
        if event::poll(SPLASH_POLL_INTERVAL)? {
            if let Event::Key(_) = event::read()? {
                break;
            }
        }
        waited += SPLASH_POLL_INTERVAL;
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

async fn send_chat_message<B: Backend>(
    app: &mut App,
    client: &reqwest::Client,
    groq_model: &str,
    terminal: &mut Terminal<B>,
) {
    let user_text = app.chat.input.trim().to_string();
    if user_text.is_empty() {
        return;
    }
    app.chat.input.clear();
    app.chat.messages.push(ChatMessage {
        role: Role::User,
        content: user_text,
    });

    let Ok(api_key) = std::env::var("GROQ_API_KEY") else {
        app.chat.messages.push(ChatMessage {
            role: Role::Assistant,
            content: "GROQ_API_KEY isn't set, so I can't reach the model. Set it in .env or your environment and reopen the chat.".to_string(),
        });
        return;
    };

    app.chat.in_flight = true;
    // Same redraw-before-await trick as request_fix: without this the
    // "thinking..." state never actually paints before the response lands.
    let _ = terminal.draw(|frame| ui::draw(frame, app));

    // Rebuilt fresh every send (not cached at chat-open time) so it always
    // reflects the live pipeline results.
    let system_prompt = chat::build_system_prompt(app);
    let mut history = vec![(Role::System, system_prompt)];
    history.extend(
        app.chat
            .messages
            .iter()
            .map(|m| (m.role, m.content.clone())),
    );

    let result = crate::groq_client::chat_completion(client, &api_key, groq_model, &history, 0.3).await;
    app.chat.in_flight = false;

    let reply = match result {
        Ok(reply) => reply,
        Err(err) => format!("(request to Groq failed: {err})"),
    };
    app.chat.messages.push(ChatMessage {
        role: Role::Assistant,
        content: reply,
    });
}

async fn confirm_fix<B: Backend>(app: &mut App, config: &PipelineConfig, terminal: &mut Terminal<B>) {
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
    let _ = terminal.draw(|frame| ui::draw(frame, app));

    match remediation::apply_version_bump(&config.project_path, &fix).await {
        Ok(summary) => {
            app.push_log(&format!("[FIXED] {summary}"));
            app.push_log("[FIX] re-scanning to confirm the fix took...");
            let _ = terminal.draw(|frame| ui::draw(frame, app));

            // Re-run the whole pipeline rather than just deleting this one
            // row: OSV is queried again against the now-bumped version (so
            // a vulnerability genuinely disappears only because it's
            // actually gone, not because we assumed the fix worked), and
            // the dependency tree/centrality reflect whatever the bump
            // pulled in transitively.
            match pipeline::run(config, |line| app.push_log(line)).await {
                Ok(output) => {
                    app.load_output(output);
                    app.selected = 0;
                }
                Err(err) => app.push_log(&format!("[FIX] re-scan failed: {err} (fix was applied to disk regardless)")),
            }
        }
        Err(err) => app.push_log(&format!("[FIX] failed: {err}")),
    }
}
