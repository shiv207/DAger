mod app;
mod ui;

pub use app::App;

use crate::pipeline::{self, PipelineConfig};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::Backend, backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;

pub async fn run(config: PipelineConfig) -> anyhow::Result<()> {
    let mut app = App::new();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, &mut app, config).await;

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
) -> anyhow::Result<()> {
    // v1 runs the pipeline to completion before the TUI becomes interactive,
    // streaming log lines into `app` as it goes. A live-updating pipeline
    // (spawned as a background tokio task feeding the log/scorecard through
    // a channel while this loop keeps drawing) is the natural follow-up once
    // the pipeline itself is trustworthy end to end.
    let output = pipeline::run(&config, |line| app.push_log(line)).await?;
    app.load_output(output);

    loop {
        terminal.draw(|frame| ui::draw(frame, app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => app.select_next(),
                    KeyCode::Up | KeyCode::Char('k') => app.select_previous(),
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
