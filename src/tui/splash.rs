//! Startup splash: renders `assets/dagger_logo.ans` (real ANSI art,
//! reconstructed and verified byte-for-byte — see `ansi_art.rs`) via the
//! hand-rolled SGR parser. Purely decorative — shown once before the
//! pipeline runs, dismissed by any keypress or a short timeout, never
//! blocks anything functional. Falls back to a plain text title on
//! terminals too narrow to fit the art without clipping it.

use super::ansi_art;
use super::theme;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::Line,
    widgets::Paragraph,
    Frame,
};

const ART_WIDTH: u16 = 113;
const TAGLINE: &str = "deterministic reachability & blast-radius analysis";
const HINT: &str = "press any key to begin  ·  auto-continuing shortly...";

pub fn draw(frame: &mut Frame) {
    let area = frame.size();
    let show_art = area.width >= ART_WIDTH + 4 && area.height >= 16;

    let mut lines: Vec<Line> = Vec::new();
    let content_width = if show_art {
        let raw = include_str!("../../assets/dagger_logo.ans");
        lines.extend(raw.lines().filter(|l| !l.is_empty()).map(ansi_art::parse_line));
        lines.push(Line::default());
        ART_WIDTH
    } else {
        lines.push(Line::styled("DAGGER", Style::default().fg(theme::DANGER)));
        lines.push(Line::default());
        TAGLINE.len().max(HINT.len()) as u16
    };

    let width = content_width as usize;
    lines.push(Line::styled(
        format!("{TAGLINE:^width$}"),
        Style::default().fg(theme::MUTED),
    ));
    lines.push(Line::default());
    lines.push(Line::styled(format!("{HINT:^width$}"), Style::default().fg(theme::ACCENT)));

    let block_height = lines.len() as u16;
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(block_height),
            Constraint::Min(0),
        ])
        .split(area);

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, centered_horizontal(content_width, vertical[1]));
}

fn centered_horizontal(width: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    Rect::new(x, area.y, width, area.height)
}
