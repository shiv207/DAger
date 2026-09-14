//! Minimal ANSI SGR (Select Graphic Rendition) parser, just enough to
//! render `assets/dagger_logo.ans` as styled `ratatui` spans.
//!
//! Not a general ANSI terminal emulator — deliberately scoped to the subset
//! actually present in that asset: `ESC [ 0 m` (reset) and `ESC [ 0;FG;BG m`
//! (reset + standard/bright foreground + background color), no cursor
//! movement, no 256-color/truecolor, no bold/italic. Pulling in a crate for
//! this (`ansi-to-tui`) would have forced a ratatui 0.29+ upgrade across the
//! whole TUI (it depends on `ratatui-core`, incompatible with our pinned
//! 0.26) — too much blind API-drift risk for one splash asset, so this is
//! hand-rolled and unit-tested against the exact codes the asset uses.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

pub fn parse_line(raw: &str) -> Line<'static> {
    let mut spans = Vec::new();
    let mut style = Style::default();
    let mut buf = String::new();
    let mut chars = raw.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next(); // consume '['
            if !buf.is_empty() {
                spans.push(Span::styled(std::mem::take(&mut buf), style));
            }
            let mut code = String::new();
            for c2 in chars.by_ref() {
                if c2 == 'm' {
                    break;
                }
                code.push(c2);
            }
            style = apply_sgr(style, &code);
        } else {
            buf.push(c);
        }
    }
    if !buf.is_empty() {
        spans.push(Span::styled(buf, style));
    }

    Line::from(spans)
}

fn apply_sgr(mut style: Style, code: &str) -> Style {
    for part in code.split(';') {
        let Ok(n) = part.parse::<u16>() else {
            continue;
        };
        style = match n {
            0 => Style::default(),
            30..=37 => style.fg(standard_color(n - 30)),
            90..=97 => style.fg(bright_color(n - 90)),
            40..=47 => style.bg(standard_color(n - 40)),
            100..=107 => style.bg(bright_color(n - 100)),
            _ => style,
        };
    }
    style
}

fn standard_color(index: u16) -> Color {
    match index {
        0 => Color::Black,
        1 => Color::Red,
        2 => Color::Green,
        3 => Color::Yellow,
        4 => Color::Blue,
        5 => Color::Magenta,
        6 => Color::Cyan,
        7 => Color::Gray,
        _ => Color::Reset,
    }
}

fn bright_color(index: u16) -> Color {
    match index {
        0 => Color::DarkGray,
        1 => Color::LightRed,
        2 => Color::LightGreen,
        3 => Color::LightYellow,
        4 => Color::LightBlue,
        5 => Color::LightMagenta,
        6 => Color::LightCyan,
        7 => Color::White,
        _ => Color::Reset,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_with_no_codes_renders_as_one_span() {
        let line = parse_line("hello");
        assert_eq!(line.spans.len(), 1);
        assert_eq!(line.spans[0].content, "hello");
    }

    #[test]
    fn reset_then_fg_bg_applies_both_colors() {
        let line = parse_line("\u{1b}[0;34;40ma");
        assert_eq!(line.spans.len(), 1);
        assert_eq!(line.spans[0].style.fg, Some(Color::Blue));
        assert_eq!(line.spans[0].style.bg, Some(Color::Black));
    }

    #[test]
    fn bright_fg_and_bg_use_the_light_palette() {
        let line = parse_line("\u{1b}[0;97;47mx");
        assert_eq!(line.spans[0].style.fg, Some(Color::White));
        assert_eq!(line.spans[0].style.bg, Some(Color::Gray));
    }

    #[test]
    fn multiple_runs_in_one_line_produce_separate_spans() {
        let line = parse_line("\u{1b}[0;34;40mAB\u{1b}[0;37;40mCD");
        assert_eq!(line.spans.len(), 2);
        assert_eq!(line.spans[0].content, "AB");
        assert_eq!(line.spans[1].content, "CD");
        assert_eq!(line.spans[0].style.fg, Some(Color::Blue));
        assert_eq!(line.spans[1].style.fg, Some(Color::Gray));
    }

    #[test]
    fn the_real_asset_parses_without_panicking_and_keeps_visible_width() {
        let raw = include_str!("../../assets/dagger_logo.ans");
        for line in raw.lines() {
            if line.is_empty() {
                continue;
            }
            let parsed = parse_line(line);
            let visible_width: usize = parsed.spans.iter().map(|s| s.content.chars().count()).sum();
            assert_eq!(visible_width, 113, "line width drifted from the verified reconstruction");
        }
    }
}
