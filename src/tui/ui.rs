use super::theme;
use super::tree_view::{self, NodeStatus};
use super::App;
use crate::groq_client::Role;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{block::Position, Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

pub fn draw(frame: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.size());

    draw_header(frame, app, root[0]);

    if app.chat.open {
        draw_chat(frame, app, root[1]);
    } else {
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(25),
                Constraint::Percentage(45),
                Constraint::Percentage(30),
            ])
            .split(root[1]);

        draw_log_pane(frame, app, body[0]);
        draw_dependency_tree(frame, app, body[1]);
        draw_scorecard(frame, app, body[2]);
    }

    draw_footer(frame, app, root[2]);

    if let Some(fix) = &app.fix_prompt {
        draw_fix_popup(frame, fix);
    }
}

fn panel_block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::BORDER))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(theme::MUTED),
        ))
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let exploitable = app.exploitable_count();
    let status_color = if exploitable > 0 { theme::DANGER } else { theme::SUCCESS };

    let lines = vec![
        Line::from(vec![
            Span::styled(
                " DAGger",
                Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "  deterministic reachability & blast-radius analysis",
                Style::default().fg(theme::MUTED),
            ),
        ]),
        Line::from(vec![
            Span::raw(" "),
            Span::styled(app.total_found.to_string(), Style::default().fg(theme::TEXT)),
            Span::styled(" found  ", Style::default().fg(theme::MUTED)),
            Span::styled("->", Style::default().fg(theme::MUTED)),
            Span::styled(
                format!("  {exploitable} proven exploitable"),
                Style::default().fg(status_color).add_modifier(Modifier::BOLD),
            ),
        ]),
    ];

    let header = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    frame.render_widget(header, area);
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let in_flight = app.fix_in_flight || app.chat.in_flight;
    let text = if app.fix_in_flight {
        " fetching fix suggestion from groq... "
    } else if app.chat.in_flight {
        " qwen is thinking... "
    } else if app.fix_prompt.is_some() {
        " y confirm    n/esc dismiss "
    } else if app.chat.open {
        " type your question    enter send    esc close chat "
    } else {
        " j/k select    f fix selected    c chat with qwen    q quit "
    };
    let style = if in_flight {
        Style::default().fg(theme::ACCENT)
    } else {
        Style::default().fg(theme::MUTED)
    };
    let footer = Paragraph::new(Span::styled(text, style));
    frame.render_widget(footer, area);
}

fn draw_log_pane(frame: &mut Frame, app: &App, area: Rect) {
    let visible_rows = area.height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = app
        .log
        .iter()
        .rev()
        .take(visible_rows)
        .rev()
        .map(|line| ListItem::new(Line::styled(line.as_str(), Style::default().fg(theme::TEXT))))
        .collect();
    let list = List::new(items).block(panel_block("execution log"));
    frame.render_widget(list, area);
}

fn draw_dependency_tree(frame: &mut Frame, app: &App, area: Rect) {
    // TODO: renders top-down and simply clips once the pane fills, rather
    // than scrolling — vulnerable nodes are sorted ahead of safe siblings
    // (tree_view::build_tree) specifically so they surface near the top
    // instead of being clipped out on a large dependency tree.
    let tree = tree_view::build_tree(&app.graph, &app.vulnerable_names, &app.reachable_vulnerable_names);
    let visible_rows = area.height.saturating_sub(2) as usize;

    let lines: Vec<Line> = if tree.is_empty() {
        vec![Line::styled("(no packages resolved)", Style::default().fg(theme::MUTED))]
    } else {
        tree.iter()
            .take(visible_rows)
            .map(|entry| {
                let color = match entry.status {
                    NodeStatus::Safe => theme::DIM,
                    NodeStatus::VulnerableUnreachable => theme::MUTED,
                    NodeStatus::VulnerableReachable if entry.centrality > 0.5 => theme::DANGER,
                    NodeStatus::VulnerableReachable => theme::WARNING,
                };
                let suffix = if entry.is_repeat { " (*)" } else { "" };
                Line::from(vec![
                    Span::styled(entry.prefix.clone(), Style::default().fg(theme::BORDER)),
                    Span::styled(
                        format!("{}@{}{suffix}", entry.name, entry.version),
                        Style::default().fg(color),
                    ),
                ])
            })
            .collect()
    };

    let paragraph = Paragraph::new(lines).block(panel_block("dependency tree"));
    frame.render_widget(paragraph, area);
}

fn draw_scorecard(frame: &mut Frame, app: &App, area: Rect) {
    let body = match app.selected_assessment() {
        Some(a) => {
            let mut lines = vec![
                Line::from(Span::styled(
                    a.vulnerability.id.clone(),
                    Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
                )),
                Line::styled(
                    format!(
                        "{}@{}",
                        a.vulnerability.package.name, a.vulnerability.package.version
                    ),
                    Style::default().fg(theme::MUTED),
                ),
                Line::default(),
                Line::styled(
                    "risk = base_severity * reachable * (1 + w * centrality)",
                    Style::default().fg(theme::MUTED),
                ),
                Line::styled(
                    format!("  base_severity  {:.2}", a.base_severity),
                    Style::default().fg(theme::TEXT),
                ),
                Line::from(vec![
                    Span::styled("  reachable      ", Style::default().fg(theme::TEXT)),
                    Span::styled(
                        a.reachable.to_string(),
                        Style::default().fg(if a.reachable { theme::DANGER } else { theme::SUCCESS }),
                    ),
                ]),
                Line::styled(
                    format!("  centrality     {:.3}  (w={:.2})", a.centrality, a.centrality_weight),
                    Style::default().fg(theme::TEXT),
                ),
                Line::styled("  ─────────────────────────", Style::default().fg(theme::BORDER)),
                Line::from(Span::styled(
                    format!("  risk_score     {:.2}", a.risk_score),
                    Style::default().fg(theme::DANGER).add_modifier(Modifier::BOLD),
                )),
                Line::default(),
                Line::styled(a.vulnerability.summary.clone(), Style::default().fg(theme::TEXT)),
            ];

            if let Some(fixed) = &a.vulnerability.fixed_version {
                lines.push(Line::default());
                lines.push(Line::styled(
                    format!("fixed in {fixed}"),
                    Style::default().fg(theme::SUCCESS),
                ));
            }
            if a.reachable {
                lines.push(Line::default());
                lines.push(Line::styled("[f] propose a fix", Style::default().fg(theme::MUTED)));
            }

            lines
        }
        None => vec![Line::styled(
            "No vulnerability selected.",
            Style::default().fg(theme::MUTED),
        )],
    };

    let scorecard = Paragraph::new(body).block(panel_block("scorecard"));
    frame.render_widget(scorecard, area);
}

fn draw_chat(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    let mut lines: Vec<Line> = Vec::new();
    if app.chat.messages.is_empty() {
        lines.push(Line::styled(
            "Ask anything — e.g. \"what's actually wrong here?\" or",
            Style::default().fg(theme::MUTED),
        ));
        lines.push(Line::styled(
            "\"explain reachability like I'm five\".",
            Style::default().fg(theme::MUTED),
        ));
    }
    for message in &app.chat.messages {
        let (label, color) = match message.role {
            Role::User => ("you", theme::ACCENT),
            Role::Assistant => ("qwen", theme::SUCCESS),
            Role::System => continue, // never stored as a message; rebuilt fresh per send
        };
        lines.push(Line::styled(
            format!("{label}:"),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
        for content_line in message.content.lines() {
            lines.push(Line::styled(content_line.to_string(), Style::default().fg(theme::TEXT)));
        }
        lines.push(Line::default());
    }
    if app.chat.in_flight {
        lines.push(Line::styled(
            "qwen is thinking...",
            Style::default().fg(theme::ACCENT).add_modifier(Modifier::ITALIC),
        ));
    }

    // Approximate auto-scroll-to-bottom: counts logical lines, not the
    // wrapped rows Paragraph actually renders, so this undercounts once
    // any single message wraps across multiple terminal columns. Good
    // enough to keep recent messages on screen; not pixel-exact.
    let visible_rows = chunks[0].height.saturating_sub(2);
    let scroll = (lines.len() as u16).saturating_sub(visible_rows);

    let history = Paragraph::new(lines)
        .block(panel_block("chat with qwen"))
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    frame.render_widget(history, chunks[0]);

    let input = Paragraph::new(Line::from(vec![
        Span::styled("> ", Style::default().fg(theme::ACCENT)),
        Span::styled(app.chat.input.as_str(), Style::default().fg(theme::TEXT)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    frame.render_widget(input, chunks[1]);
}

fn draw_fix_popup(frame: &mut Frame, fix: &crate::remediation::ProposedFix) {
    let area = centered_rect(60, 50, frame.size());
    frame.render_widget(Clear, area);

    let mut lines: Vec<Line> = fix
        .display_lines()
        .into_iter()
        .map(|l| Line::styled(l, Style::default().fg(theme::TEXT)))
        .collect();
    lines.push(Line::default());
    lines.push(Line::styled(
        if fix.is_auto_applicable() {
            "y = apply now      n/esc = dismiss"
        } else {
            "y/n/esc = dismiss (advisory only)"
        },
        Style::default().fg(theme::MUTED).add_modifier(Modifier::ITALIC),
    ));

    let popup = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme::ACCENT))
            .title(Span::styled(
                " proposed fix ",
                Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
            ))
            .title_position(Position::Top),
    );
    frame.render_widget(popup, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}
