use super::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        canvas::{Canvas, Points},
        Block, Borders, List, ListItem, Paragraph,
    },
    Frame,
};

pub fn draw(frame: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(frame.size());

    draw_header(frame, app, root[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(45),
            Constraint::Percentage(30),
        ])
        .split(root[1]);

    draw_log_pane(frame, app, body[0]);
    draw_graph_canvas(frame, app, body[1]);
    draw_scorecard(frame, app, body[2]);
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let text = format!(
        " {} vulnerabilities found  ->  {} mathematically proven exploitable ",
        app.total_found,
        app.exploitable_count()
    );
    let header = Paragraph::new(text)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("DAGger // Noise Reduction"),
        );
    frame.render_widget(header, area);
}

fn draw_log_pane(frame: &mut Frame, app: &App, area: Rect) {
    let visible_rows = area.height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = app
        .log
        .iter()
        .rev()
        .take(visible_rows)
        .rev()
        .map(|line| ListItem::new(Line::from(line.as_str())))
        .collect();
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Execution Log"));
    frame.render_widget(list, area);
}

fn draw_graph_canvas(frame: &mut Frame, app: &App, area: Rect) {
    // TODO(algorithm): nodes are placed on a simple circular layout keyed by
    // index, not a real force-directed graph layout (e.g. Fruchterman-
    // Reingold over the petgraph structure). Dot color/size already reflect
    // real reachability and centrality data from the pipeline — only the
    // (x, y) placement is a placeholder.
    let n = app.assessments.len().max(1) as f64;
    let assessments = &app.assessments;
    let canvas = Canvas::default()
        .block(Block::default().borders(Borders::ALL).title("Dependency Graph"))
        .x_bounds([-1.2, 1.2])
        .y_bounds([-1.2, 1.2])
        .paint(move |ctx| {
            for (i, assessment) in assessments.iter().enumerate() {
                let angle = 2.0 * std::f64::consts::PI * (i as f64) / n;
                let radius = 0.3 + 0.6 * assessment.centrality;
                let x = radius * angle.cos();
                let y = radius * angle.sin();
                let color = if !assessment.reachable {
                    Color::DarkGray
                } else if assessment.centrality > 0.5 {
                    Color::Red
                } else {
                    Color::Yellow
                };
                ctx.draw(&Points {
                    coords: &[(x, y)],
                    color,
                });
            }
        });
    frame.render_widget(canvas, area);
}

fn draw_scorecard(frame: &mut Frame, app: &App, area: Rect) {
    let body = match app.selected_assessment() {
        Some(a) => vec![
            Line::from(Span::styled(
                a.vulnerability.id.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(format!(
                "Package: {}@{}",
                a.vulnerability.package.name, a.vulnerability.package.version
            )),
            Line::from(""),
            Line::from("risk = base_severity * reachable * (1 + w * centrality)"),
            Line::from(format!("  base_severity  = {:.2}", a.base_severity)),
            Line::from(format!("  reachable      = {}", a.reachable)),
            Line::from(format!(
                "  centrality     = {:.3}  (w = {:.2})",
                a.centrality, a.centrality_weight
            )),
            Line::from("  -----------------------------"),
            Line::from(Span::styled(
                format!("  risk_score     = {:.2}", a.risk_score),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(a.vulnerability.summary.clone()),
        ],
        None => vec![Line::from("No vulnerability selected.")],
    };
    let scorecard =
        Paragraph::new(body).block(Block::default().borders(Borders::ALL).title("Scorecard"));
    frame.render_widget(scorecard, area);
}
