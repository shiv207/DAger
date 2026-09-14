//! A small, deliberately restrained palette — muted grays with one warm
//! accent color doing all the signaling, rather than a wall of primary
//! colors. Status still reads instantly (reachable/exploitable stays a
//! clear danger red, safe stays a quiet green) but nothing fights for
//! attention that doesn't need it.

use ratatui::style::Color;

pub const ACCENT: Color = Color::Rgb(217, 119, 87); // warm terracotta
pub const TEXT: Color = Color::Rgb(226, 223, 217);
pub const MUTED: Color = Color::Rgb(122, 122, 122);
pub const BORDER: Color = Color::Rgb(72, 72, 72);
/// Barely-there gray for graph nodes with no known vulnerability at all —
/// deliberately dimmer than MUTED, which is reused for "has a vulnerability
/// but it's unreachable."
pub const DIM: Color = Color::Rgb(46, 46, 46);
pub const SUCCESS: Color = Color::Rgb(126, 178, 124);
pub const DANGER: Color = Color::Rgb(214, 100, 100);
pub const WARNING: Color = Color::Rgb(206, 160, 92);
