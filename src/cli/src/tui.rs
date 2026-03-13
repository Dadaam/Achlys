//! AFL++-inspired TUI for Achlys.
//!
//! Renders a status screen with colored boxes showing fuzzer stats,
//! escalation state, AI cortex status, and coverage information.

use std::io::{self, Stdout};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame, Terminal,
};

/// Stats extracted from LibAFL's monitor output.
#[derive(Debug, Clone, Default)]
pub struct TuiStats {
    pub run_time: String,
    pub corpus_size: u64,
    pub objective_size: u64,
    pub total_execs: u64,
    pub execs_per_sec: String,
    pub clients: u64,
    pub last_event: String,
    pub last_update: Option<Instant>,
}

/// Shared TUI state updated by the monitor callback.
pub struct TuiState {
    stats: TuiStats,
    start_time: Instant,
    target_name: String,
    mode: String,
}

impl TuiState {
    pub fn new(target_name: String, mode: String) -> Self {
        Self {
            stats: TuiStats::default(),
            start_time: Instant::now(),
            target_name,
            mode,
        }
    }

    /// Parse the formatted stats string from SimpleMonitor.
    /// Format: `[EVENT #ID] run time: X, clients: N, corpus: N, objectives: N, executions: N, exec/sec: N`
    pub fn update_from_stats(&mut self, stats_str: &str) {
        // Extract event name
        if let Some(bracket_end) = stats_str.find(']')
            && let Some(bracket_start) = stats_str.find('[')
        {
            let event_part = &stats_str[bracket_start + 1..bracket_end];
            if let Some(space_idx) = event_part.find(" #") {
                self.stats.last_event = event_part[..space_idx].to_string();
            }
        }

        // Parse key-value pairs after the bracket
        let pairs_str = stats_str
            .find(']')
            .map(|i| &stats_str[i + 2..])
            .unwrap_or(stats_str);

        for part in pairs_str.split(", ") {
            let mut kv = part.splitn(2, ": ");
            if let (Some(key), Some(val)) = (kv.next(), kv.next()) {
                match key.trim() {
                    "run time" => self.stats.run_time = val.to_string(),
                    "clients" => self.stats.clients = val.parse().unwrap_or(0),
                    "corpus" => self.stats.corpus_size = val.parse().unwrap_or(0),
                    "objectives" => self.stats.objective_size = val.parse().unwrap_or(0),
                    "executions" => self.stats.total_execs = val.parse().unwrap_or(0),
                    "exec/sec" => self.stats.execs_per_sec = val.to_string(),
                    _ => {}
                }
            }
        }

        self.stats.last_update = Some(Instant::now());
    }
}

/// The TUI renderer.
pub struct AchlysTui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    state: Arc<Mutex<TuiState>>,
}

impl AchlysTui {
    /// Initialize the TUI (enters alternate screen, enables raw mode).
    pub fn init(target_name: String, mode: String) -> io::Result<(Self, Arc<Mutex<TuiState>>)> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        let state = Arc::new(Mutex::new(TuiState::new(target_name, mode)));
        let state_clone = state.clone();

        Ok((Self { terminal, state }, state_clone))
    }

    /// Draw the TUI frame.
    pub fn draw(&mut self) -> io::Result<()> {
        let state = self.state.lock().unwrap();
        let stats = &state.stats;
        let target = &state.target_name;
        let mode = &state.mode;
        let uptime = format_duration(state.start_time.elapsed());

        // Snapshot data for rendering
        let run_time = stats.run_time.clone();
        let corpus = format_number(stats.corpus_size);
        let objectives = format_number(stats.objective_size);
        let total_execs = format_number(stats.total_execs);
        let execs_per_sec = stats.execs_per_sec.clone();
        let last_event = stats.last_event.clone();
        let mode_display = mode.clone();
        let target_display = target.clone();

        drop(state);

        self.terminal.draw(|frame| {
            let area = frame.area();
            let data = RenderData {
                target: &target_display,
                mode: &mode_display,
                uptime: &uptime,
                run_time: &run_time,
                corpus: &corpus,
                objectives: &objectives,
                total_execs: &total_execs,
                execs_per_sec: &execs_per_sec,
                last_event: &last_event,
            };
            render_ui(frame, area, &data);
        })?;

        Ok(())
    }

    /// Restore the terminal to normal state.
    pub fn cleanup(&mut self) -> io::Result<()> {
        disable_raw_mode()?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        self.terminal.show_cursor()?;
        Ok(())
    }

    /// Check for quit key (q or Ctrl+C).
    #[allow(dead_code)]
    pub fn should_quit() -> bool {
        if event::poll(std::time::Duration::from_millis(0)).unwrap_or(false)
            && let Ok(Event::Key(key)) = event::read()
        {
            return key.code == KeyCode::Char('q')
                || key.code == KeyCode::Char('c')
                    && key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL);
        }
        false
    }
}

impl Drop for AchlysTui {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct RenderData<'a> {
    target: &'a str,
    mode: &'a str,
    uptime: &'a str,
    run_time: &'a str,
    corpus: &'a str,
    objectives: &'a str,
    total_execs: &'a str,
    execs_per_sec: &'a str,
    last_event: &'a str,
}

fn render_ui(frame: &mut Frame, area: Rect, d: &RenderData<'_>) {
    let cyan = Style::default().fg(Color::Cyan);
    let green = Style::default().fg(Color::Green);
    let yellow = Style::default().fg(Color::Yellow);
    let red = Style::default().fg(Color::Red);
    let white = Style::default().fg(Color::White);
    let dim = Style::default().fg(Color::DarkGray);

    // Main layout: header + body
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // Header
    let header_text = vec![Line::from(vec![
        Span::styled(" target: ", dim),
        Span::styled(d.target, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled("    uptime: ", dim),
        Span::styled(d.uptime, green),
        Span::styled("    mode: ", dim),
        Span::styled(d.mode, yellow),
    ])];

    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                " achlys ",
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(header, main_layout[0]);

    // Body: 2x2 grid
    let body_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_layout[1]);

    let left_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body_cols[0]);

    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body_cols[1]);

    let speed_str = format!("{}/sec", d.execs_per_sec);
    let obj_style = if d.objectives == "0" { dim } else { red };

    // Process Timing (top-left)
    let timing = make_stats_block(
        " process timing ",
        Color::Cyan,
        &[
            ("run time", d.run_time, cyan),
            ("total execs", d.total_execs, white),
            ("exec speed", &speed_str, green),
            ("last event", d.last_event, dim),
        ],
    );
    frame.render_widget(timing, left_rows[0]);

    // Overall Results (top-right)
    let results = make_stats_block(
        " overall results ",
        Color::Green,
        &[
            ("corpus count", d.corpus, white),
            ("crashes", d.objectives, obj_style),
            ("total execs", d.total_execs, white),
        ],
    );
    frame.render_widget(results, right_rows[0]);

    // Stage Info (bottom-left)
    let stage_info = make_stats_block(
        " stage info ",
        Color::Yellow,
        &[
            ("current mode", d.mode, yellow),
            ("exec speed", &speed_str, green),
        ],
    );
    frame.render_widget(stage_info, left_rows[1]);

    // Fuzzer Status (bottom-right)
    let status = make_stats_block(
        " status ",
        Color::Magenta,
        &[
            ("corpus", d.corpus, white),
            ("crashes", d.objectives, obj_style),
            ("speed", &speed_str, green),
        ],
    );
    frame.render_widget(status, right_rows[1]);
}

fn make_stats_block<'a>(
    title: &'a str,
    title_color: Color,
    entries: &[(&'a str, &'a str, Style)],
) -> Paragraph<'a> {
    let mut lines = Vec::new();
    for (label, value, style) in entries {
        let dots = ".".repeat(22usize.saturating_sub(label.len()));
        lines.push(Line::from(vec![
            Span::styled(format!("  {} ", label), Style::default().fg(Color::DarkGray)),
            Span::styled(dots, Style::default().fg(Color::DarkGray)),
            Span::raw(" "),
            Span::styled((*value).to_string(), *style),
        ]));
    }

    Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                title,
                Style::default()
                    .fg(title_color)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(Color::DarkGray)),
    )
}

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Create the monitor callback that updates the TUI.
/// Returns a closure suitable for `SimpleMonitor::new()`.
pub fn create_tui_callback(
    state: Arc<Mutex<TuiState>>,
    tui: Arc<Mutex<AchlysTui>>,
) -> impl FnMut(&str) {
    move |stats_str: &str| {
        if let Ok(mut s) = state.lock() {
            s.update_from_stats(stats_str);
        }
        if let Ok(mut t) = tui.lock() {
            let _ = t.draw();
        }
    }
}
