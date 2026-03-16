//! AFL++-inspired TUI for Achlys.
//!
//! Renders a status screen with colored boxes showing fuzzer stats,
//! escalation state, AI cortex status, and a live event log.

use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crossterm::{
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

/// Global quit flag set by the Ctrl+C handler.
static QUIT_FLAG: AtomicBool = AtomicBool::new(false);

const MAX_LOG_LINES: usize = 50;

/// Stats extracted from LibAFL's monitor output.
#[derive(Debug, Clone, Default)]
pub struct TuiStats {
    pub run_time: String,
    pub corpus_size: u64,
    pub objective_size: u64,
    pub total_execs: u64,
    pub execs_per_sec: String,
    pub last_event: String,
}

/// Shared TUI state updated by the monitor callback.
pub struct TuiState {
    pub stats: TuiStats,
    pub start_time: Instant,
    pub target_name: String,
    pub mode: String,
    pub logs: VecDeque<String>,
}

impl TuiState {
    pub fn new(target_name: String, mode: String) -> Self {
        Self {
            stats: TuiStats::default(),
            start_time: Instant::now(),
            target_name,
            mode,
            logs: VecDeque::with_capacity(MAX_LOG_LINES),
        }
    }

    /// Add a log message to the ring buffer.
    pub fn log(&mut self, msg: String) {
        if self.logs.len() >= MAX_LOG_LINES {
            self.logs.pop_front();
        }
        self.logs.push_back(msg);
    }

    /// Parse the formatted stats string from SimpleMonitor.
    pub fn update_from_stats(&mut self, stats_str: &str) {
        // Detect escalation/achlys messages mixed into the stats string
        // These come from println! in builder.rs and escalation.rs
        if stats_str.contains("[achlys") {
            // Extract all [achlys...] messages
            for part in stats_str.split("[achlys") {
                if let Some(end) = part.find(')') {
                    let msg = format!("[achlys{}", &part[..=end]);
                    self.log(msg);

                    // Detect stage changes
                    if part.contains("escalating") && part.contains("AI Hybrid") {
                        self.mode = "AI Hybrid".to_string();
                    } else if part.contains("de-escalating") && part.contains("Havoc") {
                        self.mode = "Havoc".to_string();
                    }
                }
            }
        }

        // Parse the standard monitor key-value pairs
        let pairs_str = stats_str
            .find(']')
            .map(|i| &stats_str[i + 2..])
            .unwrap_or(stats_str);

        // Extract event name
        if let Some(bracket_end) = stats_str.find(']')
            && let Some(bracket_start) = stats_str.find('[')
        {
            let event_part = &stats_str[bracket_start + 1..bracket_end];
            if let Some(space_idx) = event_part.find(" #") {
                self.stats.last_event = event_part[..space_idx].to_string();
            }
        }

        for part in pairs_str.split(", ") {
            let mut kv = part.splitn(2, ": ");
            if let (Some(key), Some(val)) = (kv.next(), kv.next()) {
                match key.trim() {
                    "run time" => self.stats.run_time = val.to_string(),
                    "corpus" => self.stats.corpus_size = val.parse().unwrap_or(0),
                    "objectives" => self.stats.objective_size = val.parse().unwrap_or(0),
                    "executions" => self.stats.total_execs = val.parse().unwrap_or(0),
                    "exec/sec" => self.stats.execs_per_sec = val.to_string(),
                    _ => {}
                }
            }
        }
    }
}

/// The TUI renderer.
pub struct AchlysTui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    state: Arc<Mutex<TuiState>>,
}

impl AchlysTui {
    /// Initialize the TUI.
    pub fn init(target_name: String, mode: String) -> io::Result<(Self, Arc<Mutex<TuiState>>)> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        let state = Arc::new(Mutex::new(TuiState::new(target_name, mode)));
        let state_clone = state.clone();

        // Install Ctrl+C handler
        ctrlc::set_handler(move || {
            QUIT_FLAG.store(true, Ordering::SeqCst);
            // Restore terminal immediately
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            std::process::exit(0);
        })
        .expect("failed to set Ctrl+C handler");

        Ok((Self { terminal, state }, state_clone))
    }

    /// Draw the TUI frame.
    pub fn draw(&mut self) -> io::Result<()> {
        if QUIT_FLAG.load(Ordering::Relaxed) {
            return Ok(());
        }

        let state = self.state.lock().unwrap();

        // Snapshot all data for rendering
        let target = state.target_name.clone();
        let mode = state.mode.clone();
        let uptime = format_duration(state.start_time.elapsed());
        let run_time = state.stats.run_time.clone();
        let corpus = format_number(state.stats.corpus_size);
        let objectives = format_number(state.stats.objective_size);
        let total_execs = format_number(state.stats.total_execs);
        let execs_per_sec = state.stats.execs_per_sec.clone();
        let last_event = state.stats.last_event.clone();
        let logs: Vec<String> = state.logs.iter().cloned().collect();

        drop(state);

        self.terminal.draw(|frame| {
            let area = frame.area();
            render_ui(frame, area, &RenderData {
                target: &target,
                mode: &mode,
                uptime: &uptime,
                run_time: &run_time,
                corpus: &corpus,
                objectives: &objectives,
                total_execs: &total_execs,
                execs_per_sec: &execs_per_sec,
                last_event: &last_event,
                logs: &logs,
            });
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
    logs: &'a [String],
}

fn render_ui(frame: &mut Frame, area: Rect, d: &RenderData<'_>) {
    let cyan = Style::default().fg(Color::Cyan);
    let green = Style::default().fg(Color::Green);
    let _yellow = Style::default().fg(Color::Yellow);
    let red = Style::default().fg(Color::Red);
    let white = Style::default().fg(Color::White);
    let dim = Style::default().fg(Color::DarkGray);
    let border = Style::default().fg(Color::DarkGray);

    // Main layout: header + body + logs
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Min(10),   // stats grid
            Constraint::Length(8), // logs
        ])
        .split(area);

    // ─── Header ───
    let mode_color = match d.mode {
        "AI Hybrid" => Color::Magenta,
        "Havoc" => Color::Yellow,
        _ => Color::Green,
    };

    let header_text = vec![Line::from(vec![
        Span::styled(" target: ", dim),
        Span::styled(d.target, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled("    uptime: ", dim),
        Span::styled(d.uptime, green),
        Span::styled("    stage: ", dim),
        Span::styled(d.mode, Style::default().fg(mode_color).add_modifier(Modifier::BOLD)),
    ])];

    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                " achlys ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ))
            .border_style(border),
    );
    frame.render_widget(header, main_layout[0]);

    // ─── Stats grid (2x2) ───
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

    // Process Timing
    frame.render_widget(
        make_stats_block(" process timing ", Color::Cyan, &[
            ("run time", d.run_time, cyan),
            ("total execs", d.total_execs, white),
            ("exec speed", &speed_str, green),
            ("last event", d.last_event, dim),
        ]),
        left_rows[0],
    );

    // Overall Results
    frame.render_widget(
        make_stats_block(" overall results ", Color::Green, &[
            ("corpus count", d.corpus, white),
            ("crashes", d.objectives, obj_style),
            ("total execs", d.total_execs, white),
        ]),
        right_rows[0],
    );

    // Stage Info
    frame.render_widget(
        make_stats_block(" stage info ", Color::Yellow, &[
            ("current stage", d.mode, Style::default().fg(mode_color)),
            ("exec speed", &speed_str, green),
        ]),
        left_rows[1],
    );

    // Status
    frame.render_widget(
        make_stats_block(" status ", Color::Magenta, &[
            ("corpus", d.corpus, white),
            ("crashes", d.objectives, obj_style),
            ("speed", &speed_str, green),
        ]),
        right_rows[1],
    );

    // ─── Logs ───
    let log_lines: Vec<Line> = d
        .logs
        .iter()
        .rev()
        .take(6)
        .rev()
        .map(|msg| {
            let color = if msg.contains("escalating") {
                Color::Magenta
            } else if msg.contains("error") || msg.contains("failed") {
                Color::Red
            } else if msg.contains("loaded") || msg.contains("started") {
                Color::Green
            } else {
                Color::DarkGray
            };
            Line::from(Span::styled(format!("  {msg}"), Style::default().fg(color)))
        })
        .collect();

    let logs_widget = Paragraph::new(log_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                " logs ",
                Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
            ))
            .border_style(border),
    );
    frame.render_widget(logs_widget, main_layout[2]);
}

fn make_stats_block<'a>(
    title: &'a str,
    title_color: Color,
    entries: &[(&'a str, &'a str, Style)],
) -> Paragraph<'a> {
    let mut lines = Vec::new();
    for (label, value, style) in entries {
        let dots = ".".repeat(20usize.saturating_sub(label.len()));
        lines.push(Line::from(vec![
            Span::styled(format!("  {label} "), Style::default().fg(Color::DarkGray)),
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
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
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
