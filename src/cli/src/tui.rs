//! AFL++-inspired TUI for Achlys.

use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
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

const MAX_LOG_LINES: usize = 50;

#[derive(Debug, Clone, Default)]
pub struct TuiStats {
    pub run_time: String,
    pub corpus_size: u64,
    pub objective_size: u64,
    pub total_execs: u64,
    pub execs_per_sec: String,
    pub last_event: String,
}

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

    pub fn log(&mut self, msg: String) {
        if self.logs.len() >= MAX_LOG_LINES {
            self.logs.pop_front();
        }
        self.logs.push_back(msg);
    }

    pub fn update_from_stats(&mut self, stats_str: &str) {
        // Detect [achlys...] messages mixed into the output
        if stats_str.contains("[achlys") {
            for part in stats_str.split("[achlys") {
                if part.is_empty() {
                    continue;
                }
                let msg = format!("[achlys{}", part.trim());
                // Detect stage transitions
                if part.contains("escalating") && part.contains("AI Hybrid") {
                    self.mode = "AI Hybrid".to_string();
                    self.log(msg);
                    continue;
                } else if part.contains("de-escalating") && part.contains("Havoc") {
                    self.mode = "Havoc".to_string();
                    self.log(msg);
                    continue;
                }
                if msg.len() > 10 {
                    self.log(msg);
                }
            }
        }

        // Extract event name from [EVENT #ID]
        if let Some(bracket_end) = stats_str.find(']')
            && let Some(bracket_start) = stats_str.find('[')
            && bracket_start < bracket_end
        {
            let event_part = &stats_str[bracket_start + 1..bracket_end];
            if let Some(space_idx) = event_part.find(" #") {
                self.stats.last_event = event_part[..space_idx].to_string();
            }
        }

        // Parse key-value pairs
        if let Some(i) = stats_str.find(']') {
            let pairs = &stats_str[i + 2..];
            for part in pairs.split(", ") {
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
}

pub struct AchlysTui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    state: Arc<Mutex<TuiState>>,
}

impl AchlysTui {
    pub fn init(target_name: String, mode: String) -> io::Result<(Self, Arc<Mutex<TuiState>>)> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        let state = Arc::new(Mutex::new(TuiState::new(target_name, mode)));
        let state_clone = state.clone();

        // Spawn key event polling thread for Ctrl+C / q quit
        // In raw mode, Ctrl+C is a key event, not a signal
        std::thread::spawn(|| {
            loop {
                if let Ok(true) = event::poll(Duration::from_millis(200))
                    && let Ok(Event::Key(key)) = event::read()
                {
                    let quit = key.code == KeyCode::Char('q')
                        || (key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL));
                    if quit {
                        let _ = disable_raw_mode();
                        let _ = execute!(io::stdout(), LeaveAlternateScreen);
                        std::process::exit(0);
                    }
                }
            }
        });

        Ok((Self { terminal, state }, state_clone))
    }

    pub fn draw(&mut self) -> io::Result<()> {
        let state = self.state.lock().unwrap();

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
            render_ui(frame, frame.area(), &RenderData {
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
    let red = Style::default().fg(Color::Red);
    let white = Style::default().fg(Color::White);
    let dim = Style::default().fg(Color::DarkGray);
    let border = Style::default().fg(Color::DarkGray);

    let mode_color = if d.mode.contains("AI") {
        Color::Magenta
    } else if d.mode.contains("havoc") || d.mode.contains("Havoc") {
        Color::Yellow
    } else {
        Color::Green
    };

    // Layout: header + stats + logs
    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(8),
        ])
        .split(area);

    // Header
    let header = Paragraph::new(vec![Line::from(vec![
        Span::styled(" target: ", dim),
        Span::styled(d.target, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled("    uptime: ", dim),
        Span::styled(d.uptime, green),
        Span::styled("    stage: ", dim),
        Span::styled(d.mode, Style::default().fg(mode_color).add_modifier(Modifier::BOLD)),
    ])])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" achlys ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)))
            .border_style(border),
    );
    frame.render_widget(header, main[0]);

    // Stats 2x2
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main[1]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(cols[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(cols[1]);

    let speed = format!("{}/sec", d.execs_per_sec);
    let obj_style = if d.objectives == "0" { dim } else { red };

    frame.render_widget(stat_block(" process timing ", Color::Cyan, &[
        ("run time", d.run_time, cyan),
        ("total execs", d.total_execs, white),
        ("exec speed", &speed, green),
        ("last event", d.last_event, dim),
    ]), left[0]);

    frame.render_widget(stat_block(" overall results ", Color::Green, &[
        ("corpus count", d.corpus, white),
        ("crashes", d.objectives, obj_style),
        ("total execs", d.total_execs, white),
    ]), right[0]);

    frame.render_widget(stat_block(" stage info ", Color::Yellow, &[
        ("current stage", d.mode, Style::default().fg(mode_color)),
        ("exec speed", &speed, green),
    ]), left[1]);

    frame.render_widget(stat_block(" status ", Color::Magenta, &[
        ("corpus", d.corpus, white),
        ("crashes", d.objectives, obj_style),
        ("speed", &speed, green),
    ]), right[1]);

    // Logs
    let log_lines: Vec<Line> = d.logs.iter().rev().take(6).rev().map(|msg| {
        let color = if msg.contains("escalat") {
            Color::Magenta
        } else if msg.contains("error") || msg.contains("failed") {
            Color::Red
        } else if msg.contains("loaded") || msg.contains("started") || msg.contains("training") {
            Color::Green
        } else {
            Color::DarkGray
        };
        Line::from(Span::styled(format!("  {msg}"), Style::default().fg(color)))
    }).collect();

    frame.render_widget(
        Paragraph::new(log_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(" logs ", Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)))
                .border_style(border),
        ),
        main[2],
    );
}

fn stat_block<'a>(title: &'a str, color: Color, entries: &[(&'a str, &'a str, Style)]) -> Paragraph<'a> {
    let lines: Vec<Line> = entries.iter().map(|(k, v, s)| {
        let dots = ".".repeat(20usize.saturating_sub(k.len()));
        Line::from(vec![
            Span::styled(format!("  {k} "), Style::default().fg(Color::DarkGray)),
            Span::styled(dots, Style::default().fg(Color::DarkGray)),
            Span::raw(" "),
            Span::styled((*v).to_string(), *s),
        ])
    }).collect();

    Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(title, Style::default().fg(color).add_modifier(Modifier::BOLD)))
            .border_style(Style::default().fg(Color::DarkGray)),
    )
}

fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000 { format!("{:.1}M", n as f64 / 1e6) }
    else if n >= 1_000 { format!("{:.1}K", n as f64 / 1e3) }
    else { n.to_string() }
}

pub fn create_tui_callback(
    state: Arc<Mutex<TuiState>>,
    tui: Arc<Mutex<AchlysTui>>,
    log_sink: achlys_core::SharedLogSink,
) -> impl FnMut(&str) {
    move |stats_str: &str| {
        if let Ok(mut s) = state.lock() {
            s.update_from_stats(stats_str);

            // Drain escalation logs from the shared sink
            if let Ok(mut logs) = log_sink.lock() {
                while let Some(msg) = logs.pop_front() {
                    // Detect stage changes
                    if msg.contains("escalating") && msg.contains("AI Hybrid") {
                        s.mode = "AI Hybrid".to_string();
                    } else if msg.contains("de-escalating") && msg.contains("Havoc") {
                        s.mode = "Havoc".to_string();
                    }
                    s.log(msg);
                }
            }
        }
        if let Ok(mut t) = tui.lock() {
            let _ = t.draw();
        }
    }
}
