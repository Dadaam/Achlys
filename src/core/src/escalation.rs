use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use libafl::{stages::Stage, stages::Restartable, Error};

use crate::plateau::SharedPlateauDetector;

/// Shared log sink for escalation events (readable by the TUI).
pub type SharedLogSink = Arc<Mutex<VecDeque<String>>>;

/// Create a new shared log sink.
pub fn shared_log_sink() -> SharedLogSink {
    Arc::new(Mutex::new(VecDeque::with_capacity(50)))
}

/// Check escalation state every N executions (avoids mutex contention).
const DEFAULT_CHECK_INTERVAL: usize = 1000;

/// The current fuzzing strategy stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzStage {
    /// Stage 1: Random mutations at maximum speed.
    Havoc,
    /// Stage 2: AI-guided mutations mixed with havoc.
    AiHybrid,
    /// Stage 3: Constraint solving for hard branches (future).
    Symbolic,
}

impl fmt::Display for FuzzStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzStage::Havoc => write!(f, "Havoc"),
            FuzzStage::AiHybrid => write!(f, "AI Hybrid"),
            FuzzStage::Symbolic => write!(f, "Symbolic"),
        }
    }
}

/// Manages stage transitions based on coverage plateau detection.
///
/// Transitions:
/// - Havoc → AiHybrid: plateau detected AND cortex available
/// - AiHybrid → Havoc: coverage resumes (de-escalation)
pub struct EscalationManager {
    current_stage: FuzzStage,
    detector: SharedPlateauDetector,
    has_ai: bool,
    log_sink: Option<SharedLogSink>,
}

impl EscalationManager {
    pub fn new(detector: SharedPlateauDetector, has_ai: bool) -> Self {
        Self {
            current_stage: FuzzStage::Havoc,
            detector,
            has_ai,
            log_sink: None,
        }
    }

    /// Set a shared log sink for escalation events.
    pub fn set_log_sink(&mut self, sink: SharedLogSink) {
        self.log_sink = Some(sink);
    }

    fn emit_log(&self, msg: String) {
        eprintln!("{msg}");
        if let Some(ref sink) = self.log_sink
            && let Ok(mut logs) = sink.lock()
        {
            if logs.len() >= 50 {
                logs.pop_front();
            }
            logs.push_back(msg);
        }
    }

    /// Check if escalation/de-escalation is needed. Returns the stage to use.
    pub fn tick(&mut self) -> FuzzStage {
        let in_plateau = self
            .detector
            .lock()
            .map(|mut d| d.check())
            .unwrap_or(false);

        let previous = self.current_stage;

        match self.current_stage {
            FuzzStage::Havoc => {
                if in_plateau && self.has_ai {
                    self.current_stage = FuzzStage::AiHybrid;
                    self.emit_log(format!(
                        "[achlys] escalating: {} -> {} (plateau detected)",
                        previous, self.current_stage
                    ));
                }
            }
            FuzzStage::AiHybrid => {
                if !in_plateau {
                    self.current_stage = FuzzStage::Havoc;
                    self.emit_log(format!(
                        "[achlys] de-escalating: {} -> {} (coverage resumed)",
                        previous, self.current_stage
                    ));
                }
            }
            FuzzStage::Symbolic => {
                // Future: de-escalate when symbolic finds new paths
            }
        }

        self.current_stage
    }

    pub fn current_stage(&self) -> FuzzStage {
        self.current_stage
    }
}

/// A LibAFL Stage that delegates to either havoc or AI stage
/// based on the escalation manager's decision.
///
/// Checks escalation every `check_interval` executions to avoid
/// lock contention on the plateau detector mutex.
pub struct EscalatingStage<H, A> {
    havoc_stage: H,
    ai_stage: Option<A>,
    manager: EscalationManager,
    check_interval: usize,
    exec_count: usize,
    log_sink: Option<SharedLogSink>,
}

impl<H, A> EscalatingStage<H, A> {
    /// Create an escalating stage with only havoc (no AI available).
    #[must_use]
    pub fn havoc_only(havoc_stage: H, detector: SharedPlateauDetector) -> Self {
        Self {
            havoc_stage,
            ai_stage: None,
            manager: EscalationManager::new(detector, false),
            check_interval: DEFAULT_CHECK_INTERVAL,
            exec_count: 0,
            log_sink: None,
        }
    }

    /// Create an escalating stage with both havoc and AI stages.
    #[must_use]
    pub fn with_ai(
        havoc_stage: H,
        ai_stage: A,
        detector: SharedPlateauDetector,
    ) -> Self {
        Self {
            havoc_stage,
            ai_stage: Some(ai_stage),
            manager: EscalationManager::new(detector, true),
            check_interval: DEFAULT_CHECK_INTERVAL,
            exec_count: 0,
            log_sink: None,
        }
    }

    /// Attach a shared log sink for escalation events.
    #[must_use]
    pub fn with_log_sink(mut self, sink: SharedLogSink) -> Self {
        self.manager.set_log_sink(sink.clone());
        self.log_sink = Some(sink);
        self
    }

    /// Set how often to check for escalation (every N executions).
    #[must_use]
    pub fn with_check_interval(mut self, interval: usize) -> Self {
        self.check_interval = interval;
        self
    }

    pub fn current_stage(&self) -> FuzzStage {
        self.manager.current_stage()
    }
}

impl<E, EM, S, Z, H, A> Stage<E, EM, S, Z> for EscalatingStage<H, A>
where
    H: Stage<E, EM, S, Z>,
    A: Stage<E, EM, S, Z>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        // Check escalation periodically
        self.exec_count += 1;
        if self.exec_count.is_multiple_of(self.check_interval) {
            self.manager.tick();
        }

        match self.manager.current_stage() {
            FuzzStage::Havoc | FuzzStage::Symbolic => {
                self.havoc_stage.perform(fuzzer, executor, state, manager)
            }
            FuzzStage::AiHybrid => {
                if let Some(ref mut ai) = self.ai_stage {
                    ai.perform(fuzzer, executor, state, manager)
                } else {
                    // Fallback to havoc if no AI stage
                    self.havoc_stage.perform(fuzzer, executor, state, manager)
                }
            }
        }
    }
}

impl<S, H, A> Restartable<S> for EscalatingStage<H, A>
where
    H: Restartable<S>,
    A: Restartable<S>,
{
    // Always delegate to havoc stage for restart tracking.
    // The AI stage's StdMutationalStage doesn't have its RetryCountRestartHelper
    // registered in the state (only the initially active stage gets init_state called).
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        self.havoc_stage.should_restart(state)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        self.havoc_stage.clear_progress(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plateau::shared_detector;
    use std::time::Duration;

    #[test]
    fn test_escalation_manager_starts_at_havoc() {
        let detector = shared_detector(Duration::from_secs(10));
        let manager = EscalationManager::new(detector, true);
        assert_eq!(manager.current_stage(), FuzzStage::Havoc);
    }

    #[test]
    fn test_escalation_on_plateau() {
        let detector = shared_detector(Duration::from_millis(50));
        let mut manager = EscalationManager::new(detector, true);

        // No plateau yet
        assert_eq!(manager.tick(), FuzzStage::Havoc);

        // Wait for plateau
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(manager.tick(), FuzzStage::AiHybrid);
    }

    #[test]
    fn test_no_escalation_without_ai() {
        let detector = shared_detector(Duration::from_millis(50));
        let mut manager = EscalationManager::new(detector, false);

        std::thread::sleep(Duration::from_millis(60));
        // Should stay in Havoc even with plateau because no AI
        assert_eq!(manager.tick(), FuzzStage::Havoc);
    }

    #[test]
    fn test_deescalation_on_new_coverage() {
        let detector = shared_detector(Duration::from_millis(50));
        let mut manager = EscalationManager::new(detector.clone(), true);

        // Trigger plateau
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(manager.tick(), FuzzStage::AiHybrid);

        // Simulate new coverage
        detector.lock().unwrap().on_new_coverage(100);
        assert_eq!(manager.tick(), FuzzStage::Havoc);
    }

    #[test]
    fn test_fuzz_stage_display() {
        assert_eq!(format!("{}", FuzzStage::Havoc), "Havoc");
        assert_eq!(format!("{}", FuzzStage::AiHybrid), "AI Hybrid");
        assert_eq!(format!("{}", FuzzStage::Symbolic), "Symbolic");
    }
}
