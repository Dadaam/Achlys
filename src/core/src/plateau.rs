use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Tracks coverage growth over time and detects when the fuzzer is stuck.
///
/// A plateau is declared when no new coverage edges have been found
/// for `timeout` duration. This is the trigger for escalation to a
/// smarter (but slower) fuzzing strategy.
#[derive(Debug)]
pub struct PlateauDetector {
    timeout: Duration,
    last_new_coverage: Instant,
    total_edges: usize,
    in_plateau: bool,
}

impl PlateauDetector {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            last_new_coverage: Instant::now(),
            total_edges: 0,
            in_plateau: false,
        }
    }

    /// Called when the feedback reports new coverage.
    pub fn on_new_coverage(&mut self, total_edges: usize) {
        self.last_new_coverage = Instant::now();
        self.total_edges = total_edges;
        self.in_plateau = false;
    }

    /// Check if we've hit a plateau (no new coverage for `timeout`).
    pub fn check(&mut self) -> bool {
        if !self.in_plateau && self.last_new_coverage.elapsed() >= self.timeout {
            self.in_plateau = true;
        }
        self.in_plateau
    }

    /// Reset after de-escalation (coverage resumed).
    pub fn reset(&mut self) {
        self.last_new_coverage = Instant::now();
        self.in_plateau = false;
    }

    pub fn total_edges(&self) -> usize {
        self.total_edges
    }

    pub fn is_in_plateau(&self) -> bool {
        self.in_plateau
    }
}

/// Shared handle to a PlateauDetector.
pub type SharedPlateauDetector = Arc<Mutex<PlateauDetector>>;

/// Create a new shared plateau detector.
pub fn shared_detector(timeout: Duration) -> SharedPlateauDetector {
    Arc::new(Mutex::new(PlateauDetector::new(timeout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_plateau_initially() {
        let mut detector = PlateauDetector::new(Duration::from_secs(10));
        assert!(!detector.check());
        assert!(!detector.is_in_plateau());
    }

    #[test]
    fn test_plateau_after_timeout() {
        let mut detector = PlateauDetector::new(Duration::from_millis(50));
        assert!(!detector.check());

        std::thread::sleep(Duration::from_millis(60));
        assert!(detector.check());
        assert!(detector.is_in_plateau());
    }

    #[test]
    fn test_coverage_resets_plateau() {
        let mut detector = PlateauDetector::new(Duration::from_millis(50));

        std::thread::sleep(Duration::from_millis(60));
        assert!(detector.check());

        detector.on_new_coverage(42);
        assert!(!detector.check());
        assert!(!detector.is_in_plateau());
        assert_eq!(detector.total_edges(), 42);
    }

    #[test]
    fn test_reset() {
        let mut detector = PlateauDetector::new(Duration::from_millis(50));

        std::thread::sleep(Duration::from_millis(60));
        assert!(detector.check());

        detector.reset();
        assert!(!detector.check());
    }
}
