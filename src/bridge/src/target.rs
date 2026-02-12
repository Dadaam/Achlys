use libafl::executors::ExitKind;

/// Abstraction over how Achlys talks to a fuzzing target.
///
/// The engine sends bytes and reads coverage — it never knows
/// whether it's fuzzing an inline library, a spawned binary, or a network service.
pub trait Target {
    /// Execute the target with the given input bytes.
    fn execute(&mut self, input: &[u8]) -> ExitKind;

    /// Returns a mutable reference to the coverage map, if available.
    /// Returns `None` for blackbox targets (no coverage feedback).
    fn coverage_map(&mut self) -> Option<&mut [u8]>;

    /// Name identifier for the LibAFL observer wrapping this target's coverage.
    fn observer_name(&self) -> &str;

    /// Whether this target provides real coverage feedback.
    fn has_coverage(&mut self) -> bool {
        self.coverage_map().is_some()
    }
}
