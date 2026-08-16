use std::fmt;
use std::io;
use std::path::PathBuf;

use libafl::executors::ExitKind;

/// Launch or I/O failure. Not a target crash, timeout, or successful run.
#[derive(Debug)]
pub enum InfraError {
    MissingBinary { path: PathBuf },
    Spawn { path: PathBuf, source: io::Error },
    Write { source: io::Error },
    Wait { source: io::Error },
}

impl fmt::Display for InfraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBinary { path } => {
                write!(f, "target binary not found: {}", path.display())
            }
            Self::Spawn { path, source } => {
                write!(f, "failed to spawn {}: {source}", path.display())
            }
            Self::Write { source } => write!(f, "failed to write target input: {source}"),
            Self::Wait { source } => write!(f, "failed to wait for target: {source}"),
        }
    }
}

impl std::error::Error for InfraError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingBinary { .. } => None,
            Self::Spawn { source, .. } | Self::Write { source } | Self::Wait { source } => {
                Some(source)
            }
        }
    }
}

/// Abstraction over how Achlys talks to a fuzzing target.
///
/// The engine sends bytes and reads coverage — it never knows
/// whether it's fuzzing an inline library, a spawned binary, or a network service.
pub trait Target {
    /// Execute the target with the given input bytes.
    ///
    /// Crashes and timeouts are `Ok(ExitKind)`. Spawn, write, wait, and
    /// missing-binary failures are `Err(InfraError)` — not successful runs.
    fn execute(&mut self, input: &[u8]) -> Result<ExitKind, InfraError>;

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
