use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use libafl::executors::ExitKind;

use crate::target::Target;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const FILE_PLACEHOLDER: &str = "@@";

/// How the input is delivered to the target binary.
#[derive(Debug, Clone)]
pub enum InputMethod {
    /// Pipe input bytes to the binary's stdin.
    Stdin,
    /// Replace `@@` in args with a temporary file containing the input.
    FileReplace {
        /// Index of the `@@` placeholder in the args list.
        position: usize,
    },
}

/// Fork+exec target that spawns a binary for each execution.
///
/// Supports two input delivery modes (like AFL++):
/// - **Stdin**: pipe bytes to the process stdin
/// - **FileReplace**: `@@` in args is replaced with a temp file path
///
/// This is blackbox-only (no coverage feedback). The target is evaluated
/// solely by exit code and signals (crash detection).
pub struct ForkExecTarget {
    binary_path: PathBuf,
    args: Vec<String>,
    input_method: InputMethod,
    timeout: Duration,
    temp_dir: PathBuf,
    observer_name: String,
}

impl ForkExecTarget {
    /// Create a new ForkExec target from a binary path and arguments.
    ///
    /// If any argument is `@@`, the input will be delivered via a temporary file
    /// replacing that argument. Otherwise, input is piped to stdin.
    pub fn new(binary: impl Into<PathBuf>, args: Vec<String>) -> Self {
        let input_method = args
            .iter()
            .position(|a| a == FILE_PLACEHOLDER)
            .map(|pos| InputMethod::FileReplace { position: pos })
            .unwrap_or(InputMethod::Stdin);

        let temp_dir = std::env::temp_dir().join("achlys_forkexec");
        let _ = fs::create_dir_all(&temp_dir);

        Self {
            binary_path: binary.into(),
            args,
            input_method,
            timeout: DEFAULT_TIMEOUT,
            temp_dir,
            observer_name: "forkexec".to_string(),
        }
    }

    /// Set the execution timeout per run.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn build_command(&self, input: &[u8]) -> std::io::Result<(Command, Option<PathBuf>)> {
        let mut cmd = Command::new(&self.binary_path);
        let mut temp_file = None;

        match &self.input_method {
            InputMethod::Stdin => {
                cmd.stdin(Stdio::piped());
                cmd.args(&self.args);
            }
            InputMethod::FileReplace { position } => {
                let file_path = self.temp_dir.join("input");
                fs::write(&file_path, input)?;

                let args: Vec<String> = self
                    .args
                    .iter()
                    .enumerate()
                    .map(|(i, arg)| {
                        if i == *position {
                            file_path.to_string_lossy().into_owned()
                        } else {
                            arg.clone()
                        }
                    })
                    .collect();

                cmd.args(&args);
                cmd.stdin(Stdio::null());
                temp_file = Some(file_path);
            }
        }

        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());

        Ok((cmd, temp_file))
    }
}

impl Target for ForkExecTarget {
    fn execute(&mut self, input: &[u8]) -> ExitKind {
        let (mut cmd, temp_file) = match self.build_command(input) {
            Ok(result) => result,
            Err(_) => return ExitKind::Ok,
        };

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(_) => return ExitKind::Ok,
        };

        // Write input to stdin if needed
        if matches!(self.input_method, InputMethod::Stdin) {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input);
                // Drop stdin to close pipe and let the process proceed
            }
        }

        // Wait with timeout
        let result = match child.wait_timeout(self.timeout) {
            Ok(Some(status)) => {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    if let Some(signal) = status.signal() {
                        const SIGILL: i32 = 4;
                        const SIGABRT: i32 = 6;
                        const SIGBUS: i32 = 7;
                        const SIGFPE: i32 = 8;
                        const SIGSEGV: i32 = 11;

                        match signal {
                            SIGILL | SIGABRT | SIGBUS | SIGFPE | SIGSEGV => ExitKind::Crash,
                            _ => ExitKind::Ok,
                        }
                    } else {
                        ExitKind::Ok
                    }
                }
                #[cfg(not(unix))]
                {
                    if status.success() {
                        ExitKind::Ok
                    } else {
                        ExitKind::Crash
                    }
                }
            }
            Ok(None) => {
                // Timed out
                let _ = child.kill();
                let _ = child.wait();
                ExitKind::Timeout
            }
            Err(_) => ExitKind::Ok,
        };

        // Cleanup temp file
        if let Some(path) = temp_file {
            let _ = fs::remove_file(path);
        }

        result
    }

    fn coverage_map(&mut self) -> Option<&mut [u8]> {
        // Blackbox — no coverage
        None
    }

    fn observer_name(&self) -> &str {
        &self.observer_name
    }
}

/// Extension trait for `std::process::Child` to add timeout support.
trait ChildExt {
    fn wait_timeout(&mut self, timeout: Duration) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl ChildExt for std::process::Child {
    fn wait_timeout(&mut self, timeout: Duration) -> std::io::Result<Option<std::process::ExitStatus>> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(1);

        loop {
            match self.try_wait()? {
                Some(status) => return Ok(Some(status)),
                None => {
                    if start.elapsed() >= timeout {
                        return Ok(None);
                    }
                    std::thread::sleep(poll_interval);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stdin_mode_detection() {
        let target = ForkExecTarget::new("/bin/cat", vec![]);
        assert!(matches!(target.input_method, InputMethod::Stdin));
    }

    #[test]
    fn test_file_replace_detection() {
        let target = ForkExecTarget::new(
            "/usr/bin/test_binary",
            vec!["-i".to_string(), "@@".to_string(), "-o".to_string(), "/dev/null".to_string()],
        );
        assert!(matches!(target.input_method, InputMethod::FileReplace { position: 1 }));
    }

    #[test]
    fn test_execute_cat_stdin() {
        let mut target = ForkExecTarget::new("/bin/cat", vec![]);
        let result = target.execute(b"hello world");
        assert!(matches!(result, ExitKind::Ok));
    }

    #[test]
    fn test_execute_false_returns_ok() {
        // /bin/false exits with code 1, but that's not a crash signal
        let mut target = ForkExecTarget::new("/bin/false", vec![]);
        let result = target.execute(b"");
        assert!(matches!(result, ExitKind::Ok));
    }
}
