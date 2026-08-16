//! Off-hot-path sanitizer replay and crash deduplication (Master Plan §16).
//!
//! Verification only: compile with ASan/UBSan and replay a candidate input.
//! This is not a fuzz executor and must not sit on the H0 throughput path.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use achlys_protocol::InputId;
use anyhow::{Context, Result, bail};

use crate::target::InfraError;

/// Unix signals treated as a target crash (same set as `ForkExecTarget`).
#[cfg(unix)]
mod signals {
    pub const SIGILL: i32 = 4;
    pub const SIGABRT: i32 = 6;
    pub const SIGBUS: i32 = 7;
    pub const SIGFPE: i32 = 8;
    pub const SIGSEGV: i32 = 11;
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_STDERR: usize = 64 * 1024;

/// Apple clang defaults `handle_abort=0`, so `abort()` is otherwise silent.
/// `detect_leaks=0` keeps Clean runs free of leak-checker noise.
const ASAN_OPTIONS: &str = "abort_on_error=1:detect_leaks=0:handle_abort=1:disable_coredump=1";
const UBSAN_OPTIONS: &str = "print_stacktrace=1:halt_on_error=1:abort_on_error=1";

/// Tiny stdin/hex-argv driver. Same contract as `micro.rs` so existing
/// `achlys_micro_<name>` targets can be linked without changing them.
const DRIVER_C: &str = r#"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ACHLYS_MICRO_FN
#error "ACHLYS_MICRO_FN must name the target function"
#endif

int ACHLYS_MICRO_FN(const uint8_t *data, size_t len);

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(const char *s, uint8_t *out, size_t cap, size_t *n) {
    size_t len = strlen(s);
    if (len == 0 || (len % 2) != 0) {
        return 0;
    }
    size_t need = len / 2;
    if (need > cap) {
        return 0;
    }
    for (size_t i = 0; i < need; i++) {
        int hi = hex_nibble((unsigned char)s[2 * i]);
        int lo = hex_nibble((unsigned char)s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *n = need;
    return 1;
}

int main(int argc, char **argv) {
    uint8_t buf[4096];
    size_t n = 0;

    if (argc >= 2) {
        if (!decode_hex(argv[1], buf, sizeof(buf), &n)) {
            n = strlen(argv[1]);
            if (n > sizeof(buf)) {
                n = sizeof(buf);
            }
            memcpy(buf, argv[1], n);
        }
    } else {
        n = fread(buf, 1, sizeof(buf), stdin);
    }

    return ACHLYS_MICRO_FN(buf, n);
}
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayClass {
    ReproducibleCrash,
    Timeout,
    /// Ran to completion with no crash signal or sanitizer abort.
    /// Nonzero exit without a signal is Clean, not a crash.
    Clean,
    InfraFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    pub class: ReplayClass,
    pub signal: Option<i32>,
    pub exit_code: Option<i32>,
    pub stderr: String,
    pub stderr_digest: [u8; 32],
    pub stack_signature: Option<String>,
}

pub struct SanitizerReplayer {
    binary: PathBuf,
    timeout: Duration,
    max_stderr_bytes: usize,
}

impl SanitizerReplayer {
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            timeout: DEFAULT_TIMEOUT,
            max_stderr_bytes: DEFAULT_MAX_STDERR,
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_max_stderr(mut self, n: usize) -> Self {
        self.max_stderr_bytes = n;
        self
    }

    /// Compile `benchmarks/micro/<name>.c` plus a stdin/hex driver with
    /// `clang -O0 -g -fsanitize=address,undefined` into `out_dir/<name>_asan`.
    pub fn compile_micro(name: &str, out_dir: &Path) -> Result<PathBuf> {
        if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
            bail!("invalid micro target name: {name:?}");
        }

        let src = micro_src_dir().join(format!("{name}.c"));
        if !src.is_file() {
            bail!("missing micro source {}", src.display());
        }

        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("create {}", out_dir.display()))?;

        let driver = out_dir.join(format!("{name}_driver.c"));
        std::fs::write(&driver, DRIVER_C).with_context(|| format!("write {}", driver.display()))?;

        let path = out_dir.join(format!("{name}_asan"));
        let output = Command::new("clang")
            .args(["-O0", "-g", "-fsanitize=address,undefined", "-o"])
            .arg(&path)
            .arg(&driver)
            .arg(&src)
            .arg(format!("-DACHLYS_MICRO_FN=achlys_micro_{name}"))
            .output()
            .context("failed to run clang (is it installed?)")?;

        if !output.status.success() {
            bail!(
                "clang sanitizer build failed for {name}: {}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if !path.is_file() {
            bail!("clang produced no binary at {}", path.display());
        }
        Ok(path)
    }

    /// Compile vendored cJSON + `harness_afl.c` with ASan/UBSan into
    /// `out_dir/cjson_asan`. Verification only — not a throughput worker.
    pub fn compile_cjson(out_dir: &Path) -> Result<PathBuf> {
        let cjson = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/targets/cJSON");
        let src = cjson.join("cJSON.c");
        let harness = cjson.join("harness_afl.c");
        if !src.is_file() || !harness.is_file() {
            bail!("missing cJSON sources under {}", cjson.display());
        }

        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("create {}", out_dir.display()))?;

        let driver = out_dir.join("cjson_stdin_driver.c");
        std::fs::write(
            &driver,
            r#"
#include <stdint.h>
#include <stdio.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(void) {
    uint8_t buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    return LLVMFuzzerTestOneInput(buf, n);
}
"#,
        )
        .with_context(|| format!("write {}", driver.display()))?;

        let path = out_dir.join("cjson_asan");
        let output = Command::new("clang")
            .args(["-O0", "-g", "-fsanitize=address,undefined", "-o"])
            .arg(&path)
            .arg("-I")
            .arg(&cjson)
            .arg(&harness)
            .arg(&src)
            .arg(&driver)
            .output()
            .context("failed to run clang (is it installed?)")?;
        if !output.status.success() {
            bail!(
                "clang sanitizer build failed for cJSON: {}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if !path.is_file() {
            bail!("clang produced no binary at {}", path.display());
        }
        Ok(path)
    }

    /// Replay `input` on stdin. Missing binary / spawn failure is `Err`,
    /// not `Clean`. Timeout kills the child process group.
    pub fn replay(&self, input: &[u8]) -> Result<ReplayReport, InfraError> {
        if !self.binary.is_file() {
            return Err(InfraError::MissingBinary {
                path: self.binary.clone(),
            });
        }

        let mut cmd = Command::new(&self.binary);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("ASAN_OPTIONS", ASAN_OPTIONS)
            .env("UBSAN_OPTIONS", UBSAN_OPTIONS)
            .env("MallocNanoZone", "0");

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(InfraError::MissingBinary {
                    path: self.binary.clone(),
                });
            }
            Err(source) => {
                return Err(InfraError::Spawn {
                    path: self.binary.clone(),
                    source,
                });
            }
        };

        let pid = child.id();

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input);
        }

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let max = self.max_stderr_bytes;
        let reader = std::thread::spawn(move || drain_stdio(stdout, stderr, max));

        match wait_timeout(&mut child, self.timeout) {
            Ok(None) => {
                kill_process_group(pid);
                let _ = child.kill();
                let _ = child.wait();
                let bytes = reader.join().unwrap_or_default();
                Ok(build_report(ReplayClass::Timeout, None, None, bytes))
            }
            Ok(Some(status)) => {
                let bytes = reader.join().unwrap_or_default();
                Ok(classify(status, bytes))
            }
            Err(source) => {
                kill_process_group(pid);
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                Err(InfraError::Wait { source })
            }
        }
    }
}

/// Normalize ASan/UBSan/abort stacks: drop hex addresses, keep function/file
/// frames. `None` if no stack-like content.
pub fn normalize_stack_signature(stderr: &str) -> Option<String> {
    let mut frames = Vec::new();
    for line in stderr.lines() {
        if is_frame_line(line) {
            let normalized = collapse_paths(&strip_build_ids(&strip_hex_addresses(line.trim())));
            if !normalized.is_empty() {
                frames.push(normalized);
            }
        }
    }
    if frames.is_empty() {
        None
    } else {
        Some(frames.join("\n"))
    }
}

/// Dedup key: stack signature if present, else hex(stderr digest), else class.
pub fn dedup_key(report: &ReplayReport) -> String {
    if let Some(sig) = &report.stack_signature
        && !sig.is_empty()
    {
        return sig.clone();
    }
    if !report.stderr.is_empty() {
        return InputId(report.stderr_digest).to_hex();
    }
    class_name(report.class).to_string()
}

fn class_name(class: ReplayClass) -> &'static str {
    match class {
        ReplayClass::ReproducibleCrash => "ReproducibleCrash",
        ReplayClass::Timeout => "Timeout",
        ReplayClass::Clean => "Clean",
        ReplayClass::InfraFailure => "InfraFailure",
    }
}

fn micro_src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/micro")
}

fn build_report(
    class: ReplayClass,
    signal: Option<i32>,
    exit_code: Option<i32>,
    bytes: Vec<u8>,
) -> ReplayReport {
    let stderr = String::from_utf8_lossy(&bytes).into_owned();
    let stderr_digest = InputId::from_bytes(stderr.as_bytes()).0;
    let stack_signature = normalize_stack_signature(&stderr);
    ReplayReport {
        class,
        signal,
        exit_code,
        stderr,
        stderr_digest,
        stack_signature,
    }
}

fn classify(status: ExitStatus, bytes: Vec<u8>) -> ReplayReport {
    let stderr_preview = String::from_utf8_lossy(&bytes);
    let asan_abort = sanitizer_aborted(&stderr_preview);

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            let class = if is_crash_signal(signal) || asan_abort {
                ReplayClass::ReproducibleCrash
            } else {
                ReplayClass::InfraFailure
            };
            return build_report(class, Some(signal), None, bytes);
        }
        let class = if asan_abort {
            ReplayClass::ReproducibleCrash
        } else {
            ReplayClass::Clean
        };
        build_report(class, None, status.code(), bytes)
    }

    #[cfg(not(unix))]
    {
        let class = if asan_abort {
            ReplayClass::ReproducibleCrash
        } else {
            ReplayClass::Clean
        };
        build_report(class, None, status.code(), bytes)
    }
}

#[cfg(unix)]
fn is_crash_signal(signal: i32) -> bool {
    matches!(
        signal,
        signals::SIGILL | signals::SIGABRT | signals::SIGBUS | signals::SIGFPE | signals::SIGSEGV
    )
}

fn sanitizer_aborted(stderr: &str) -> bool {
    const MARKS: &[&str] = &[
        "ERROR: AddressSanitizer:",
        "ERROR: UndefinedBehaviorSanitizer:",
        "ERROR: MemorySanitizer:",
        "AddressSanitizer:DEADLYSIGNAL",
        "SUMMARY: AddressSanitizer:",
        "SUMMARY: UndefinedBehaviorSanitizer:",
    ];
    MARKS.iter().any(|m| stderr.contains(m))
}

fn is_frame_line(line: &str) -> bool {
    let t = line.trim_start();
    let Some(rest) = t.strip_prefix('#') else {
        return false;
    };
    rest.bytes().next().is_some_and(|b| b.is_ascii_digit())
}

fn strip_hex_addresses(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let plus = b[i] == b'+';
        let start = i + usize::from(plus);
        if start + 2 <= b.len()
            && b[start] == b'0'
            && (b[start + 1] == b'x' || b[start + 1] == b'X')
        {
            let mut j = start + 2;
            while j < b.len() && b[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > start + 2 {
                i = j;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    collapse_ws(&out)
}

fn strip_build_ids(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'('
            && s[i..].starts_with("(BuildId:")
            && let Some(end) = s[i..].find(')')
        {
            i += end + 1;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    collapse_ws(&out)
}

/// Keep `file:line` / basename, drop `/tmp/...` rebuild paths.
fn collapse_paths(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, token) in s.split_whitespace().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if let Some((_, tail)) = token.rsplit_once('/') {
            out.push_str(tail);
        } else {
            out.push_str(token);
        }
    }
    out
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            prev_space = false;
            out.push(c);
        }
    }
    out.trim().to_string()
}

fn drain_stdio(
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
    max: usize,
) -> Vec<u8> {
    let err_h = stderr.map(|pipe| std::thread::spawn(move || read_capped(pipe, max)));
    let out_h = stdout.map(|pipe| std::thread::spawn(move || read_capped(pipe, max)));

    let mut combined = Vec::new();
    if let Some(h) = err_h
        && let Ok(buf) = h.join()
    {
        combined.extend(buf);
    }
    if let Some(h) = out_h
        && let Ok(buf) = h.join()
    {
        combined.extend(buf);
    }
    if combined.len() > max {
        combined.truncate(max);
    }
    combined
}

fn read_capped(mut pipe: impl Read, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < max {
                    let take = n.min(max - out.len());
                    out.extend_from_slice(&buf[..take]);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    out
}

fn wait_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> io::Result<Option<ExitStatus>> {
    let start = Instant::now();
    let poll = Duration::from_millis(1);
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(Some(status)),
            None if start.elapsed() >= timeout => return Ok(None),
            None => std::thread::sleep(poll),
        }
    }
}

fn kill_process_group(pid: u32) {
    #[cfg(unix)]
    {
        if pid > 1 {
            // SAFETY: child was spawned with process_group(0), so pid == pgid.
            unsafe {
                libc::killpg(pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    static HARNESS: Mutex<()> = Mutex::new(());
    static BUILD_SEQ: AtomicU64 = AtomicU64::new(0);

    struct Built {
        dir: PathBuf,
        path: PathBuf,
    }

    impl Drop for Built {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn compile_locked(name: &str) -> Built {
        let seq = BUILD_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("achlys_asan_{name}_{}_{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create sanitizer build dir");
        let path = SanitizerReplayer::compile_micro(name, &dir).expect("compile sanitizer micro");
        Built { dir, path }
    }

    fn replay_micro(name: &str, input: &[u8], timeout: Duration) -> ReplayReport {
        let _guard = HARNESS.lock().unwrap_or_else(|e| e.into_inner());
        let built = compile_locked(name);
        SanitizerReplayer::new(&built.path)
            .with_timeout(timeout)
            .replay(input)
            .expect("sanitizer replay")
    }

    const FAST: Duration = Duration::from_secs(5);
    const HANG: Duration = Duration::from_millis(300);

    #[test]
    fn crash_if_magic_bug_is_reproducible_crash() {
        let _guard = HARNESS.lock().unwrap_or_else(|e| e.into_inner());
        let built = compile_locked("crash_if_magic");
        let replayer = SanitizerReplayer::new(&built.path).with_timeout(FAST);
        let report = replayer.replay(b"BUG!").expect("BUG!");
        assert_eq!(report.class, ReplayClass::ReproducibleCrash);
        assert!(
            report.stack_signature.is_some(),
            "expected stack signature, stderr was:\n{}",
            report.stderr
        );
        let again = replayer.replay(b"BUG!").expect("BUG! again");
        assert_eq!(
            dedup_key(&report),
            dedup_key(&again),
            "dedup_key must be stable on one binary"
        );
    }

    #[test]
    fn crash_if_magic_safe_is_clean() {
        let report = replay_micro("crash_if_magic", b"safe", FAST);
        assert_eq!(report.class, ReplayClass::Clean);
        assert!(report.signal.is_none());
    }

    #[test]
    fn rebuild_same_source_shares_normalized_key() {
        let _guard = HARNESS.lock().unwrap_or_else(|e| e.into_inner());
        let first = compile_locked("crash_if_magic");
        let a = SanitizerReplayer::new(&first.path)
            .with_timeout(FAST)
            .replay(b"BUG!")
            .expect("first rebuild");
        let second = compile_locked("crash_if_magic");
        let b = SanitizerReplayer::new(&second.path)
            .with_timeout(FAST)
            .replay(b"BUG!")
            .expect("second rebuild");
        assert_eq!(a.class, ReplayClass::ReproducibleCrash);
        assert_eq!(b.class, ReplayClass::ReproducibleCrash);
        assert_eq!(
            dedup_key(&a),
            dedup_key(&b),
            "rebuild paths/BuildId must not change the key\n--- a ---\n{}\n--- b ---\n{}",
            a.stack_signature.as_deref().unwrap_or(""),
            b.stack_signature.as_deref().unwrap_or("")
        );
    }

    #[test]
    fn same_abort_site_shares_dedup_key() {
        let _guard = HARNESS.lock().unwrap_or_else(|e| e.into_inner());
        let built = compile_locked("crash_if_magic");
        let replayer = SanitizerReplayer::new(&built.path).with_timeout(FAST);
        let a = replayer.replay(b"BUG!").expect("BUG!");
        let b = replayer.replay(b"BUG!xxxx").expect("BUG!xxxx");
        assert_eq!(a.class, ReplayClass::ReproducibleCrash);
        assert_eq!(b.class, ReplayClass::ReproducibleCrash);
        assert!(a.stack_signature.is_some());
        assert!(b.stack_signature.is_some());
        assert_eq!(
            dedup_key(&a),
            dedup_key(&b),
            "same abort site must share a key\n--- a ---\n{}\n--- b ---\n{}",
            a.stderr,
            b.stderr
        );
    }

    #[test]
    fn timeout_hang_is_timeout() {
        let report = replay_micro("timeout_hang", b"HANG", HANG);
        assert_eq!(report.class, ReplayClass::Timeout);
        assert!(report.signal.is_none());
        assert!(report.exit_code.is_none());
    }

    #[test]
    fn cjson_seed_is_clean() {
        let _guard = HARNESS.lock().unwrap_or_else(|e| e.into_inner());
        let seq = BUILD_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("achlys_asan_cjson_{}_{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create cjson asan dir");
        let path = SanitizerReplayer::compile_cjson(&dir).expect("compile cjson asan");
        let report = SanitizerReplayer::new(&path)
            .with_timeout(FAST)
            .replay(br#"{"a":1}"#)
            .expect("replay cjson seed");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(report.class, ReplayClass::Clean);
    }

    #[test]
    fn missing_binary_is_infra_error() {
        let err = SanitizerReplayer::new("/no/such/achlys_asan_binary")
            .replay(b"")
            .expect_err("missing binary must be an infrastructure failure");
        assert!(matches!(err, InfraError::MissingBinary { .. }));
    }

    #[test]
    fn normalize_stack_signature_strips_hex_addresses() {
        let a = "\
==11==ERROR: AddressSanitizer: ABRT on unknown address 0xaaa (pc 0xaaa bp 0xbbb sp 0xccc T0)
    #0 0x0000aaaa in abort+0x10 (libc.so.6+0x1111)
    #1 0x0000bbbb in achlys_micro_crash_if_magic crash_if_magic.c:10
    #2 0x0000cccc in main driver.c:70
";
        let b = "\
==22==ERROR: AddressSanitizer: ABRT on unknown address 0xddd (pc 0xeee bp 0xfff sp 0x123 T0)
    #0 0x0000dddd in abort+0x20 (libc.so.6+0x2222)
    #1 0x0000eeee in achlys_micro_crash_if_magic crash_if_magic.c:10
    #2 0x0000ffff in main driver.c:70
";
        let na = normalize_stack_signature(a).expect("stack a");
        let nb = normalize_stack_signature(b).expect("stack b");
        assert_eq!(na, nb);
        assert!(!na.contains("0x") && !na.contains("0X"));
        assert!(na.contains("achlys_micro_crash_if_magic"));
        assert!(na.contains("crash_if_magic.c:10"));

        let rebuilt_a = "    #4 0x1 in main /tmp/achlys_asan_crash_if_magic_1/crash_if_magic_driver.c:57:12 (BuildId: aaaa)";
        let rebuilt_b = "    #4 0x2 in main /tmp/achlys_asan_crash_if_magic_2/crash_if_magic_driver.c:57:12 (BuildId: bbbb)";
        assert_eq!(
            normalize_stack_signature(rebuilt_a),
            normalize_stack_signature(rebuilt_b)
        );
        assert!(normalize_stack_signature("no frames, just noise 0xdead").is_none());
    }
}
