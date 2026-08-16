//! Deterministic compile-and-run helper for `benchmarks/micro`.
//!
//! Mechanism correctness only (Master Plan §20.1). Not a performance
//! or superiority claim (§24.6).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use libafl::executors::ExitKind;

use crate::forkexec::ForkExecTarget;
use crate::target::Target;

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

static BUILD_SEQ: AtomicU64 = AtomicU64::new(0);
static HARNESS: Mutex<()> = Mutex::new(());

struct Built {
    dir: PathBuf,
    path: PathBuf,
}

impl Drop for Built {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn micro_src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/micro")
}

fn compile_micro(name: &str) -> Built {
    let seq = BUILD_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("achlys_micro_{name}_{}_{seq}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create micro build dir");

    let src = micro_src_dir().join(format!("{name}.c"));
    assert!(src.is_file(), "missing {}", src.display());

    let driver = dir.join("driver.c");
    fs::write(&driver, DRIVER_C).expect("write micro driver");

    let path = dir.join(name);
    let output = Command::new("clang")
        .args(["-O0", "-g", "-o"])
        .arg(&path)
        .arg(&driver)
        .arg(&src)
        .arg(format!("-DACHLYS_MICRO_FN=achlys_micro_{name}"))
        .output()
        .unwrap_or_else(|err| panic!("failed to run clang (is it installed?): {err}"));
    assert!(
        output.status.success(),
        "clang failed for {name}: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        path.is_file(),
        "clang produced no binary at {}",
        path.display()
    );

    Built { dir, path }
}

fn run_arg(bin: &Path, arg: &str, timeout: Duration) -> ExitKind {
    let mut target =
        ForkExecTarget::new(bin.to_path_buf(), vec![arg.to_string()]).with_timeout(timeout);
    target.execute(b"").expect("micro target execute")
}

/// Compile and run one target. Serialized so a `while (1)` hang cannot
/// starve sibling tests and so macOS crash reporting is not piled up.
fn exec_micro(name: &str, arg: &str, timeout: Duration) -> ExitKind {
    let _guard = HARNESS.lock().unwrap_or_else(|e| e.into_inner());
    let built = compile_micro(name);
    run_arg(&built.path, arg, timeout)
}

const FAST: Duration = Duration::from_millis(800);
const HANG: Duration = Duration::from_millis(150);

#[test]
fn magic_u32_deadbeef_crashes() {
    // 0xDEADBEEF little-endian.
    let kind = exec_micro("magic_u32", "efbeadde", FAST);
    assert!(
        matches!(kind, ExitKind::Crash),
        "expected Crash, got {kind:?}"
    );
}

#[test]
fn magic_u32_other_bytes_ok() {
    let kind = exec_micro("magic_u32", "00000000", FAST);
    assert!(matches!(kind, ExitKind::Ok), "expected Ok, got {kind:?}");
}

#[test]
fn timeout_hang_times_out() {
    let kind = exec_micro("timeout_hang", "HANG", HANG);
    assert!(
        matches!(kind, ExitKind::Timeout),
        "expected Timeout, got {kind:?}"
    );
}

#[test]
fn checksum_wrong_ok() {
    // data[1] == 0x41 but data[0] is not xor(rest).
    let kind = exec_micro("checksum", "0041", FAST);
    assert!(matches!(kind, ExitKind::Ok), "expected Ok, got {kind:?}");
}

#[test]
fn checksum_valid_magic_crashes() {
    // xor(0x41) == 0x41, then second-byte magic.
    let kind = exec_micro("checksum", "4141", FAST);
    assert!(
        matches!(kind, ExitKind::Crash),
        "expected Crash, got {kind:?}"
    );
}

#[test]
fn crash_if_magic_bug_crashes() {
    let kind = exec_micro("crash_if_magic", "BUG!", FAST);
    assert!(
        matches!(kind, ExitKind::Crash),
        "expected Crash, got {kind:?}"
    );
}

#[test]
fn crash_if_magic_other_ok() {
    let kind = exec_micro("crash_if_magic", "safe", FAST);
    assert!(matches!(kind, ExitKind::Ok), "expected Ok, got {kind:?}");
}

#[test]
fn nonzero_exit_nok_is_ok() {
    // Return code 1 is not a crash signal. Mechanism only (§20.1 / §24.6).
    let kind = exec_micro("nonzero_exit", "NOK!", FAST);
    assert!(
        matches!(kind, ExitKind::Ok),
        "nonzero exit must be Ok, not Crash; got {kind:?}"
    );
}

#[test]
fn nonzero_exit_ok_is_ok() {
    let kind = exec_micro("nonzero_exit", "ok", FAST);
    assert!(matches!(kind, ExitKind::Ok), "expected Ok, got {kind:?}");
}

#[test]
fn coverage_stable_abc_ok() {
    let kind = exec_micro("coverage_stable", "ABC", FAST);
    assert!(matches!(kind, ExitKind::Ok), "expected Ok, got {kind:?}");
}

#[test]
fn coverage_stable_xxx_ok() {
    let kind = exec_micro("coverage_stable", "xxx", FAST);
    assert!(matches!(kind, ExitKind::Ok), "expected Ok, got {kind:?}");
}
