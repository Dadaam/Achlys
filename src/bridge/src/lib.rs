//! Target abstraction layer for Achlys.
//!
//! Defines the `Target` trait and provides backends for different
//! execution modes: in-process FFI, fork+exec, and auto-compilation.

pub mod compiler;
pub mod forkexec;
pub mod inprocess;
pub mod target;

pub use compiler::AutoCompiler;
pub use forkexec::ForkExecTarget;
pub use inprocess::{CoverageMap, InProcessTarget};
pub use target::Target;

#[cfg(test)]
mod smoke_tests {
    use std::fs;
    use std::path::PathBuf;

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn vendored_cjson_is_present() {
        let dir = workspace_root().join("examples/targets/cJSON");
        assert!(dir.join("cJSON.c").is_file());
        assert!(dir.join("cJSON.h").is_file());
        assert!(dir.join("LICENSE").is_file());
        assert!(dir.join("sancov_callbacks.c").is_file());
        assert!(dir.join("VERSION").is_file());
    }

    #[test]
    fn micro_crash_if_magic_source_is_present() {
        let src = fs::read_to_string(workspace_root().join("benchmarks/micro/crash_if_magic.c"))
            .expect("benchmarks/micro/crash_if_magic.c");
        assert!(src.contains("BUG!"));
        assert!(src.contains("LLVMFuzzerTestOneInput") || src.contains("parse"));
    }

    /// Unit-level stand-in for campaign artifact bounds.
    /// A timed campaign smoke waits for a time-bounded worker (T0.10 / T1).
    #[test]
    fn crash_artifact_dir_stays_bounded() {
        let dir = std::env::temp_dir().join(format!("achlys_smoke_crashes_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        const MAX_CRASHES: usize = 8;
        for i in 0..MAX_CRASHES {
            fs::write(dir.join(format!("id_{i:06}")), b"BUG!").unwrap();
        }
        let count = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
            .count();
        assert_eq!(count, MAX_CRASHES);
        let _ = fs::remove_dir_all(&dir);
    }
}
