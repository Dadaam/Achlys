use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Embedded SanCov callbacks source (same as examples/targets/cJSON/sancov_callbacks.c).
const SANCOV_CALLBACKS: &str = r#"
#include <stdint.h>
#define MAX_EDGES 65536

extern uint8_t EDGES_MAP[MAX_EDGES];
extern unsigned long EDGES_COUNT;

uint8_t EDGES_MAP[MAX_EDGES] = {0};
unsigned long EDGES_COUNT = 0;

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    uint32_t idx = 1;
    while (start < stop) {
        *start = idx;
        start++;
        idx++;
    }
    EDGES_COUNT = (unsigned long)(idx - 1);
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t idx = *guard;
    if (idx > 0 && idx < MAX_EDGES) {
        if (EDGES_MAP[idx] < 255) {
            EDGES_MAP[idx]++;
        }
    }
}
"#;

/// Compiles C/C++ source files with Clang and SanitizeCoverage instrumentation.
///
/// Produces a shared library that can be loaded for in-process graybox fuzzing,
/// or a standalone binary for fork+exec graybox fuzzing.
pub struct AutoCompiler {
    output_dir: PathBuf,
}

impl AutoCompiler {
    /// Create a new compiler targeting the given output directory.
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        Self {
            output_dir: output_dir.into(),
        }
    }

    /// Compile source files into an instrumented static library.
    ///
    /// Returns the path to the compiled `.a` file.
    pub fn compile_static_lib(
        &self,
        sources: &[PathBuf],
        lib_name: &str,
    ) -> Result<PathBuf> {
        if sources.is_empty() {
            bail!("no source files provided");
        }

        fs::create_dir_all(&self.output_dir)
            .context("failed to create output directory")?;

        // Write sancov callbacks to temp file
        let sancov_path = self.output_dir.join("sancov_callbacks.c");
        fs::write(&sancov_path, SANCOV_CALLBACKS)
            .context("failed to write sancov_callbacks.c")?;

        // Compile each source file to .o
        let mut objects = Vec::new();

        for source in sources {
            let obj_name = source
                .file_stem()
                .context("source has no file stem")?
                .to_string_lossy()
                .into_owned()
                + ".o";
            let obj_path = self.output_dir.join(&obj_name);

            let compiler = Self::detect_compiler(source)?;

            let status = Command::new(&compiler)
                .args([
                    "-c",
                    "-O3",
                    "-fsanitize-coverage=trace-pc-guard",
                    "-o",
                ])
                .arg(&obj_path)
                .arg(source)
                .status()
                .with_context(|| format!("failed to run {}", compiler))?;

            if !status.success() {
                bail!(
                    "compilation failed for {}: {} exited with {}",
                    source.display(),
                    compiler,
                    status
                );
            }
            objects.push(obj_path);
        }

        // Compile sancov callbacks (no instrumentation needed for the callbacks themselves)
        let sancov_obj = self.output_dir.join("sancov_callbacks.o");
        let status = Command::new("clang")
            .args(["-c", "-O3", "-o"])
            .arg(&sancov_obj)
            .arg(&sancov_path)
            .status()
            .context("failed to compile sancov_callbacks.c")?;

        if !status.success() {
            bail!("sancov_callbacks.c compilation failed");
        }
        objects.push(sancov_obj);

        // Archive into static lib
        let lib_path = self.output_dir.join(format!("lib{}.a", lib_name));
        let status = Command::new("ar")
            .arg("rcs")
            .arg(&lib_path)
            .args(&objects)
            .status()
            .context("failed to run ar")?;

        if !status.success() {
            bail!("archiving failed for {}", lib_path.display());
        }

        println!(
            "[achlys] compiled {} source file(s) with SanCov → {}",
            sources.len(),
            lib_path.display()
        );

        Ok(lib_path)
    }

    /// Compile source files into an instrumented standalone binary.
    ///
    /// Returns the path to the compiled binary.
    pub fn compile_binary(
        &self,
        sources: &[PathBuf],
        binary_name: &str,
    ) -> Result<PathBuf> {
        if sources.is_empty() {
            bail!("no source files provided");
        }

        fs::create_dir_all(&self.output_dir)
            .context("failed to create output directory")?;

        let sancov_path = self.output_dir.join("sancov_callbacks.c");
        fs::write(&sancov_path, SANCOV_CALLBACKS)
            .context("failed to write sancov_callbacks.c")?;

        let binary_path = self.output_dir.join(binary_name);
        let compiler = Self::detect_compiler(&sources[0])?;

        let mut cmd = Command::new(&compiler);
        cmd.args(["-O3", "-fsanitize-coverage=trace-pc-guard", "-o"])
            .arg(&binary_path);

        for source in sources {
            cmd.arg(source);
        }
        cmd.arg(&sancov_path);

        let status = cmd
            .status()
            .with_context(|| format!("failed to run {}", compiler))?;

        if !status.success() {
            bail!("compilation failed: {} exited with {}", compiler, status);
        }

        println!(
            "[achlys] compiled instrumented binary → {}",
            binary_path.display()
        );

        Ok(binary_path)
    }

    /// Detect whether to use clang or clang++ based on file extension.
    fn detect_compiler(source: &Path) -> Result<String> {
        let ext = source
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("c");

        match ext {
            "c" => Ok("clang".to_string()),
            "cc" | "cpp" | "cxx" | "C" => Ok("clang++".to_string()),
            _ => Ok("clang".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_compiler_c() {
        let result = AutoCompiler::detect_compiler(Path::new("foo.c")).unwrap();
        assert_eq!(result, "clang");
    }

    #[test]
    fn test_detect_compiler_cpp() {
        let result = AutoCompiler::detect_compiler(Path::new("foo.cpp")).unwrap();
        assert_eq!(result, "clang++");
    }

    #[test]
    fn test_detect_compiler_cc() {
        let result = AutoCompiler::detect_compiler(Path::new("bar.cc")).unwrap();
        assert_eq!(result, "clang++");
    }
}
