//! Compile measurement artifacts from a target manifest.
//!
//! Fast in-process workers may stay linked into the fuzzer binary. Canonical
//! coverage and sanitizer verification use separately compiled binaries whose
//! bytes are hashed into `BuildIdentity`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use achlys_protocol::{BuildIdentity, BuildKind, Instrumentation, TargetManifest};
use anyhow::{Context, Result, bail};

pub const CANONICAL_MAP_LEN: usize = 65536;

const DUMP_CJSON: &str = r#"
#include <stdint.h>
#include <stdio.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern uint8_t EDGES_MAP[65536];
int main(void) {
    uint8_t buf[65536];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    LLVMFuzzerTestOneInput(buf, n);
    fwrite(EDGES_MAP, 1, 65536, stdout);
    return 0;
}
"#;

const DUMP_MICRO: &str = r#"
#include <stdint.h>
#include <stdio.h>
#ifndef ACHLYS_MICRO_FN
#error "ACHLYS_MICRO_FN must name the target function"
#endif
int ACHLYS_MICRO_FN(const uint8_t *data, size_t len);
extern uint8_t EDGES_MAP[65536];
int main(void) {
    uint8_t buf[65536];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    ACHLYS_MICRO_FN(buf, n);
    fwrite(EDGES_MAP, 1, 65536, stdout);
    return 0;
}
"#;

const STDIN_CJSON: &str = r#"
#include <stdint.h>
#include <stdio.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(void) {
    uint8_t buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    return LLVMFuzzerTestOneInput(buf, n);
}
"#;

const STDIN_MICRO: &str = r#"
#include <stdint.h>
#include <stdio.h>
#ifndef ACHLYS_MICRO_FN
#error "ACHLYS_MICRO_FN must name the target function"
#endif
int ACHLYS_MICRO_FN(const uint8_t *data, size_t len);
int main(void) {
    uint8_t buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    return ACHLYS_MICRO_FN(buf, n);
}
"#;

/// A compiled measurement binary plus the identity of those exact bytes.
#[derive(Debug, Clone)]
pub struct CompiledArtifact {
    pub path: PathBuf,
    pub identity: BuildIdentity,
}

impl CompiledArtifact {
    #[must_use]
    pub fn artifact_hash_hex(&self) -> Option<String> {
        self.identity.artifact_hash.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerTarget {
    CjsonParse,
    MicroCrashIfMagic,
    MicroNonzeroExit,
    MicroCoverageStable,
}

impl WorkerTarget {
    pub fn parse(target_id: &str) -> Result<Self> {
        match target_id {
            "cjson-parse" => Ok(Self::CjsonParse),
            "micro-crash-if-magic" => Ok(Self::MicroCrashIfMagic),
            "micro-nonzero-exit" => Ok(Self::MicroNonzeroExit),
            "micro-coverage-stable" => Ok(Self::MicroCoverageStable),
            other => {
                bail!("unsupported worker target {other:?}; refusing to run a different harness")
            }
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CjsonParse => "cjson-parse",
            Self::MicroCrashIfMagic => "micro-crash-if-magic",
            Self::MicroNonzeroExit => "micro-nonzero-exit",
            Self::MicroCoverageStable => "micro-coverage-stable",
        }
    }

    #[must_use]
    pub fn micro_fn(self) -> Option<&'static str> {
        match self {
            Self::CjsonParse => None,
            Self::MicroCrashIfMagic => Some("achlys_micro_crash_if_magic"),
            Self::MicroNonzeroExit => Some("achlys_micro_nonzero_exit"),
            Self::MicroCoverageStable => Some("achlys_micro_coverage_stable"),
        }
    }
}

/// Compile the canonical dump binary from the manifest's canonical flags.
pub fn compile_canonical(
    workspace: &Path,
    manifest: &TargetManifest,
    out_dir: &Path,
    extra_identity_files: &[&str],
) -> Result<CompiledArtifact> {
    compile_kind(
        workspace,
        manifest,
        BuildKind::Canonical,
        out_dir,
        "canonical",
        extra_identity_files,
        true,
    )
}

/// Compile the sanitizer replay binary from the manifest's sanitizer flags.
pub fn compile_sanitizer(
    workspace: &Path,
    manifest: &TargetManifest,
    out_dir: &Path,
    extra_identity_files: &[&str],
) -> Result<CompiledArtifact> {
    compile_kind(
        workspace,
        manifest,
        BuildKind::Sanitizer,
        out_dir,
        "sanitizer",
        extra_identity_files,
        false,
    )
}

fn compile_kind(
    workspace: &Path,
    manifest: &TargetManifest,
    kind: BuildKind,
    out_dir: &Path,
    name: &str,
    extra_identity_files: &[&str],
    dump_coverage: bool,
) -> Result<CompiledArtifact> {
    let spec = manifest
        .spec(kind)
        .ok_or_else(|| anyhow::anyhow!("manifest has no {kind:?} build"))?;
    let target = WorkerTarget::parse(&manifest.target_id)?;

    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let mut cmd = Command::new("clang");
    if spec.flags.is_empty() {
        if dump_coverage {
            cmd.args(["-O1", "-g", "-fsanitize-coverage=trace-pc-guard"]);
        } else {
            cmd.args(["-O1", "-g", "-fsanitize=address,undefined"]);
        }
    } else {
        cmd.args(&spec.flags);
    }

    let mut includes = Vec::new();
    let mut sources: Vec<PathBuf> = Vec::new();
    for src in &manifest.sources {
        let path = resolve(workspace, &src.path);
        if !path.is_file() {
            bail!("missing source {}", path.display());
        }
        if path.extension().and_then(|e| e.to_str()) == Some("h") {
            if let Some(parent) = path.parent() {
                includes.push(parent.to_path_buf());
            }
            continue;
        }
        sources.push(path);
    }

    match target {
        WorkerTarget::CjsonParse => {
            let cjson = workspace.join("examples/targets/cJSON");
            includes.push(cjson.clone());
            let harness = cjson.join("harness_afl.c");
            if harness.is_file() && !sources.iter().any(|s| s.ends_with("harness_afl.c")) {
                sources.push(harness);
            }
            if dump_coverage {
                let sancov = cjson.join("sancov_callbacks.c");
                if sancov.is_file() && !sources.iter().any(|s| s.ends_with("sancov_callbacks.c")) {
                    sources.push(sancov);
                }
            }
            let driver = out_dir.join(format!("{name}_driver.c"));
            fs::write(
                &driver,
                if dump_coverage {
                    DUMP_CJSON
                } else {
                    STDIN_CJSON
                },
            )?;
            sources.push(driver);
        }
        _ => {
            if dump_coverage {
                let sancov = workspace.join("examples/targets/cJSON/sancov_callbacks.c");
                sources.push(sancov);
            }
            let driver = out_dir.join(format!("{name}_driver.c"));
            fs::write(
                &driver,
                if dump_coverage {
                    DUMP_MICRO
                } else {
                    STDIN_MICRO
                },
            )?;
            sources.push(driver);
            if let Some(fn_name) = target.micro_fn() {
                cmd.arg(format!("-DACHLYS_MICRO_FN={fn_name}"));
            }
        }
    }

    let path = out_dir.join(name);
    cmd.arg("-o").arg(&path);
    for inc in &includes {
        cmd.arg("-I").arg(inc);
    }
    for src in &sources {
        cmd.arg(src);
    }

    let output = cmd.output().context("failed to run clang")?;
    if !output.status.success() {
        bail!(
            "clang {name} build failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if !path.is_file() {
        bail!("clang produced no binary at {}", path.display());
    }

    if dump_coverage && spec.instrumentation == Some(Instrumentation::None) {
        bail!("canonical build must not declare instrumentation=none");
    }

    let identity =
        BuildIdentity::from_executed(manifest, kind, workspace, extra_identity_files, Some(&path))
            .map_err(|e| anyhow::anyhow!(e))?;

    if identity.artifact_hash.is_none() {
        bail!("compiled {name} binary was not hashed");
    }

    Ok(CompiledArtifact { path, identity })
}

fn resolve(workspace: &Path, rel: &Path) -> PathBuf {
    if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        workspace.join(rel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn unknown_target_is_rejected() {
        let err = WorkerTarget::parse("definitely-not-a-target").unwrap_err();
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn compile_canonical_cjson_hashes_artifact() {
        let root = workspace();
        let manifest =
            TargetManifest::from_path(root.join("benchmarks/manifests/cjson-parse.toml"))
                .expect("manifest");
        let dir = std::env::temp_dir().join(format!("achlys_canon_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let art = compile_canonical(&root, &manifest, &dir, &[]).expect("compile canonical");
        assert!(art.path.is_file());
        assert!(art.identity.artifact_hash.is_some());
        assert_eq!(art.identity.kind, BuildKind::Canonical);
        let _ = fs::remove_dir_all(&dir);
    }
}
