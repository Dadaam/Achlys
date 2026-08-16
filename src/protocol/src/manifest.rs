use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ids::TargetId;

/// Current manifest schema. Bump only with an explicit migration.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// How the worker delivers bytes to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InputMode {
    Inprocess,
    Stdin,
    #[serde(rename = "file")]
    FileReplace,
}

/// Which build variant a spec describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildKind {
    Fast,
    Canonical,
    Sanitizer,
}

impl BuildKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Canonical => "canonical",
            Self::Sanitizer => "sanitizer",
        }
    }
}

/// Coverage instrumentation recorded on a build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Instrumentation {
    SancovEdge,
    None,
}

/// One source file that participates in a target identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpec {
    pub path: PathBuf,
}

/// Compiler / artifact description for one variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSpec {
    #[serde(default)]
    pub artifact: Option<PathBuf>,
    #[serde(default)]
    pub instrumentation: Option<Instrumentation>,
    #[serde(default)]
    pub sanitizers: Vec<String>,
    #[serde(default)]
    pub flags: Vec<String>,
}

/// Required and optional variants for one logical target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Builds {
    pub fast: BuildSpec,
    pub canonical: BuildSpec,
    #[serde(default)]
    pub sanitizer: Option<BuildSpec>,
}

/// Versioned campaign input. Campaigns consume this, not ad-hoc CLI flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetManifest {
    pub schema_version: u32,
    pub target_id: String,
    pub harness: String,
    pub input_mode: InputMode,
    pub max_input_len: usize,
    pub timeout_ms: u64,
    #[serde(default)]
    pub sources: Vec<SourceSpec>,
    pub builds: Builds,
}

/// Manifest load or validation failure.
#[derive(Debug)]
pub enum ManifestError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        message: String,
    },
    Invalid {
        message: String,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read {}: {source}", path.display())
            }
            Self::Parse { path, message } => {
                write!(f, "failed to parse {}: {message}", path.display())
            }
            Self::Invalid { message } => write!(f, "invalid target manifest: {message}"),
        }
    }
}

impl std::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { .. } | Self::Invalid { .. } => None,
        }
    }
}

impl TargetManifest {
    /// Parse and validate a TOML manifest from disk.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ManifestError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| ManifestError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let parsed: Self = toml::from_str(&text).map_err(|err| ManifestError::Parse {
            path: path.to_path_buf(),
            message: err.to_string(),
        })?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ManifestError::Invalid {
                message: format!(
                    "unsupported schema_version {} (expected {MANIFEST_SCHEMA_VERSION})",
                    self.schema_version
                ),
            });
        }
        if self.target_id.trim().is_empty() {
            return Err(ManifestError::Invalid {
                message: "target_id must be non-empty".into(),
            });
        }
        if self.harness.trim().is_empty() {
            return Err(ManifestError::Invalid {
                message: "harness must be non-empty".into(),
            });
        }
        if self.max_input_len == 0 {
            return Err(ManifestError::Invalid {
                message: "max_input_len must be > 0".into(),
            });
        }
        if self.timeout_ms == 0 {
            return Err(ManifestError::Invalid {
                message: "timeout_ms must be > 0".into(),
            });
        }
        if let Some(san) = &self.builds.sanitizer
            && san.sanitizers.is_empty()
        {
            return Err(ManifestError::Invalid {
                message: "build.sanitizer must list at least one sanitizer".into(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn target_id(&self) -> TargetId {
        TargetId(self.target_id.clone())
    }

    #[must_use]
    pub fn spec(&self, kind: BuildKind) -> Option<&BuildSpec> {
        match kind {
            BuildKind::Fast => Some(&self.builds.fast),
            BuildKind::Canonical => Some(&self.builds.canonical),
            BuildKind::Sanitizer => self.builds.sanitizer.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
schema_version = 1
target_id = "cjson-parse"
harness = "cJSON_Parse"
input_mode = "inprocess"
max_input_len = 64
timeout_ms = 1000

[[sources]]
path = "examples/targets/cJSON/cJSON.c"

[builds.fast]
instrumentation = "sancov-edge"
flags = ["-O3", "-fsanitize-coverage=trace-pc-guard"]

[builds.canonical]
instrumentation = "sancov-edge"
flags = ["-O1", "-g", "-fsanitize-coverage=trace-pc-guard"]

[builds.sanitizer]
instrumentation = "none"
sanitizers = ["address", "undefined"]
flags = ["-O1", "-g", "-fsanitize=address,undefined"]
"#;

    #[test]
    fn parse_sample_manifest() {
        let m: TargetManifest = toml::from_str(SAMPLE).unwrap();
        m.validate().unwrap();
        assert_eq!(m.target_id.as_str(), "cjson-parse");
        assert!(matches!(m.input_mode, InputMode::Inprocess));
        assert_eq!(m.builds.sanitizer.as_ref().unwrap().sanitizers.len(), 2);
        assert!(m.spec(BuildKind::Fast).is_some());
    }

    #[test]
    fn reject_wrong_schema() {
        let mut m: TargetManifest = toml::from_str(SAMPLE).unwrap();
        m.schema_version = 99;
        assert!(m.validate().is_err());
    }

    #[test]
    fn reject_zero_timeout() {
        let mut m: TargetManifest = toml::from_str(SAMPLE).unwrap();
        m.timeout_ms = 0;
        assert!(m.validate().is_err());
    }

    #[test]
    fn reject_empty_sanitizer_list() {
        let mut m: TargetManifest = toml::from_str(SAMPLE).unwrap();
        m.builds.sanitizer.as_mut().unwrap().sanitizers.clear();
        assert!(m.validate().is_err());
    }

    #[test]
    fn repo_manifests_load() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/manifests");
        for name in ["cjson-parse.toml", "micro-crash-if-magic.toml"] {
            let m = TargetManifest::from_path(root.join(name)).unwrap();
            assert_eq!(m.schema_version, MANIFEST_SCHEMA_VERSION);
            assert!(m.max_input_len > 0);
        }
    }

    #[test]
    fn from_path_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "achlys_manifest_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("target.toml");
        fs::write(&path, SAMPLE).unwrap();
        let loaded = TargetManifest::from_path(&path).unwrap();
        assert_eq!(loaded.target_id, "cjson-parse");
        let _ = fs::remove_dir_all(&dir);
    }
}
