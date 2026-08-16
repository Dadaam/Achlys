use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ids::{BuildId, TargetId};
use crate::manifest::{BuildKind, TargetManifest};

/// Inputs that uniquely identify a compiled target variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildIdentityParts {
    pub target_id: TargetId,
    pub kind: BuildKind,
    pub compiler: String,
    pub flags: Vec<String>,
    pub source_hashes: BTreeMap<String, [u8; 32]>,
    pub artifact_hash: Option<[u8; 32]>,
}

/// Recorded identity of one build variant. `build_id` is the hash of the parts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildIdentity {
    pub target_id: TargetId,
    pub kind: BuildKind,
    pub compiler: String,
    pub flags: Vec<String>,
    pub source_hashes: BTreeMap<String, String>,
    pub artifact_hash: Option<String>,
    pub build_id: BuildId,
}

impl BuildIdentity {
    #[must_use]
    pub fn compute(parts: BuildIdentityParts) -> Self {
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        chunks.push(parts.target_id.0.as_bytes().to_vec());
        chunks.push(parts.kind.as_str().as_bytes().to_vec());
        chunks.push(parts.compiler.as_bytes().to_vec());
        for flag in &parts.flags {
            chunks.push(flag.as_bytes().to_vec());
        }
        for (path, hash) in &parts.source_hashes {
            chunks.push(path.as_bytes().to_vec());
            chunks.push(hash.to_vec());
        }
        if let Some(art) = parts.artifact_hash {
            chunks.push(art.to_vec());
        }
        let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
        let build_id = BuildId::from_parts(&refs);

        Self {
            target_id: parts.target_id,
            kind: parts.kind,
            compiler: parts.compiler,
            flags: parts.flags,
            source_hashes: parts
                .source_hashes
                .into_iter()
                .map(|(k, v)| (k, hex::encode(v)))
                .collect(),
            artifact_hash: parts.artifact_hash.map(hex::encode),
            build_id,
        }
    }

    /// Build identity for `kind` using on-disk source hashes and `clang -v`.
    pub fn from_manifest(
        manifest: &TargetManifest,
        kind: BuildKind,
        workspace_root: &Path,
    ) -> Result<Self, String> {
        let spec = manifest
            .spec(kind)
            .ok_or_else(|| format!("manifest has no {kind:?} build"))?;

        let mut source_hashes = BTreeMap::new();
        for source in &manifest.sources {
            let path = if source.path.is_absolute() {
                source.path.clone()
            } else {
                workspace_root.join(&source.path)
            };
            let bytes = fs::read(&path)
                .map_err(|err| format!("failed to hash source {}: {err}", path.display()))?;
            let hash: [u8; 32] = Sha256::digest(&bytes).into();
            source_hashes.insert(source.path.display().to_string(), hash);
        }

        let artifact_hash = match &spec.artifact {
            Some(art) => {
                let path = if art.is_absolute() {
                    art.clone()
                } else {
                    workspace_root.join(art)
                };
                if path.is_file() {
                    let bytes = fs::read(&path).map_err(|err| {
                        format!("failed to hash artifact {}: {err}", path.display())
                    })?;
                    Some(Sha256::digest(&bytes).into())
                } else {
                    None
                }
            }
            None => None,
        };

        let compiler = detect_clang_version().unwrap_or_else(|| "clang".to_string());

        Ok(Self::compute(BuildIdentityParts {
            target_id: manifest.target_id(),
            kind,
            compiler,
            flags: spec.flags.clone(),
            source_hashes,
            artifact_hash,
        }))
    }
}

fn detect_clang_version() -> Option<String> {
    let output = Command::new("clang").arg("-v").output().ok()?;
    let text = if output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).into_owned()
    } else {
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    text.lines().next().map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_id_is_stable_and_sensitive() {
        let mut sources = BTreeMap::new();
        sources.insert("a.c".into(), [1u8; 32]);
        let a = BuildIdentity::compute(BuildIdentityParts {
            target_id: TargetId("t".into()),
            kind: BuildKind::Fast,
            compiler: "clang 1".into(),
            flags: vec!["-O3".into()],
            source_hashes: sources.clone(),
            artifact_hash: None,
        });
        let b = BuildIdentity::compute(BuildIdentityParts {
            target_id: TargetId("t".into()),
            kind: BuildKind::Fast,
            compiler: "clang 1".into(),
            flags: vec!["-O3".into()],
            source_hashes: sources.clone(),
            artifact_hash: None,
        });
        assert_eq!(a.build_id, b.build_id);

        let c = BuildIdentity::compute(BuildIdentityParts {
            target_id: TargetId("t".into()),
            kind: BuildKind::Canonical,
            compiler: "clang 1".into(),
            flags: vec!["-O1".into()],
            source_hashes: sources,
            artifact_hash: None,
        });
        assert_ne!(a.build_id, c.build_id);
    }
}
