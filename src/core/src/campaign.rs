//! Post-campaign ingest and finish. Never call from the execution hot path.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use achlys_protocol::{
    BuildId, CampaignEvent, CampaignRecord, InputId, InputMetadata, MetricsSnapshot, TargetManifest,
};
use anyhow::{Context, Result};

use crate::store::{CampaignStore, now_unix_ms};

/// Control-plane session wrapping a [`CampaignStore`].
#[derive(Debug)]
pub struct CampaignSession {
    store: CampaignStore,
}

impl CampaignSession {
    /// Create a fresh campaign root, persist `campaign.json`, write CampaignStarted.
    pub fn begin(
        out_dir: impl AsRef<Path>,
        manifest: &TargetManifest,
        record: &CampaignRecord,
    ) -> Result<Self> {
        let store = CampaignStore::create(out_dir, record.campaign_id, manifest)?;
        store.write_campaign_record(record)?;
        store.append_event(&CampaignEvent::CampaignStarted {
            schema_version: CampaignEvent::SCHEMA_VERSION,
            campaign_id: record.campaign_id,
            target_id: manifest.target_id.clone(),
            fast_build: record.fast_build.clone(),
            canonical_build: record.canonical_build.clone(),
            sanitizer_build: record.sanitizer_build.clone(),
            unix_ms: now_unix_ms(),
        })?;
        Ok(Self { store })
    }

    /// Ingest every regular file in a worker corpus dir (e.g. InMemoryOnDiskCorpus folder).
    /// Skip empty / non-files. Content-addressed; duplicates are one object.
    pub fn ingest_worker_dir(
        &self,
        dir: &Path,
        producer: &str,
        producer_build: BuildId,
    ) -> Result<usize> {
        let campaign_id = self.store.campaign_id();
        let mut unique = HashSet::new();
        let entries =
            fs::read_dir(dir).with_context(|| format!("read worker dir {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
            let path = entry.path();
            if !path.is_file() || is_libafl_sidecar(&path) {
                continue;
            }
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            if bytes.is_empty() {
                continue;
            }
            let meta = InputMetadata {
                input_id: InputId::from_bytes(&bytes),
                parent_ids: Vec::new(),
                producer: producer.to_string(),
                producer_build,
                campaign_id,
                local_coverage: None,
                canonical_delta: None,
                stored_unix_ms: now_unix_ms(),
            };
            let id = self.store.put_input(&bytes, meta)?;
            unique.insert(id);
        }
        Ok(unique.len())
    }

    pub fn finish(&self, snapshot: MetricsSnapshot) -> Result<()> {
        self.store.write_metrics(&snapshot)?;
        self.store.append_event(&CampaignEvent::CampaignFinished {
            campaign_id: self.store.campaign_id(),
            snapshot,
            unix_ms: now_unix_ms(),
        })?;
        Ok(())
    }

    #[must_use]
    pub fn store(&self) -> &CampaignStore {
        &self.store
    }
}

/// LibAFL `InMemoryOnDiskCorpus` writes `.*.metadata` next to inputs.
fn is_libafl_sidecar(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.starts_with('.') || name.ends_with(".metadata")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{sample_target_manifest, unique_temp_dir};
    use achlys_protocol::{
        BuildIdentity, BuildIdentityParts, BuildKind, CampaignId, CampaignRecord, TargetId,
    };
    use std::collections::BTreeMap;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            Self(unique_temp_dir(label))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample_build() -> BuildIdentity {
        BuildIdentity::compute(BuildIdentityParts {
            target_id: TargetId("micro-store".into()),
            kind: BuildKind::Fast,
            compiler: "clang".into(),
            flags: vec!["-O3".into()],
            source_hashes: BTreeMap::new(),
            artifact_hash: None,
        })
    }

    #[test]
    fn ingest_worker_dir_dedups_identical_files() {
        let out = TempDir::new("session");
        let build = sample_build();
        let record = CampaignRecord {
            schema_version: CampaignEvent::SCHEMA_VERSION,
            campaign_id: CampaignId::from_label("ingest"),
            target_id: "micro-store".into(),
            label: "ingest".into(),
            seed: 1,
            max_iters: Some(1),
            max_seconds: None,
            max_input_len: 64,
            timeout_ms: 1000,
            tool: "test".into(),
            host: "test".into(),
            rustc: "test".into(),
            git: "test".into(),
            git_dirty_tracked: 0,
            git_untracked: 0,
            fast_build: build,
            canonical_build: None,
            sanitizer_build: None,
            started_unix_ms: 0,
        };
        let session = CampaignSession::begin(&out.0, &sample_target_manifest(), &record).unwrap();

        let worker = TempDir::new("worker");
        fs::write(worker.0.join("a"), b"alpha").unwrap();
        fs::write(worker.0.join("b"), b"beta").unwrap();
        fs::write(worker.0.join("c"), b"alpha").unwrap();
        fs::write(worker.0.join("empty"), b"").unwrap();
        fs::write(worker.0.join(".deadbeef_1.metadata"), b"not-an-input").unwrap();
        fs::create_dir(worker.0.join("nested")).unwrap();

        let stored = session
            .ingest_worker_dir(&worker.0, "havoc", BuildId([1; 32]))
            .unwrap();
        assert_eq!(stored, 2);
        assert_eq!(session.store().list_inputs().unwrap().len(), 2);

        let snapshot = MetricsSnapshot {
            executions: 10,
            corpus_count: 2,
            objectives: 1,
            canonical_edges: 0,
            elapsed_ms: 1,
            crash: Default::default(),
        };
        session.finish(snapshot).unwrap();
        assert!(
            session
                .store()
                .root()
                .join("metrics")
                .join("summary.json")
                .is_file()
        );
    }
}
