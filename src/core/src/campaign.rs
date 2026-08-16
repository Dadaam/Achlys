//! Post-campaign ingest and finish. Never call from the execution hot path.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use achlys_protocol::{
    BuildId, BuildIdentity, CampaignEvent, CampaignId, InputId, InputMetadata, MetricsSnapshot,
    TargetManifest,
};
use anyhow::{Context, Result};

use crate::store::{CampaignStore, now_unix_ms};

/// Control-plane session wrapping a [`CampaignStore`].
#[derive(Debug)]
pub struct CampaignSession {
    store: CampaignStore,
}

impl CampaignSession {
    /// Copy manifest into the campaign dir, write CampaignStarted.
    pub fn begin(
        out_dir: impl AsRef<Path>,
        campaign_label: &str,
        manifest: &TargetManifest,
        build: &BuildIdentity,
    ) -> Result<Self> {
        let campaign_id = CampaignId::from_label(campaign_label);
        let store = CampaignStore::create(out_dir, campaign_id, manifest)?;
        store.append_event(&CampaignEvent::CampaignStarted {
            schema_version: CampaignEvent::SCHEMA_VERSION,
            campaign_id,
            target_id: manifest.target_id.clone(),
            build: build.clone(),
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
            if !path.is_file() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{sample_target_manifest, unique_temp_dir};
    use achlys_protocol::{BuildIdentity, BuildIdentityParts, BuildKind, TargetId};
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
        let session =
            CampaignSession::begin(&out.0, "ingest", &sample_target_manifest(), &sample_build())
                .unwrap();

        let worker = TempDir::new("worker");
        fs::write(worker.0.join("a"), b"alpha").unwrap();
        fs::write(worker.0.join("b"), b"beta").unwrap();
        fs::write(worker.0.join("c"), b"alpha").unwrap();
        fs::write(worker.0.join("empty"), b"").unwrap();
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
