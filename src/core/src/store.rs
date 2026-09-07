//! Content-addressed campaign artifact store (post-campaign / control plane).
//!
//! Layout under `root()`:
//! ```text
//! manifest.toml
//! corpus/objects/ab/cd/<full-hex-hash>
//! corpus/metadata/<full-hex-hash>.json
//! crashes/objects/ab/cd/<full-hex-hash>
//! events/events.jsonl
//! metrics/summary.json
//! reports/canonical.json
//! ```
//!
//! `ab/cd` is [`InputId::object_prefix`]. Identity is SHA-256 of raw bytes
//! ([`InputId::from_bytes`]); metadata does not change it.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use achlys_protocol::{
    BuildId, CampaignEvent, CampaignId, CampaignRecord, CoverageDigest, InputId, InputMetadata,
    MetricsSnapshot, TargetManifest,
};
use anyhow::{Context, Result, anyhow, bail};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Canonical coverage summary written after replay, not during the hot loop.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CanonicalReport {
    pub digest: CoverageDigest,
    pub edge_count: u32,
    pub admitted: usize,
    pub rejected: usize,
    pub replayed: usize,
    pub canonical_build: BuildId,
    pub artifact_hash: Option<String>,
}

/// Filesystem object store for one campaign. Not invoked per execution.
#[derive(Debug, Clone)]
pub struct CampaignStore {
    root: PathBuf,
    campaign_id: CampaignId,
}

impl CampaignStore {
    /// Create the campaign directory tree and write `manifest.toml`.
    pub fn create(
        root: impl AsRef<Path>,
        campaign_id: CampaignId,
        manifest: &TargetManifest,
    ) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if is_occupied(&root) {
            bail!(
                "campaign root is not empty: {} (reuse is forbidden; pick a new --out)",
                root.display()
            );
        }
        fs::create_dir_all(&root)
            .with_context(|| format!("create campaign root {}", root.display()))?;
        for dir in [
            root.join("corpus").join("objects"),
            root.join("corpus").join("metadata"),
            root.join("crashes").join("objects"),
            root.join("events"),
            root.join("metrics"),
            root.join("reports"),
        ] {
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        }

        let toml = manifest_to_toml(manifest)?;
        write_atomic(&root.join("manifest.toml"), toml.as_bytes())?;

        Ok(Self { root, campaign_id })
    }

    /// Open an existing campaign directory (requires `manifest.toml`).
    pub fn open(root: impl AsRef<Path>, campaign_id: CampaignId) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let manifest = root.join("manifest.toml");
        if !manifest.is_file() {
            bail!("campaign store missing manifest.toml at {}", root.display());
        }
        Ok(Self { root, campaign_id })
    }

    /// Store `bytes` under [`InputId::from_bytes`]. Idempotent: the object file
    /// and first-producer metadata are written only when missing.
    /// [`CampaignEvent::InputStored`] is appended only on first insert.
    pub fn put_input(&self, bytes: &[u8], mut meta: InputMetadata) -> Result<InputId> {
        let id = InputId::from_bytes(bytes);
        meta.input_id = id;
        let object = self.input_object_path(&id);
        let first = !object.is_file();
        if first {
            write_atomic(&object, bytes)?;
        }

        let meta_path = self
            .root
            .join("corpus")
            .join("metadata")
            .join(format!("{}.json", id.to_hex()));
        let meta_json = serde_json::to_vec_pretty(&meta).context("serialize input metadata")?;
        write_once(&meta_path, &meta_json)?;

        if first {
            self.append_event(&CampaignEvent::InputStored {
                campaign_id: self.campaign_id,
                input_id: id,
                bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                unix_ms: now_unix_ms(),
            })?;
        }
        Ok(id)
    }

    pub fn get_input(&self, id: &InputId) -> Result<Vec<u8>> {
        let path = self.input_object_path(id);
        let bytes =
            fs::read(&path).with_context(|| format!("read input {id} from {}", path.display()))?;
        if InputId::from_bytes(&bytes) != *id {
            bail!("stored input hash mismatch: {id}");
        }
        Ok(bytes)
    }

    pub fn put_crash(&self, bytes: &[u8]) -> Result<InputId> {
        let id = InputId::from_bytes(bytes);
        let path = self.crash_object_path(&id);
        if !path.is_file() {
            write_atomic(&path, bytes)?;
        }
        Ok(id)
    }

    pub fn get_crash(&self, id: &InputId) -> Result<Vec<u8>> {
        let path = self.crash_object_path(id);
        fs::read(&path).with_context(|| format!("read crash {id} from {}", path.display()))
    }

    /// Append one JSON object as a single flushed line.
    pub fn append_event(&self, ev: &CampaignEvent) -> Result<()> {
        let path = self.root.join("events").join("events.jsonl");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let mut line = ev.to_jsonl().context("serialize campaign event")?;
        line.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        file.write_all(line.as_bytes())
            .with_context(|| format!("append {}", path.display()))?;
        file.sync_data()
            .with_context(|| format!("sync {}", path.display()))?;
        Ok(())
    }

    pub fn write_metrics(&self, snapshot: &MetricsSnapshot) -> Result<()> {
        let path = self.root.join("metrics").join("summary.json");
        let json = serde_json::to_vec_pretty(snapshot).context("serialize metrics")?;
        write_atomic(&path, &json)
    }

    pub fn write_canonical_report(&self, report: &CanonicalReport) -> Result<()> {
        let path = self.root.join("reports").join("canonical.json");
        let json = serde_json::to_vec_pretty(report).context("serialize canonical report")?;
        write_atomic(&path, &json)
    }

    /// Object hashes only — does not load input bytes.
    pub fn list_inputs(&self) -> Result<Vec<InputId>> {
        let objects = self.root.join("corpus").join("objects");
        let mut ids = Vec::new();
        if !objects.is_dir() {
            return Ok(ids);
        }
        for ab in read_dirs(&objects)? {
            for cd in read_dirs(&ab)? {
                let entries =
                    fs::read_dir(&cd).with_context(|| format!("list {}", cd.display()))?;
                for entry in entries {
                    let entry =
                        entry.with_context(|| format!("read entry under {}", cd.display()))?;
                    if !entry.path().is_file() {
                        continue;
                    }
                    let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                        continue;
                    };
                    if let Ok(id) = name.parse::<InputId>() {
                        ids.push(id);
                    }
                }
            }
        }
        ids.sort_unstable_by_key(|id| id.0);
        Ok(ids)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn campaign_id(&self) -> CampaignId {
        self.campaign_id
    }

    /// Recover only an interrupted final append. Committed malformed lines
    /// remain errors. Called only while the campaign has a single writer.
    pub fn read_events(&self) -> Result<Vec<CampaignEvent>> {
        let path = self.root.join("events").join("events.jsonl");
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let mut bytes =
            fs::read(&path).with_context(|| format!("read events {}", path.display()))?;
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            let committed = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
            // Keep the interrupted tail for diagnosis before truncating it.
            write_atomic(&path.with_extension("interrupted"), &bytes[committed..])?;
            let file = OpenOptions::new().write(true).open(&path)?;
            file.set_len(committed as u64)?;
            file.sync_data()?;
            bytes.truncate(committed);
        }
        let text = std::str::from_utf8(&bytes).context("committed event log is not UTF-8")?;
        let mut out = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let ev = CampaignEvent::from_jsonl(line).with_context(|| {
                format!("parse events.jsonl line {} at {}", idx + 1, path.display())
            })?;
            out.push(ev);
        }
        Ok(out)
    }

    pub fn write_campaign_record(&self, record: &CampaignRecord) -> Result<()> {
        if record.campaign_id != self.campaign_id {
            bail!(
                "campaign record id {} does not match store {}",
                record.campaign_id,
                self.campaign_id
            );
        }
        let path = self.root.join("campaign.json");
        let json = serde_json::to_vec_pretty(record).context("serialize campaign.json")?;
        write_atomic(&path, &json)
    }

    fn input_object_path(&self, id: &InputId) -> PathBuf {
        object_path(&self.root.join("corpus").join("objects"), id)
    }

    fn crash_object_path(&self, id: &InputId) -> PathBuf {
        object_path(&self.root.join("crashes").join("objects"), id)
    }
}

pub(crate) fn is_occupied(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    if !path.is_dir() {
        return true;
    }
    match fs::read_dir(path) {
        Ok(entries) => entries.flatten().any(|e| e.file_name() != ".DS_Store"),
        Err(_) => true,
    }
}

pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn object_path(objects_root: &Path, id: &InputId) -> PathBuf {
    let (ab, cd) = id.object_prefix();
    objects_root.join(ab).join(cd).join(id.to_hex())
}

pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let tmp = parent.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    file.write_all(data)
        .with_context(|| format!("write {}", tmp.display()))?;
    file.sync_data()?;
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("rename {} -> {}", tmp.display(), path.display()));
    }
    Ok(())
}

/// Publish an immutable object without replacing the first producer's record.
pub(crate) fn write_once(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().context("object has no parent")?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".publish-{}-{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    file.write_all(data)?;
    file.sync_data()?;
    let result = fs::hard_link(&tmp, path);
    fs::remove_file(&tmp)?;
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).context("publish immutable object"),
    }
}

fn read_dirs(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let entries = fs::read_dir(dir).with_context(|| format!("list {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry under {}", dir.display()))?;
        if entry.path().is_dir() {
            out.push(entry.path());
        }
    }
    Ok(out)
}

/// `toml` cannot encode serde `None` (JSON null). Drop those keys.
fn manifest_to_toml(manifest: &TargetManifest) -> Result<String> {
    let json = serde_json::to_value(manifest).context("serialize manifest")?;
    let value = json_to_toml(json)?;
    toml::to_string_pretty(&value).context("encode manifest.toml")
}

fn json_to_toml(value: serde_json::Value) -> Result<toml::Value> {
    match value {
        serde_json::Value::Null => bail!("toml cannot represent null"),
        serde_json::Value::Bool(b) => Ok(toml::Value::Boolean(b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(toml::Value::Integer(i))
            } else if let Some(u) = n.as_u64() {
                Ok(toml::Value::Integer(
                    i64::try_from(u).context("integer exceeds toml i64")?,
                ))
            } else if let Some(f) = n.as_f64() {
                Ok(toml::Value::Float(f))
            } else {
                bail!("unsupported json number {n}");
            }
        }
        serde_json::Value::String(s) => Ok(toml::Value::String(s)),
        serde_json::Value::Array(items) => {
            let converted = items
                .into_iter()
                .filter(|v| !v.is_null())
                .map(json_to_toml)
                .collect::<Result<Vec<_>>>()?;
            Ok(toml::Value::Array(converted))
        }
        serde_json::Value::Object(map) => {
            let mut table = toml::map::Map::new();
            for (key, val) in map {
                if val.is_null() {
                    continue;
                }
                table.insert(key, json_to_toml(val)?);
            }
            Ok(toml::Value::Table(table))
        }
    }
}

#[cfg(test)]
pub(crate) fn unique_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "achlys_{label}_{}_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create unique temp dir");
    dir
}

#[cfg(test)]
pub(crate) fn sample_target_manifest() -> TargetManifest {
    use achlys_protocol::{BuildSpec, Builds, InputMode, Instrumentation};

    TargetManifest {
        schema_version: 1,
        target_id: "micro-store".into(),
        harness: "entry".into(),
        input_mode: InputMode::Inprocess,
        max_input_len: 64,
        timeout_ms: 1000,
        sources: vec![],
        builds: Builds {
            fast: BuildSpec {
                artifact: None,
                instrumentation: Some(Instrumentation::SancovEdge),
                sanitizers: vec![],
                flags: vec!["-O3".into()],
            },
            canonical: BuildSpec {
                artifact: None,
                instrumentation: Some(Instrumentation::SancovEdge),
                sanitizers: vec![],
                flags: vec!["-O1".into()],
            },
            sanitizer: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use achlys_protocol::{BuildId, InputMetadata};

    struct TempDir(PathBuf);

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

    fn test_meta(campaign: CampaignId) -> InputMetadata {
        InputMetadata {
            input_id: InputId([0; 32]),
            parent_ids: vec![],
            producer: "test".into(),
            producer_build: BuildId([0; 32]),
            campaign_id: campaign,
            local_coverage: None,
            canonical_delta: None,
            stored_unix_ms: 1,
            worker_id: None,
            producer_seq: None,
            strategy: None,
        }
    }

    fn count_corpus_objects(root: &Path) -> usize {
        let objects = root.join("corpus").join("objects");
        let mut n = 0;
        let Ok(abs) = fs::read_dir(&objects) else {
            return 0;
        };
        for ab in abs.flatten() {
            let Ok(cds) = fs::read_dir(ab.path()) else {
                continue;
            };
            for cd in cds.flatten() {
                let Ok(files) = fs::read_dir(cd.path()) else {
                    continue;
                };
                n += files.flatten().filter(|e| e.path().is_file()).count();
            }
        }
        n
    }

    fn open_store(label: &str) -> (TempDir, CampaignStore) {
        let tmp = TempDir::new(label);
        let campaign = CampaignId::from_label(label);
        let store = CampaignStore::create(&tmp.0, campaign, &sample_target_manifest()).unwrap();
        (tmp, store)
    }

    #[test]
    fn put_same_bytes_twice_one_object() {
        let (_tmp, store) = open_store("put_dup");
        let meta = test_meta(store.campaign_id());
        let id1 = store.put_input(b"seed", meta.clone()).unwrap();
        let id2 = store.put_input(b"seed", meta).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1, InputId::from_bytes(b"seed"));
        assert_eq!(count_corpus_objects(store.root()), 1);
    }

    #[test]
    fn duplicate_preserves_origin_and_corrupt_object_fails() {
        let (_tmp, store) = open_store("immutable_origin");
        let first = test_meta(store.campaign_id());
        let id = store.put_input(b"seed", first.clone()).unwrap();
        let mut second = first;
        second.producer = "different".into();
        store.put_input(b"seed", second).unwrap();
        let meta: InputMetadata = serde_json::from_slice(
            &fs::read(
                store
                    .root()
                    .join("corpus/metadata")
                    .join(format!("{}.json", id.to_hex())),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(meta.producer, "test");
        fs::write(store.input_object_path(&id), b"corrupt").unwrap();
        assert!(
            store
                .get_input(&id)
                .unwrap_err()
                .to_string()
                .contains("hash mismatch")
        );
    }

    #[test]
    fn get_input_returns_exact_bytes() {
        let (_tmp, store) = open_store("get_bytes");
        let raw = b"\x00hello\xffworld";
        let id = store
            .put_input(raw, test_meta(store.campaign_id()))
            .unwrap();
        assert_eq!(store.get_input(&id).unwrap(), raw);
    }

    #[test]
    fn events_jsonl_parseable() {
        let (_tmp, store) = open_store("events");
        store
            .put_input(b"a", test_meta(store.campaign_id()))
            .unwrap();
        store
            .put_input(b"a", test_meta(store.campaign_id()))
            .unwrap();
        store
            .put_input(b"b", test_meta(store.campaign_id()))
            .unwrap();

        let path = store.root().join("events").join("events.jsonl");
        let text = fs::read_to_string(&path).unwrap();
        let mut stored = 0usize;
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let ev = CampaignEvent::from_jsonl(line).expect("parseable CampaignEvent");
            if matches!(ev, CampaignEvent::InputStored { .. }) {
                stored += 1;
            }
        }
        assert_eq!(stored, 2, "InputStored only on first insert");
    }

    #[test]
    fn interrupted_tail_is_recovered_without_hiding_committed_corruption() {
        let (_tmp, store) = open_store("journal_tail");
        store
            .put_input(b"seed", test_meta(store.campaign_id()))
            .unwrap();
        let path = store.root().join("events/events.jsonl");
        let original = fs::read(&path).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"type\":\"can\xff").unwrap();
        assert_eq!(store.read_events().unwrap().len(), 1);
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(path.with_extension("interrupted").is_file());
        file.write_all(b"not-json\n").unwrap();
        assert!(store.read_events().is_err());
    }

    #[test]
    fn create_rejects_occupied_root() {
        let tmp = TempDir::new("occupied");
        let campaign = CampaignId::from_label("occupied");
        CampaignStore::create(&tmp.0, campaign, &sample_target_manifest()).unwrap();
        let err = CampaignStore::create(&tmp.0, campaign, &sample_target_manifest())
            .expect_err("second create must fail");
        assert!(
            err.to_string().contains("not empty"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn create_writes_manifest_toml() {
        let tmp = TempDir::new("manifest");
        let campaign = CampaignId::from_label("manifest");
        let store = CampaignStore::create(&tmp.0, campaign, &sample_target_manifest()).unwrap();
        let path = store.root().join("manifest.toml");
        assert!(path.is_file(), "create() must write manifest.toml");
        let loaded = TargetManifest::from_path(&path).unwrap();
        assert_eq!(loaded.target_id, "micro-store");
        assert_eq!(loaded.schema_version, 1);
    }

    #[test]
    fn list_inputs_returns_stored_ids() {
        let (_tmp, store) = open_store("list");
        let a = store
            .put_input(b"one", test_meta(store.campaign_id()))
            .unwrap();
        let b = store
            .put_input(b"two", test_meta(store.campaign_id()))
            .unwrap();
        let _ = store
            .put_input(b"one", test_meta(store.campaign_id()))
            .unwrap();
        let mut got = store.list_inputs().unwrap();
        let mut want = vec![a, b];
        got.sort_unstable_by_key(|id| id.0);
        want.sort_unstable_by_key(|id| id.0);
        assert_eq!(got, want);
    }
}
