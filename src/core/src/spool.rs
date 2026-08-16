//! Filesystem candidate spool. Workers write; the admit process reads.
//!
//! Not on the execution hot path. All names are content-addressed so a
//! duplicate push is a no-op.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use achlys_protocol::{InputId, InputMetadata, WorkerId};
use anyhow::{Context, Result, anyhow, bail};

use crate::store::write_atomic;

/// Default bound on how many inbox records `take_inbox` returns per call.
pub const DEFAULT_TAKE: usize = 64;

/// On-disk worker registration written by a worker at start.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkerRegistration {
    pub worker_id: WorkerId,
    pub slot: u32,
    pub sender_seq: u64,
    pub restart: bool,
    pub previous_seq: Option<u64>,
}

/// Offline continuation plan written by the launcher before spawn.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkerResume {
    pub worker_id: WorkerId,
    pub slot: u32,
    pub restart: bool,
    pub previous_seq: Option<u64>,
    pub next_seq: u64,
}

/// Worker exit notice. Admit turns this into `WorkerLeft`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkerExit {
    pub worker_id: WorkerId,
    pub slot: u32,
    pub sender_seq: u64,
    pub reason: String,
}

/// Filesystem spool under `<out>/spool`.
#[derive(Debug, Clone)]
pub struct CandidateSpool {
    root: PathBuf,
}

impl CandidateSpool {
    pub fn create(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        for dir in [
            root.join("inbox"),
            root.join("processing"),
            root.join("overflow"),
            root.join("deltas"),
            root.join("workers"),
            root.join("snapshot"),
            root.join("resume"),
            root.join("left"),
        ] {
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        }
        Ok(Self { root })
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_dir() {
            bail!("spool root missing: {}", root.display());
        }
        Self::create(root)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Persist bytes + metadata under `inbox/<hex>`. Idempotent.
    pub fn push(&self, bytes: &[u8], meta: &InputMetadata) -> Result<InputId> {
        if bytes.is_empty() {
            bail!("refusing to spool empty input");
        }
        let id = InputId::from_bytes(bytes);
        let mut meta = meta.clone();
        meta.input_id = id;
        let json = serde_json::to_vec_pretty(&meta).context("serialize spool metadata")?;
        // Metadata first so a visible object file is never unpaired.
        write_atomic(
            &self.inbox_dir().join(format!("{}.json", id.to_hex())),
            &json,
        )?;
        let bin = self.inbox_dir().join(id.to_hex());
        if !bin.is_file() {
            write_atomic(&bin, bytes)?;
        }
        Ok(id)
    }

    /// Move up to `max` inbox objects into `processing/` and return them.
    /// Crash between take and submit leaves files in `processing/` for reconstruct.
    pub fn take_inbox(&self, max: usize) -> Result<Vec<(InputId, Vec<u8>, InputMetadata)>> {
        take_from_dir(&self.inbox_dir(), &self.processing_dir(), max)
    }

    /// Reclaim leftover `processing/` records after an admit crash.
    pub fn take_processing(&self, max: usize) -> Result<Vec<(InputId, Vec<u8>, InputMetadata)>> {
        take_from_dir(&self.processing_dir(), &self.processing_dir(), max)
    }

    pub fn ack_processed(&self, id: &InputId) -> Result<()> {
        let hex = id.to_hex();
        let _ = fs::remove_file(self.processing_dir().join(&hex));
        let _ = fs::remove_file(self.processing_dir().join(format!("{hex}.json")));
        Ok(())
    }

    #[must_use]
    pub fn inbox_len(&self) -> usize {
        count_pairs(&self.inbox_dir())
    }

    #[must_use]
    pub fn processing_len(&self) -> usize {
        count_pairs(&self.processing_dir())
    }

    #[must_use]
    pub fn overflow_len(&self) -> usize {
        count_pairs(&self.overflow_dir())
    }

    pub fn write_overflow(&self, bytes: &[u8], meta: &InputMetadata) -> Result<InputId> {
        let id = InputId::from_bytes(bytes);
        let bin = self.overflow_dir().join(id.to_hex());
        if !bin.is_file() {
            write_atomic(&bin, bytes)?;
        }
        let mut meta = meta.clone();
        meta.input_id = id;
        let json = serde_json::to_vec_pretty(&meta).context("serialize overflow metadata")?;
        write_atomic(
            &self.overflow_dir().join(format!("{}.json", id.to_hex())),
            &json,
        )?;
        Ok(id)
    }

    pub fn take_overflow(&self, max: usize) -> Result<Vec<(InputId, Vec<u8>, InputMetadata)>> {
        take_from_dir(&self.overflow_dir(), &self.processing_dir(), max)
    }

    /// True if inbox, processing, or overflow still holds an object from `worker`.
    pub fn has_pending_for(&self, worker: WorkerId) -> Result<bool> {
        for dir in [self.inbox_dir(), self.processing_dir(), self.overflow_dir()] {
            if dir_has_worker(&dir, worker)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn write_delta(&self, sequence: u64, admitted: &[InputId]) -> Result<PathBuf> {
        let path = self.deltas_dir().join(format!("{sequence:016}.json"));
        let body = serde_json::json!({
            "sequence": sequence,
            "admitted": admitted,
        });
        let json = serde_json::to_vec_pretty(&body).context("serialize corpus delta")?;
        write_atomic(&path, &json)?;
        Ok(path)
    }

    /// Deltas with `sequence > after_seq`, sorted.
    pub fn unread_deltas(&self, after_seq: u64) -> Result<Vec<(u64, Vec<InputId>)>> {
        let mut out = Vec::new();
        let dir = self.deltas_dir();
        if !dir.is_dir() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir).with_context(|| format!("list {}", dir.display()))? {
            let entry = entry.with_context(|| format!("read {}", dir.display()))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(&path)
                .with_context(|| format!("read delta {}", path.display()))?;
            let value: serde_json::Value =
                serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
            let seq = value
                .get("sequence")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| anyhow!("delta missing sequence: {}", path.display()))?;
            if seq <= after_seq {
                continue;
            }
            let admitted = value
                .get("admitted")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| anyhow!("delta missing admitted: {}", path.display()))?;
            let mut ids = Vec::new();
            for item in admitted {
                let s = item
                    .as_str()
                    .ok_or_else(|| anyhow!("admitted entry not a string"))?;
                ids.push(
                    s.parse::<InputId>()
                        .with_context(|| format!("input id {s}"))?,
                );
            }
            out.push((seq, ids));
        }
        out.sort_unstable_by_key(|(seq, _)| *seq);
        Ok(out)
    }

    pub fn write_stop(&self) -> Result<()> {
        write_atomic(&self.root.join("STOP"), b"1\n")
    }

    #[must_use]
    pub fn stop_requested(&self) -> bool {
        self.root.join("STOP").is_file()
    }

    pub fn write_worker(&self, reg: &WorkerRegistration) -> Result<PathBuf> {
        let path = self
            .workers_dir()
            .join(format!("{}.json", reg.worker_id.to_hex()));
        let json = serde_json::to_vec_pretty(reg).context("serialize worker registration")?;
        write_atomic(&path, &json)?;
        Ok(path)
    }

    pub fn take_worker_registrations(&self) -> Result<Vec<WorkerRegistration>> {
        let dir = self.workers_dir();
        let mut out = Vec::new();
        if !dir.is_dir() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir).with_context(|| format!("list {}", dir.display()))? {
            let entry = entry.with_context(|| format!("read {}", dir.display()))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.ends_with(".taken"))
            {
                continue;
            }
            let text =
                fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            let reg: WorkerRegistration =
                serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
            let taken = path.with_extension("taken.json");
            fs::rename(&path, &taken)
                .with_context(|| format!("rename {} -> {}", path.display(), taken.display()))?;
            out.push(reg);
        }
        Ok(out)
    }

    pub fn write_resume(&self, resume: &WorkerResume) -> Result<PathBuf> {
        let path = self.resume_dir().join(format!("{}.json", resume.slot));
        let json = serde_json::to_vec_pretty(resume).context("serialize worker resume")?;
        write_atomic(&path, &json)?;
        Ok(path)
    }

    pub fn read_resume(&self, slot: u32) -> Result<Option<WorkerResume>> {
        let path = self.resume_dir().join(format!("{slot}.json"));
        if !path.is_file() {
            return Ok(None);
        }
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let resume =
            serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        Ok(Some(resume))
    }

    pub fn write_left(&self, exit: &WorkerExit) -> Result<PathBuf> {
        let path = self
            .left_dir()
            .join(format!("{}.json", exit.worker_id.to_hex()));
        let json = serde_json::to_vec_pretty(exit).context("serialize worker exit")?;
        write_atomic(&path, &json)?;
        Ok(path)
    }

    pub fn take_worker_exits(&self) -> Result<Vec<WorkerExit>> {
        let dir = self.left_dir();
        let mut out = Vec::new();
        if !dir.is_dir() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir).with_context(|| format!("list {}", dir.display()))? {
            let entry = entry.with_context(|| format!("read {}", dir.display()))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.ends_with(".taken"))
            {
                continue;
            }
            let text =
                fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            let exit: WorkerExit =
                serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
            let taken = path.with_extension("taken.json");
            fs::rename(&path, &taken)
                .with_context(|| format!("rename {} -> {}", path.display(), taken.display()))?;
            out.push(exit);
        }
        Ok(out)
    }

    pub fn export_admitted_snapshot(
        &self,
        dest: &Path,
        items: &[(InputId, Vec<u8>)],
    ) -> Result<()> {
        fs::create_dir_all(dest).with_context(|| format!("create {}", dest.display()))?;
        for (id, bytes) in items {
            write_atomic(&dest.join(id.to_hex()), bytes)?;
        }
        Ok(())
    }

    fn inbox_dir(&self) -> PathBuf {
        self.root.join("inbox")
    }
    fn processing_dir(&self) -> PathBuf {
        self.root.join("processing")
    }
    fn overflow_dir(&self) -> PathBuf {
        self.root.join("overflow")
    }
    fn deltas_dir(&self) -> PathBuf {
        self.root.join("deltas")
    }
    fn workers_dir(&self) -> PathBuf {
        self.root.join("workers")
    }
    fn resume_dir(&self) -> PathBuf {
        self.root.join("resume")
    }
    fn left_dir(&self) -> PathBuf {
        self.root.join("left")
    }
}

fn dir_has_worker(dir: &Path, worker: WorkerId) -> Result<bool> {
    if !dir.is_dir() {
        return Ok(false);
    }
    for entry in fs::read_dir(dir).with_context(|| format!("list {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let meta: InputMetadata = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.worker_id == Some(worker) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn count_pairs(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut n = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.parse::<InputId>().is_ok() && dir.join(format!("{name}.json")).is_file() {
            n += 1;
        }
    }
    n
}

fn take_from_dir(
    src: &Path,
    dest: &Path,
    max: usize,
) -> Result<Vec<(InputId, Vec<u8>, InputMetadata)>> {
    fs::create_dir_all(dest).with_context(|| format!("create {}", dest.display()))?;
    if !src.is_dir() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for entry in fs::read_dir(src).with_context(|| format!("list {}", src.display()))? {
        let entry = entry.with_context(|| format!("read {}", src.display()))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Ok(id) = name.parse::<InputId>() {
            ids.push(id);
        }
        if ids.len() >= max {
            break;
        }
    }
    ids.sort_unstable();
    let mut out = Vec::new();
    for id in ids {
        let hex = id.to_hex();
        let src_bin = src.join(&hex);
        let src_meta = src.join(format!("{hex}.json"));
        if !src_bin.is_file() {
            continue;
        }
        if !src_meta.is_file() {
            // Writer has not finished the pair yet.
            continue;
        }
        let bytes = fs::read(&src_bin).with_context(|| format!("read {}", src_bin.display()))?;
        let text = fs::read_to_string(&src_meta)
            .with_context(|| format!("read {}", src_meta.display()))?;
        let meta =
            serde_json::from_str(&text).with_context(|| format!("parse {}", src_meta.display()))?;
        if src != dest {
            let dest_bin = dest.join(&hex);
            let dest_meta = dest.join(format!("{hex}.json"));
            move_or_copy(&src_bin, &dest_bin)?;
            if src_meta.is_file() {
                move_or_copy(&src_meta, &dest_meta)?;
            }
        }
        out.push((id, bytes, meta));
    }
    Ok(out)
}

fn move_or_copy(src: &Path, dest: &Path) -> Result<()> {
    if src == dest {
        return Ok(());
    }
    if dest.exists() {
        let _ = fs::remove_file(dest);
    }
    if let Err(err) = fs::rename(src, dest) {
        fs::copy(src, dest)
            .with_context(|| format!("copy {} -> {} ({err})", src.display(), dest.display()))?;
        fs::remove_file(src).with_context(|| format!("remove {}", src.display()))?;
    }
    Ok(())
}

/// Append one line to a debug log. Best-effort; never on the hot path.
pub fn append_line(path: &Path, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(file, "{line}").with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{sample_target_manifest, unique_temp_dir};
    use achlys_protocol::{BuildId, CampaignId, StrategyId};

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

    fn meta(bytes: &[u8]) -> InputMetadata {
        InputMetadata {
            input_id: InputId::from_bytes(bytes),
            parent_ids: vec![],
            producer: "havoc".into(),
            producer_build: BuildId([1; 32]),
            campaign_id: CampaignId::from_label("spool"),
            local_coverage: None,
            canonical_delta: None,
            stored_unix_ms: 1,
            worker_id: Some(WorkerId::from_slot(0)),
            producer_seq: Some(1),
            strategy: Some(StrategyId::Havoc),
        }
    }

    #[test]
    fn push_is_idempotent_and_take_moves() {
        let tmp = TempDir::new("spool_push");
        let spool = CandidateSpool::create(tmp.0.join("spool")).unwrap();
        let a = spool.push(b"alpha", &meta(b"alpha")).unwrap();
        let again = spool.push(b"alpha", &meta(b"alpha")).unwrap();
        assert_eq!(a, again);
        let first = spool.take_inbox(8).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, a);
        assert!(spool.take_inbox(8).unwrap().is_empty());
        spool.ack_processed(&a).unwrap();
        assert_eq!(spool.processing_len(), 0);
        assert!(spool.take_processing(8).unwrap().is_empty());
    }

    #[test]
    fn processing_empty_only_after_ack() {
        let tmp = TempDir::new("spool_ack");
        let spool = CandidateSpool::create(tmp.0.join("spool")).unwrap();
        let id = spool.push(b"keep", &meta(b"keep")).unwrap();
        assert_eq!(spool.inbox_len(), 1);
        let _ = spool.take_inbox(8).unwrap();
        assert_eq!(spool.processing_len(), 1);
        assert_eq!(spool.inbox_len(), 0);
        spool.ack_processed(&id).unwrap();
        assert_eq!(spool.processing_len(), 0);
    }

    #[test]
    fn processing_resume_drains_more_than_one_batch() {
        let tmp = TempDir::new("spool_300");
        let spool = CandidateSpool::create(tmp.0.join("spool")).unwrap();
        let n = 300usize;
        for i in 0..n {
            let bytes = format!("seed-{i:04}").into_bytes();
            spool.push(&bytes, &meta(&bytes)).unwrap();
        }
        assert_eq!(spool.take_inbox(n).unwrap().len(), n);
        assert_eq!(spool.processing_len(), n);
        let mut seen = 0usize;
        loop {
            let batch = spool.take_processing(64).unwrap();
            if batch.is_empty() {
                break;
            }
            for (id, _, _) in batch {
                spool.ack_processed(&id).unwrap();
                seen += 1;
            }
        }
        assert_eq!(seen, n);
        assert_eq!(spool.processing_len(), 0);
    }

    #[test]
    fn deltas_are_ordered_and_filtered() {
        let tmp = TempDir::new("spool_delta");
        let spool = CandidateSpool::create(tmp.0.join("spool")).unwrap();
        let a = InputId::from_bytes(b"a");
        let b = InputId::from_bytes(b"b");
        spool.write_delta(1, &[a]).unwrap();
        spool.write_delta(3, &[b]).unwrap();
        let unread = spool.unread_deltas(1).unwrap();
        assert_eq!(unread.len(), 1);
        assert_eq!(unread[0].0, 3);
        assert_eq!(unread[0].1, vec![b]);
    }

    #[test]
    fn stop_and_worker_registration() {
        let tmp = TempDir::new("spool_stop");
        let spool = CandidateSpool::create(tmp.0.join("spool")).unwrap();
        assert!(!spool.stop_requested());
        spool.write_stop().unwrap();
        assert!(spool.stop_requested());
        let reg = WorkerRegistration {
            worker_id: WorkerId::from_slot(1),
            slot: 1,
            sender_seq: 0,
            restart: false,
            previous_seq: None,
        };
        spool.write_worker(&reg).unwrap();
        let taken = spool.take_worker_registrations().unwrap();
        assert_eq!(taken, vec![reg]);
        assert!(spool.take_worker_registrations().unwrap().is_empty());
    }

    #[test]
    fn create_makes_dirs() {
        let tmp = TempDir::new("spool_dirs");
        let _ = sample_target_manifest();
        let spool = CandidateSpool::create(tmp.0.join("spool")).unwrap();
        assert!(spool.root().join("inbox").is_dir());
        assert!(spool.root().join("deltas").is_dir());
    }
}
