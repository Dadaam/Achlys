//! Filesystem candidate spool. Workers write; the admit process reads.
//!
//! Not on the execution hot path. All names are content-addressed so a
//! duplicate push is a no-op.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use achlys_protocol::{InputId, InputMetadata, WorkerId};
use anyhow::{Context, Result, anyhow, bail};

use crate::store::{write_atomic, write_once};

/// Default bound on how many inbox records `take_inbox` returns per call.
pub const DEFAULT_TAKE: usize = 64;

/// One indivisible publication. The filename is the hash of `bytes`.
#[derive(serde::Serialize, serde::Deserialize)]
struct CandidateRecord {
    bytes: Vec<u8>,
    meta: InputMetadata,
}

fn record_path(dir: &Path, id: &InputId) -> PathBuf {
    dir.join(format!("{}.candidate", id.to_hex()))
}

fn publish_record(dir: &Path, bytes: &[u8], meta: &InputMetadata) -> Result<InputId> {
    let id = InputId::from_bytes(bytes);
    let mut meta = meta.clone();
    meta.input_id = id;
    let record = CandidateRecord {
        bytes: bytes.to_vec(),
        meta,
    };
    write_once(&record_path(dir, &id), &serde_json::to_vec(&record)?)?;
    Ok(id)
}

/// On-disk worker registration written by a worker at start.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkerRegistration {
    pub notice_id: String,
    pub worker_id: WorkerId,
    pub slot: u32,
    pub restart: bool,
    pub previous_event_seq: Option<u64>,
    pub next_producer_seq: u64,
}

/// Offline continuation plan written by the launcher before spawn.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkerResume {
    pub worker_id: WorkerId,
    pub slot: u32,
    pub restart: bool,
    pub previous_event_seq: Option<u64>,
    pub next_producer_seq: u64,
}

/// Worker exit notice. Admit turns this into `WorkerLeft`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkerExit {
    pub notice_id: String,
    pub worker_id: WorkerId,
    pub slot: u32,
    pub next_producer_seq: u64,
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
            root.join("workers").join("processing"),
            root.join("snapshot"),
            root.join("resume"),
            root.join("left"),
            root.join("left").join("processing"),
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
        publish_record(&self.inbox_dir(), bytes, meta)
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
        let path = record_path(&self.processing_dir(), id);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context("ack candidate"),
        }
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
        publish_record(&self.overflow_dir(), bytes, meta)
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

    /// Upgrade pre-closure pairs while no worker or authority is running.
    /// Recovers a kill between the old object's and sidecar's separate moves.
    pub fn migrate_legacy(&self) -> Result<usize> {
        let dirs = [self.inbox_dir(), self.processing_dir(), self.overflow_dir()];
        let mut migrated = 0;
        for dir in &dirs {
            for entry in fs::read_dir(dir)? {
                let path = entry?.path();
                let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                let Ok(id) = name.parse::<InputId>() else {
                    continue;
                };
                let sidecar = dirs
                    .iter()
                    .map(|d| d.join(format!("{name}.json")))
                    .find(|p| p.is_file())
                    .context("legacy candidate has no metadata")?;
                let bytes = fs::read(&path)?;
                let meta: InputMetadata = serde_json::from_slice(&fs::read(&sidecar)?)?;
                if InputId::from_bytes(&bytes) != id {
                    bail!("legacy candidate hash mismatch");
                }
                publish_record(&self.processing_dir(), &bytes, &meta)?;
                fs::remove_file(&path)?;
                fs::remove_file(&sidecar)?;
                migrated += 1;
            }
        }
        Ok(migrated)
    }

    pub fn write_stop(&self) -> Result<()> {
        write_atomic(&self.root.join("STOP"), b"1\n")
    }

    pub fn clear_stop(&self) -> Result<()> {
        let path = self.root.join("STOP");
        if path.is_file() {
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        }
        Ok(())
    }

    #[must_use]
    pub fn stop_requested(&self) -> bool {
        self.root.join("STOP").is_file()
    }

    pub fn write_worker(&self, reg: &WorkerRegistration) -> Result<PathBuf> {
        let path = self
            .workers_dir()
            .join(format!("{}.json", notice_file_stem(&reg.notice_id)));
        let json = serde_json::to_vec_pretty(reg).context("serialize worker registration")?;
        write_atomic(&path, &json)?;
        Ok(path)
    }

    pub fn take_worker_registrations(&self) -> Result<Vec<WorkerRegistration>> {
        take_notices(&self.workers_dir(), &self.workers_processing_dir())
    }

    pub fn ack_worker_registration(&self, notice_id: &str) -> Result<()> {
        ack_notice(&self.workers_processing_dir(), notice_id)
    }

    pub fn return_worker_registration(&self, reg: &WorkerRegistration) -> Result<()> {
        return_notice(
            &self.workers_processing_dir(),
            &self.workers_dir(),
            &reg.notice_id,
            || self.write_worker(reg).map(|_| ()),
        )
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
            .join(format!("{}.json", notice_file_stem(&exit.notice_id)));
        let json = serde_json::to_vec_pretty(exit).context("serialize worker exit")?;
        write_atomic(&path, &json)?;
        Ok(path)
    }

    pub fn take_worker_exits(&self) -> Result<Vec<WorkerExit>> {
        take_notices(&self.left_dir(), &self.left_processing_dir())
    }

    pub fn ack_worker_exit(&self, notice_id: &str) -> Result<()> {
        ack_notice(&self.left_processing_dir(), notice_id)
    }

    pub fn return_worker_exit(&self, exit: &WorkerExit) -> Result<()> {
        return_notice(
            &self.left_processing_dir(),
            &self.left_dir(),
            &exit.notice_id,
            || self.write_left(exit).map(|_| ()),
        )
    }

    /// Unacked control notices still sitting in inbox or processing.
    #[must_use]
    pub fn leftover_control_notices(&self) -> usize {
        count_json_files(&self.workers_dir())
            + count_json_files(&self.workers_processing_dir())
            + count_json_files(&self.left_dir())
            + count_json_files(&self.left_processing_dir())
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
    fn workers_processing_dir(&self) -> PathBuf {
        self.root.join("workers").join("processing")
    }
    fn left_processing_dir(&self) -> PathBuf {
        self.root.join("left").join("processing")
    }
    fn resume_dir(&self) -> PathBuf {
        self.root.join("resume")
    }
    fn left_dir(&self) -> PathBuf {
        self.root.join("left")
    }
}

fn candidate_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("list {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) == Some("candidate") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn read_record(path: &Path) -> Result<CandidateRecord> {
    let record: CandidateRecord = serde_json::from_slice(&fs::read(path)?)
        .with_context(|| format!("decode candidate {}", path.display()))?;
    let id = InputId::from_bytes(&record.bytes);
    if record.meta.input_id != id || path.file_stem().and_then(|s| s.to_str()) != Some(&id.to_hex())
    {
        bail!("candidate content hash mismatch: {}", path.display());
    }
    Ok(record)
}

fn dir_has_worker(dir: &Path, worker: WorkerId) -> Result<bool> {
    for path in candidate_files(dir)? {
        if read_record(&path)?.meta.worker_id == Some(worker) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn count_pairs(dir: &Path) -> usize {
    // An unreadable spool must never look drained.
    candidate_files(dir).map(|v| v.len()).unwrap_or(usize::MAX)
}

fn take_from_dir(
    src: &Path,
    dest: &Path,
    max: usize,
) -> Result<Vec<(InputId, Vec<u8>, InputMetadata)>> {
    fs::create_dir_all(dest)?;
    let mut out = Vec::new();
    for path in candidate_files(src)?.into_iter().take(max) {
        let record = read_record(&path)?;
        if src != dest {
            let target = record_path(dest, &record.meta.input_id);
            // If a duplicate is already in processing, retain its first provenance.
            if target.is_file() {
                fs::remove_file(&path)?;
                continue;
            }
            fs::rename(&path, &target).context("claim indivisible candidate")?;
        }
        out.push((record.meta.input_id, record.bytes, record.meta));
    }
    Ok(out)
}

fn notice_file_stem(notice_id: &str) -> String {
    notice_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn take_notices<T>(inbox: &Path, processing: &Path) -> Result<Vec<T>>
where
    T: serde::de::DeserializeOwned,
{
    fs::create_dir_all(processing).with_context(|| format!("create {}", processing.display()))?;
    let mut out = Vec::new();
    load_json_dir(processing, &mut out)?;
    if !inbox.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(inbox).with_context(|| format!("list {}", inbox.display()))? {
        let entry = entry.with_context(|| format!("read {}", inbox.display()))?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let dest = processing.join(path.file_name().unwrap_or_default());
        move_or_copy(&path, &dest)?;
        let text = fs::read_to_string(&dest).with_context(|| format!("read {}", dest.display()))?;
        out.push(serde_json::from_str(&text).with_context(|| format!("parse {}", dest.display()))?);
    }
    Ok(out)
}

fn load_json_dir<T>(dir: &Path, out: &mut Vec<T>) -> Result<()>
where
    T: serde::de::DeserializeOwned,
{
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("list {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        out.push(serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?);
    }
    Ok(())
}

fn ack_notice(processing: &Path, notice_id: &str) -> Result<()> {
    let path = processing.join(format!("{}.json", notice_file_stem(notice_id)));
    if path.is_file() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

fn return_notice(
    processing: &Path,
    inbox: &Path,
    notice_id: &str,
    rewrite: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let name = format!("{}.json", notice_file_stem(notice_id));
    let src = processing.join(&name);
    let dest = inbox.join(&name);
    if src.is_file() {
        move_or_copy(&src, &dest)
    } else {
        rewrite()
    }
}

fn count_json_files(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            let path = entry.path();
            path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json")
        })
        .count()
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
    fn duplicate_publication_preserves_first_origin() {
        let tmp = TempDir::new("spool_origin");
        let spool = CandidateSpool::create(tmp.0.join("spool")).unwrap();
        let first = meta(b"seed");
        let mut second = first.clone();
        second.worker_id = Some(WorkerId::from_slot(1));
        spool.push(b"seed", &first).unwrap();
        spool.push(b"seed", &second).unwrap();
        assert_eq!(spool.take_inbox(1).unwrap()[0].2, first);
    }

    #[test]
    fn legacy_split_pair_recovers_after_interrupted_claim() {
        let tmp = TempDir::new("spool_split");
        let spool = CandidateSpool::create(tmp.0.join("spool")).unwrap();
        let m = meta(b"seed");
        fs::write(spool.processing_dir().join(m.input_id.to_hex()), b"seed").unwrap();
        fs::write(
            spool.inbox_dir().join(format!("{}.json", m.input_id)),
            serde_json::to_vec(&m).unwrap(),
        )
        .unwrap();
        assert_eq!(spool.migrate_legacy().unwrap(), 1);
        let got = spool.take_processing(1).unwrap();
        assert_eq!(got[0].1, b"seed");
        spool.ack_processed(&m.input_id).unwrap();
        assert!(!spool.has_pending_for(m.worker_id.unwrap()).unwrap());
    }

    #[test]
    fn corrupted_candidate_fails_before_admission() {
        let tmp = TempDir::new("spool_corrupt");
        let spool = CandidateSpool::create(tmp.0.join("spool")).unwrap();
        let id = spool.push(b"seed", &meta(b"seed")).unwrap();
        let path = record_path(&spool.inbox_dir(), &id);
        let mut record = read_record(&path).unwrap();
        record.bytes.push(1);
        fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(spool.take_inbox(1).is_err());
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
            notice_id: "reg-w1-0".into(),
            worker_id: WorkerId::from_slot(1),
            slot: 1,
            restart: false,
            previous_event_seq: None,
            next_producer_seq: 0,
        };
        spool.write_worker(&reg).unwrap();
        let taken = spool.take_worker_registrations().unwrap();
        assert_eq!(taken, vec![reg.clone()]);
        let again = spool.take_worker_registrations().unwrap();
        assert_eq!(again, vec![reg.clone()], "unacked notices must be replayed");
        spool.ack_worker_registration(&reg.notice_id).unwrap();
        assert!(spool.take_worker_registrations().unwrap().is_empty());
    }

    #[test]
    fn control_notice_survives_reopen_before_ack() {
        let tmp = TempDir::new("spool_notice_crash");
        let root = tmp.0.join("spool");
        let spool = CandidateSpool::create(&root).unwrap();
        let exit = WorkerExit {
            notice_id: "left-w0-4".into(),
            worker_id: WorkerId::from_slot(0),
            slot: 0,
            next_producer_seq: 4,
            reason: "budget".into(),
        };
        spool.write_left(&exit).unwrap();
        let first = spool.take_worker_exits().unwrap();
        assert_eq!(first, vec![exit.clone()]);
        drop(spool);
        let reopened = CandidateSpool::open(&root).unwrap();
        let replayed = reopened.take_worker_exits().unwrap();
        assert_eq!(replayed, vec![exit.clone()]);
        reopened.ack_worker_exit(&exit.notice_id).unwrap();
        assert!(reopened.take_worker_exits().unwrap().is_empty());
    }

    #[test]
    fn return_exit_is_rename_and_survives_reopen() {
        let tmp = TempDir::new("spool_return_exit");
        let root = tmp.0.join("spool");
        let spool = CandidateSpool::create(&root).unwrap();
        let exit = WorkerExit {
            notice_id: "left-w0-p4-e1".into(),
            worker_id: WorkerId::from_slot(0),
            slot: 0,
            next_producer_seq: 4,
            reason: "budget".into(),
        };
        spool.write_left(&exit).unwrap();
        let taken = spool.take_worker_exits().unwrap();
        assert_eq!(taken, vec![exit.clone()]);
        assert_eq!(spool.leftover_control_notices(), 1);
        spool.return_worker_exit(&exit).unwrap();
        assert_eq!(count_json_files(&spool.left_processing_dir()), 0);
        assert_eq!(count_json_files(&spool.left_dir()), 1);
        drop(spool);
        let reopened = CandidateSpool::open(&root).unwrap();
        assert_eq!(reopened.take_worker_exits().unwrap(), vec![exit.clone()]);
        reopened.ack_worker_exit(&exit.notice_id).unwrap();
        assert_eq!(reopened.leftover_control_notices(), 0);
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
