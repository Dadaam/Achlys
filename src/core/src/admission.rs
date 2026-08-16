//! Authoritative candidate admission. Control plane only.
//!
//! Workers never call this per execution. The admit process submits
//! content-addressed candidates, replays them on a [`AdmitOracle`], and
//! writes `CanonicalAdmitted` / `CanonicalRejected` / `CorpusDelta`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use std::time::Instant;

use achlys_bridge::{Admission, DumpOracle};
use achlys_protocol::{
    BuildId, CampaignEvent, CoverageDigest, EventEnvelope, InputId, InputMetadata, StrategyId,
    WorkerEnvelope, WorkerId, reconstruct_events,
};
use anyhow::{Context, Result, anyhow};

use crate::store::{CampaignStore, CanonicalReport, now_unix_ms};

/// In-memory pending replay bound. Overflow stays on the spool.
pub const DEFAULT_PENDING_BOUND: usize = 4096;

/// One locally-interesting candidate, not yet canonically decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCandidate {
    pub bytes: Vec<u8>,
    pub meta: InputMetadata,
}

/// Result of [`CorpusAuthority::submit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitOutcome {
    Queued,
    Duplicate,
    QueueFull,
}

/// Counters from one [`CorpusAuthority::drain`] call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainStats {
    pub replayed: usize,
    pub admitted: usize,
    pub rejected: usize,
    pub deltas: usize,
    pub queue_full: usize,
    /// Sequence of the `CorpusDelta` written this call, if any.
    pub delta_seq: Option<u64>,
    /// Admitted ids in that delta. Empty when `delta_seq` is `None`.
    pub delta_admitted: Vec<InputId>,
}

/// Replay surface used by the authority. [`DumpOracle`] implements it.
pub trait AdmitOracle {
    fn replay(&mut self, input: &[u8]) -> Result<Admission>;
    fn build_id(&self) -> BuildId;
    fn edge_count(&self) -> u32;
    fn digest(&self) -> CoverageDigest;
}

impl AdmitOracle for DumpOracle {
    fn replay(&mut self, input: &[u8]) -> Result<Admission> {
        DumpOracle::replay(self, input).map_err(|err| anyhow!("{err}"))
    }

    fn build_id(&self) -> BuildId {
        DumpOracle::build_id(self)
    }

    fn edge_count(&self) -> u32 {
        self.union().edge_count()
    }

    fn digest(&self) -> CoverageDigest {
        self.union().digest()
    }
}

/// Single-writer canonical corpus authority.
#[derive(Debug)]
pub struct CorpusAuthority {
    store: CampaignStore,
    pending: VecDeque<InputId>,
    pending_set: HashSet<InputId>,
    seen: HashSet<InputId>,
    admitted: HashSet<InputId>,
    rejected: HashSet<InputId>,
    pending_bound: usize,
    next_delta_seq: u64,
    /// Next authority-assigned event_seq per worker (journal order).
    next_event_seq: HashMap<WorkerId, u64>,
    queue_full: u64,
    replayed: usize,
}

impl CorpusAuthority {
    #[must_use]
    pub fn new(store: CampaignStore, pending_bound: usize) -> Self {
        Self {
            store,
            pending: VecDeque::new(),
            pending_set: HashSet::new(),
            seen: HashSet::new(),
            admitted: HashSet::new(),
            rejected: HashSet::new(),
            pending_bound: pending_bound.max(1),
            next_delta_seq: 1,
            next_event_seq: HashMap::new(),
            queue_full: 0,
            replayed: 0,
        }
    }

    /// Rebuild from `events.jsonl` plus leftover unreplayed objects.
    pub fn reconstruct(store: CampaignStore, pending_bound: usize) -> Result<Self> {
        let events = store.read_events()?;
        let folded = reconstruct_events(events);
        let mut auth = Self::new(store, pending_bound);
        auth.admitted = folded.admitted.iter().copied().collect();
        auth.rejected = folded.rejected.iter().copied().collect();
        auth.seen.extend(auth.admitted.iter().copied());
        auth.seen.extend(auth.rejected.iter().copied());
        auth.replayed = auth.admitted.len().saturating_add(auth.rejected.len());
        auth.next_delta_seq = folded.last_delta_seq.saturating_add(1);
        for (worker_id, rec) in folded.workers {
            auth.next_event_seq
                .insert(worker_id, rec.last_seq.saturating_add(1));
        }
        for id in auth.store.list_inputs()? {
            auth.seen.insert(id);
            if auth.admitted.contains(&id) || auth.rejected.contains(&id) {
                continue;
            }
            auth.enqueue(id);
        }
        Ok(auth)
    }

    #[must_use]
    pub fn store(&self) -> &CampaignStore {
        &self.store
    }

    #[must_use]
    pub fn queue_full_count(&self) -> u64 {
        self.queue_full
    }

    #[must_use]
    pub fn next_delta_seq(&self) -> u64 {
        self.next_delta_seq
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn replayed(&self) -> usize {
        self.replayed
    }

    #[must_use]
    pub fn rejected_len(&self) -> usize {
        self.rejected.len()
    }

    #[must_use]
    pub fn admitted_ids(&self) -> Vec<InputId> {
        let mut ids: Vec<_> = self.admitted.iter().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Replay already-admitted objects into `oracle` so a restarted
    /// authority keeps the same union. Does not write events.
    pub fn warm_oracle<O: AdmitOracle>(&self, oracle: &mut O) -> Result<()> {
        for id in self.admitted_ids() {
            let bytes = self.store.get_input(&id)?;
            let _ = oracle.replay(&bytes)?;
        }
        Ok(())
    }

    pub fn snapshot_admitted_bytes(&self) -> Result<Vec<(InputId, Vec<u8>)>> {
        let mut out = Vec::new();
        for id in self.admitted_ids() {
            let bytes = self.store.get_input(&id)?;
            out.push((id, bytes));
        }
        Ok(out)
    }

    /// Persist bytes and enqueue canonical replay. Idempotent on `InputId`.
    pub fn submit(&mut self, mut candidate: PendingCandidate) -> Result<SubmitOutcome> {
        if candidate.bytes.is_empty() {
            anyhow::bail!("refusing empty candidate");
        }
        let id = InputId::from_bytes(&candidate.bytes);
        candidate.meta.input_id = id;
        if self.admitted.contains(&id)
            || self.rejected.contains(&id)
            || self.pending_set.contains(&id)
        {
            return Ok(SubmitOutcome::Duplicate);
        }
        self.store.put_input(&candidate.bytes, candidate.meta)?;
        self.seen.insert(id);
        if !self.enqueue(id) {
            self.queue_full = self.queue_full.saturating_add(1);
            return Ok(SubmitOutcome::QueueFull);
        }
        Ok(SubmitOutcome::Queued)
    }

    /// Replay at most `max` pending inputs. Writes one `CorpusDelta` per
    /// non-empty admit batch.
    pub fn drain<O: AdmitOracle>(&mut self, oracle: &mut O, max: usize) -> Result<DrainStats> {
        let mut stats = DrainStats {
            queue_full: self.queue_full as usize,
            ..DrainStats::default()
        };
        let mut batch = Vec::new();
        let cap = max.max(1);
        while stats.replayed < cap {
            let Some(id) = self.pending.pop_front() else {
                break;
            };
            self.pending_set.remove(&id);
            if self.admitted.contains(&id) || self.rejected.contains(&id) {
                continue;
            }
            let bytes = self
                .store
                .get_input(&id)
                .with_context(|| format!("drain missing object {id}"))?;
            let admission = oracle.replay(&bytes)?;
            stats.replayed += 1;
            self.replayed += 1;
            if admission.admitted {
                self.admitted.insert(id);
                self.rejected.remove(&id);
                stats.admitted += 1;
                batch.push(id);
                self.store.append_event(&CampaignEvent::CanonicalAdmitted {
                    campaign_id: self.store.campaign_id(),
                    input_id: id,
                    digest: admission.digest,
                    new_edges: admission.new_edges,
                    total_edges: admission.total_edges,
                    canonical_build: oracle.build_id(),
                    unix_ms: now_unix_ms(),
                })?;
            } else {
                self.rejected.insert(id);
                stats.rejected += 1;
                self.store.append_event(&CampaignEvent::CanonicalRejected {
                    campaign_id: self.store.campaign_id(),
                    input_id: id,
                    digest: admission.digest,
                    canonical_build: oracle.build_id(),
                    unix_ms: now_unix_ms(),
                })?;
            }
        }
        if !batch.is_empty() {
            let sequence = self.next_delta_seq;
            self.next_delta_seq = self.next_delta_seq.saturating_add(1);
            self.store.append_event(&CampaignEvent::CorpusDelta {
                envelope: EventEnvelope::new(self.store.campaign_id(), format!("delta:{sequence}")),
                sequence,
                admitted: batch.clone(),
                unix_ms: now_unix_ms(),
            })?;
            stats.deltas = 1;
            stats.delta_seq = Some(sequence);
            stats.delta_admitted = batch;
        }
        Ok(stats)
    }

    pub fn write_canonical_report<O: AdmitOracle>(
        &self,
        oracle: &O,
        artifact_hash: Option<String>,
    ) -> Result<CanonicalReport> {
        let report = CanonicalReport {
            digest: oracle.digest(),
            edge_count: oracle.edge_count(),
            admitted: self.admitted.len(),
            rejected: self.rejected.len(),
            replayed: self.replayed,
            canonical_build: oracle.build_id(),
            artifact_hash,
        };
        self.store.write_canonical_report(&report)?;
        Ok(report)
    }

    pub fn register_worker(
        &mut self,
        worker_id: WorkerId,
        slot: u32,
        build: BuildId,
    ) -> Result<u64> {
        let seq = self.alloc_event_seq(worker_id);
        self.store.append_event(&CampaignEvent::WorkerRegistered {
            envelope: WorkerEnvelope::new(
                self.store.campaign_id(),
                worker_id,
                seq,
                monotonic_ns(),
                CampaignEvent::worker_dedup_key(worker_id, seq),
            ),
            strategy: StrategyId::Havoc,
            producer_build: build,
            slot,
            unix_ms: now_unix_ms(),
        })?;
        Ok(seq)
    }

    pub fn note_left(&mut self, worker_id: WorkerId, reason: &str) -> Result<u64> {
        let seq = self.alloc_event_seq(worker_id);
        self.store.append_event(&CampaignEvent::WorkerLeft {
            envelope: WorkerEnvelope::new(
                self.store.campaign_id(),
                worker_id,
                seq,
                monotonic_ns(),
                CampaignEvent::worker_dedup_key(worker_id, seq),
            ),
            reason: reason.to_string(),
            unix_ms: now_unix_ms(),
        })?;
        Ok(seq)
    }

    pub fn note_restarted(&mut self, worker_id: WorkerId, previous_seq: u64) -> Result<u64> {
        let seq = self.alloc_event_seq(worker_id);
        self.store.append_event(&CampaignEvent::WorkerRestarted {
            envelope: WorkerEnvelope::new(
                self.store.campaign_id(),
                worker_id,
                seq,
                monotonic_ns(),
                CampaignEvent::worker_dedup_key(worker_id, seq),
            ),
            previous_seq,
            unix_ms: now_unix_ms(),
        })?;
        Ok(seq)
    }

    pub fn note_discovered(&mut self, meta: &InputMetadata) -> Result<u64> {
        let worker_id = meta
            .worker_id
            .ok_or_else(|| anyhow!("CandidateDiscovered requires worker_id"))?;
        let producer_seq = meta.producer_seq.unwrap_or(0);
        let seq = self.alloc_event_seq(worker_id);
        self.store
            .append_event(&CampaignEvent::CandidateDiscovered {
                envelope: WorkerEnvelope::new(
                    self.store.campaign_id(),
                    worker_id,
                    seq,
                    monotonic_ns(),
                    CampaignEvent::input_dedup_key(meta.input_id),
                ),
                input_id: meta.input_id,
                parent_ids: meta.parent_ids.clone(),
                producing_strategy: meta.strategy.unwrap_or(StrategyId::Havoc),
                producer_build: meta.producer_build,
                producer_seq,
                local_coverage: meta.local_coverage,
                local_delta_count: meta.canonical_delta.unwrap_or(0),
                execution_ns: 0,
                generation_ns: 0,
                unix_ms: now_unix_ms(),
            })?;
        Ok(seq)
    }

    fn alloc_event_seq(&mut self, worker_id: WorkerId) -> u64 {
        let seq = self.next_event_seq.get(&worker_id).copied().unwrap_or(0);
        self.next_event_seq.insert(worker_id, seq.saturating_add(1));
        seq
    }

    fn enqueue(&mut self, id: InputId) -> bool {
        if self.pending_set.contains(&id) {
            return true;
        }
        if self.pending.len() >= self.pending_bound {
            return false;
        }
        self.pending.push_back(id);
        self.pending_set.insert(id);
        true
    }
}

fn monotonic_ns() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{sample_target_manifest, unique_temp_dir};
    use achlys_bridge::CoverageBitmap;
    use achlys_protocol::{
        BuildIdentity, BuildIdentityParts, BuildKind, CampaignId, CampaignRecord, TargetId,
    };
    use libafl::executors::ExitKind;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(label: &str) -> Self {
            Self(unique_temp_dir(label))
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct FakeOracle {
        build_id: BuildId,
        union: CoverageBitmap,
    }

    impl FakeOracle {
        fn new() -> Self {
            Self {
                build_id: BuildId([9; 32]),
                union: CoverageBitmap::new(8),
            }
        }
    }

    impl AdmitOracle for FakeOracle {
        fn replay(&mut self, input: &[u8]) -> Result<Admission> {
            let mut snap = vec![0u8; 8];
            if let Some(&b) = input.first() {
                snap[(b as usize) % 8] = 1;
            }
            if input.contains(&0xff) {
                snap[7] = 1;
            }
            let new_edges = self.union.union_from(&snap);
            Ok(Admission {
                input_id: InputId::from_bytes(input),
                digest: CoverageBitmap::from_slice(&snap).digest(),
                new_edges,
                total_edges: self.union.edge_count(),
                admitted: new_edges > 0,
                exit: ExitKind::Ok,
            })
        }

        fn build_id(&self) -> BuildId {
            self.build_id
        }

        fn edge_count(&self) -> u32 {
            self.union.edge_count()
        }

        fn digest(&self) -> CoverageDigest {
            self.union.digest()
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

    fn open_auth(label: &str, bound: usize) -> (TempDir, CorpusAuthority) {
        let tmp = TempDir::new(label);
        let campaign = CampaignId::from_label(label);
        let store = CampaignStore::create(&tmp.0, campaign, &sample_target_manifest()).unwrap();
        let record = CampaignRecord {
            schema_version: CampaignEvent::SCHEMA_VERSION,
            campaign_id: campaign,
            target_id: "micro-store".into(),
            label: label.into(),
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
            fast_build: sample_build(),
            canonical_build: None,
            sanitizer_build: None,
            started_unix_ms: 0,
        };
        store.write_campaign_record(&record).unwrap();
        (tmp, CorpusAuthority::new(store, bound))
    }

    fn cand(bytes: &[u8], worker: u32, seq: u64) -> PendingCandidate {
        PendingCandidate {
            bytes: bytes.to_vec(),
            meta: InputMetadata {
                input_id: InputId::from_bytes(bytes),
                parent_ids: vec![],
                producer: "havoc".into(),
                producer_build: BuildId([1; 32]),
                campaign_id: CampaignId::from_label("x"),
                local_coverage: None,
                canonical_delta: None,
                stored_unix_ms: 1,
                worker_id: Some(WorkerId::from_slot(worker)),
                producer_seq: Some(seq),
                strategy: Some(StrategyId::Havoc),
            },
        }
    }

    #[test]
    fn submit_same_bytes_is_duplicate() {
        let (_tmp, mut auth) = open_auth("adm_dup", 8);
        assert_eq!(
            auth.submit(cand(b"\x01seed", 0, 1)).unwrap(),
            SubmitOutcome::Queued
        );
        assert_eq!(
            auth.submit(cand(b"\x01seed", 1, 1)).unwrap(),
            SubmitOutcome::Duplicate
        );
        assert_eq!(auth.store().list_inputs().unwrap().len(), 1);
        assert_eq!(auth.pending_len(), 1);
    }

    #[test]
    fn drain_admits_new_edges_once() {
        let (_tmp, mut auth) = open_auth("adm_drain", 8);
        let mut oracle = FakeOracle::new();
        auth.submit(cand(b"\x01aaa", 0, 1)).unwrap();
        auth.submit(cand(b"\x01bbb", 0, 2)).unwrap();
        auth.submit(cand(&[0xff], 0, 3)).unwrap();
        let stats = auth.drain(&mut oracle, 16).unwrap();
        assert_eq!(stats.replayed, 3);
        assert_eq!(stats.admitted, 2);
        assert_eq!(stats.rejected, 1);
        assert_eq!(stats.deltas, 1);
        assert_eq!(auth.admitted_ids().len(), 2);

        let stats2 = auth.drain(&mut oracle, 16).unwrap();
        assert_eq!(stats2.replayed, 0);
    }

    #[test]
    fn reconstruct_keeps_admitted_after_drop() {
        let (tmp, mut auth) = open_auth("adm_recon", 8);
        let mut oracle = FakeOracle::new();
        auth.register_worker(WorkerId::from_slot(0), 0, BuildId([1; 32]))
            .unwrap();
        auth.submit(cand(b"\x02zz", 0, 1)).unwrap();
        auth.note_discovered(&cand(b"\x02zz", 0, 1).meta).unwrap();
        auth.drain(&mut oracle, 8).unwrap();
        let admitted = auth.admitted_ids();
        assert_eq!(admitted.len(), 1);
        let campaign = auth.store().campaign_id();
        drop(auth);

        let store = CampaignStore::open(&tmp.0, campaign).unwrap();
        let restored = CorpusAuthority::reconstruct(store, 8).unwrap();
        assert_eq!(restored.admitted_ids(), admitted);
        assert_eq!(restored.pending_len(), 0);
        assert_eq!(auth_worker_count(&restored), 1);
        let mut oracle2 = FakeOracle::new();
        restored.warm_oracle(&mut oracle2).unwrap();
        assert_eq!(oracle2.edge_count(), oracle.edge_count());
    }

    fn auth_worker_count(auth: &CorpusAuthority) -> usize {
        reconstruct_events(auth.store().read_events().unwrap())
            .workers
            .len()
    }

    #[test]
    fn queue_full_does_not_drop_object() {
        let (_tmp, mut auth) = open_auth("adm_full", 1);
        assert_eq!(
            auth.submit(cand(b"\x01one", 0, 1)).unwrap(),
            SubmitOutcome::Queued
        );
        assert_eq!(
            auth.submit(cand(b"\x02two", 0, 2)).unwrap(),
            SubmitOutcome::QueueFull
        );
        assert_eq!(auth.pending_len(), 1);
        assert_eq!(auth.store().list_inputs().unwrap().len(), 2);
        assert_eq!(auth.queue_full_count(), 1);
    }

    #[test]
    fn drain_returns_delta_without_rereading_log() {
        let (_tmp, mut auth) = open_auth("adm_delta", 8);
        let mut oracle = FakeOracle::new();
        auth.submit(cand(b"\x03zz", 0, 1)).unwrap();
        let stats = auth.drain(&mut oracle, 8).unwrap();
        assert_eq!(stats.delta_seq, Some(1));
        assert_eq!(stats.delta_admitted.len(), 1);
        assert_eq!(stats.delta_admitted[0], InputId::from_bytes(b"\x03zz"));
    }

    #[test]
    fn queue_full_then_drain_can_enqueue_again() {
        let (_tmp, mut auth) = open_auth("adm_full_drain", 1);
        let mut oracle = FakeOracle::new();
        assert_eq!(
            auth.submit(cand(b"\x01one", 0, 1)).unwrap(),
            SubmitOutcome::Queued
        );
        assert_eq!(
            auth.submit(cand(b"\x02two", 0, 2)).unwrap(),
            SubmitOutcome::QueueFull
        );
        auth.drain(&mut oracle, 8).unwrap();
        assert_eq!(auth.pending_len(), 0);
        assert_eq!(
            auth.submit(cand(b"\x02two", 0, 2)).unwrap(),
            SubmitOutcome::Queued
        );
        let stats = auth.drain(&mut oracle, 8).unwrap();
        assert_eq!(stats.replayed, 1);
        assert_eq!(auth.replayed(), 2);
        assert_eq!(auth.admitted_ids().len() + auth.rejected_len(), 2);
    }

    #[test]
    fn event_seq_is_monotonic_when_producer_seq_is_shuffled() {
        let (_tmp, mut auth) = open_auth("adm_event_seq", 8);
        let w = WorkerId::from_slot(0);
        auth.register_worker(w, 0, BuildId([1; 32])).unwrap();
        let mut late = cand(b"\x01late", 0, 9);
        late.meta.producer_seq = Some(9);
        let mut early = cand(b"\x02early", 0, 1);
        early.meta.producer_seq = Some(1);
        auth.note_discovered(&late.meta).unwrap();
        auth.note_discovered(&early.meta).unwrap();
        auth.note_left(w, "budget").unwrap();
        let mut seqs = Vec::new();
        for ev in auth.store().read_events().unwrap() {
            match ev {
                CampaignEvent::WorkerRegistered { envelope, .. }
                | CampaignEvent::CandidateDiscovered { envelope, .. }
                | CampaignEvent::WorkerLeft { envelope, .. }
                    if envelope.worker_id == w =>
                {
                    seqs.push(envelope.sender_seq);
                }
                _ => {}
            }
        }
        assert_eq!(seqs, vec![0, 1, 2, 3]);
    }
}
