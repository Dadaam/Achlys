//! Rebuild campaign control-plane state from the append-only event log.
//!
//! Pure function: no filesystem, no LibAFL. The authority uses this after
//! restart; tests use it to prove the published totals are reconstructable.

use std::collections::{BTreeMap, BTreeSet};

use crate::events::CampaignEvent;
use crate::ids::{InputId, StrategyId, WorkerId};

/// Last known control-plane record for one worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerRecord {
    pub worker_id: WorkerId,
    pub last_seq: u64,
    pub strategy: Option<StrategyId>,
    pub slot: Option<u32>,
    pub left: bool,
    pub restarts: u32,
}

/// Deterministic view of a campaign reconstructed from JSONL events.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReconstructedCampaign {
    pub workers: BTreeMap<WorkerId, WorkerRecord>,
    pub stored: BTreeSet<InputId>,
    pub admitted: BTreeSet<InputId>,
    pub rejected: BTreeSet<InputId>,
    pub last_delta_seq: u64,
    pub deltas: u64,
}

impl ReconstructedCampaign {
    fn worker_mut(&mut self, worker_id: WorkerId) -> &mut WorkerRecord {
        self.workers.entry(worker_id).or_insert(WorkerRecord {
            worker_id,
            last_seq: 0,
            strategy: None,
            slot: None,
            left: false,
            restarts: 0,
        })
    }

    fn note_seq(&mut self, worker_id: WorkerId, sender_seq: u64) {
        let rec = self.worker_mut(worker_id);
        if sender_seq > rec.last_seq {
            rec.last_seq = sender_seq;
        }
    }
}

/// Fold an event stream. Duplicate events are idempotent.
pub fn reconstruct_events<I>(events: I) -> ReconstructedCampaign
where
    I: IntoIterator<Item = CampaignEvent>,
{
    let mut out = ReconstructedCampaign::default();
    for ev in events {
        match ev {
            CampaignEvent::InputStored { input_id, .. } => {
                out.stored.insert(input_id);
            }
            CampaignEvent::CanonicalAdmitted { input_id, .. } => {
                out.admitted.insert(input_id);
                out.rejected.remove(&input_id);
            }
            CampaignEvent::CanonicalRejected { input_id, .. } => {
                if !out.admitted.contains(&input_id) {
                    out.rejected.insert(input_id);
                }
            }
            CampaignEvent::WorkerRegistered {
                worker_id,
                sender_seq,
                strategy,
                slot,
                ..
            } => {
                {
                    let rec = out.worker_mut(worker_id);
                    rec.strategy = Some(strategy);
                    rec.slot = Some(slot);
                    rec.left = false;
                }
                out.note_seq(worker_id, sender_seq);
            }
            CampaignEvent::WorkerLeft {
                worker_id,
                sender_seq,
                ..
            } => {
                out.worker_mut(worker_id).left = true;
                out.note_seq(worker_id, sender_seq);
            }
            CampaignEvent::WorkerRestarted {
                worker_id,
                sender_seq,
                previous_seq,
                ..
            } => {
                let already = out
                    .workers
                    .get(&worker_id)
                    .is_some_and(|rec| sender_seq <= rec.last_seq);
                if !already {
                    let rec = out.worker_mut(worker_id);
                    rec.left = false;
                    rec.restarts = rec.restarts.saturating_add(1);
                    if previous_seq > rec.last_seq {
                        rec.last_seq = previous_seq;
                    }
                    out.note_seq(worker_id, sender_seq);
                }
            }
            CampaignEvent::CandidateDiscovered {
                worker_id,
                sender_seq,
                ..
            } => {
                out.note_seq(worker_id, sender_seq);
            }
            CampaignEvent::CorpusDelta { sequence, .. } => {
                if sequence > out.last_delta_seq {
                    out.deltas = out.deltas.saturating_add(1);
                    out.last_delta_seq = sequence;
                }
            }
            CampaignEvent::CampaignStarted { .. }
            | CampaignEvent::CrashDiscovered { .. }
            | CampaignEvent::CrashVerified { .. }
            | CampaignEvent::Metrics { .. }
            | CampaignEvent::CampaignFinished { .. } => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::CampaignEvent;
    use crate::ids::{BuildId, CampaignId, CoverageDigest};

    fn campaign() -> CampaignId {
        CampaignId::from_label("recon")
    }

    #[test]
    fn reconstruct_is_idempotent_and_tracks_workers() {
        let w0 = WorkerId::from_slot(0);
        let w1 = WorkerId::from_slot(1);
        let a = InputId::from_bytes(b"a");
        let b = InputId::from_bytes(b"b");
        let events = vec![
            CampaignEvent::WorkerRegistered {
                schema_version: CampaignEvent::SCHEMA_VERSION,
                campaign_id: campaign(),
                worker_id: w0,
                sender_seq: 0,
                timestamp_monotonic_ns: 0,
                dedup_key: CampaignEvent::worker_dedup_key(w0, 0),
                strategy: StrategyId::Havoc,
                producer_build: BuildId([0; 32]),
                protocol_version: CampaignEvent::PROTOCOL_VERSION,
                slot: 0,
                unix_ms: 0,
            },
            CampaignEvent::WorkerRegistered {
                schema_version: CampaignEvent::SCHEMA_VERSION,
                campaign_id: campaign(),
                worker_id: w1,
                sender_seq: 0,
                timestamp_monotonic_ns: 0,
                dedup_key: CampaignEvent::worker_dedup_key(w1, 0),
                strategy: StrategyId::Havoc,
                producer_build: BuildId([0; 32]),
                protocol_version: CampaignEvent::PROTOCOL_VERSION,
                slot: 1,
                unix_ms: 0,
            },
            CampaignEvent::InputStored {
                campaign_id: campaign(),
                input_id: a,
                bytes: 1,
                unix_ms: 1,
            },
            CampaignEvent::InputStored {
                campaign_id: campaign(),
                input_id: a,
                bytes: 1,
                unix_ms: 1,
            },
            CampaignEvent::CanonicalAdmitted {
                campaign_id: campaign(),
                input_id: a,
                digest: CoverageDigest([0; 32]),
                new_edges: 1,
                total_edges: 1,
                canonical_build: BuildId([2; 32]),
                unix_ms: 2,
            },
            CampaignEvent::CanonicalRejected {
                campaign_id: campaign(),
                input_id: b,
                digest: CoverageDigest([0; 32]),
                canonical_build: BuildId([2; 32]),
                unix_ms: 3,
            },
            CampaignEvent::CorpusDelta {
                campaign_id: campaign(),
                sequence: 1,
                admitted: vec![a],
                unix_ms: 4,
            },
            CampaignEvent::WorkerRestarted {
                campaign_id: campaign(),
                worker_id: w0,
                sender_seq: 4,
                timestamp_monotonic_ns: 5,
                dedup_key: CampaignEvent::worker_dedup_key(w0, 4),
                previous_seq: 3,
                unix_ms: 5,
            },
        ];
        let once = reconstruct_events(events.clone());
        let twice = reconstruct_events(events.into_iter().chain(once_more(&once, a, b, w0, w1)));
        assert_eq!(once.admitted, BTreeSet::from([a]));
        assert_eq!(once.rejected, BTreeSet::from([b]));
        assert_eq!(once.stored, BTreeSet::from([a]));
        assert_eq!(once.last_delta_seq, 1);
        assert_eq!(once.workers[&w0].restarts, 1);
        assert_eq!(once.workers[&w0].last_seq, 4);
        assert_eq!(once.workers.len(), 2);
        assert_eq!(twice.admitted, once.admitted);
        assert_eq!(twice.rejected, once.rejected);
        assert_eq!(twice.workers[&w0].last_seq, 4);
        assert_eq!(twice.workers[&w0].restarts, once.workers[&w0].restarts);
        assert_eq!(twice.deltas, once.deltas);
    }

    #[test]
    fn duplicate_restart_and_delta_do_not_double_count() {
        let w0 = WorkerId::from_slot(0);
        let restart = CampaignEvent::WorkerRestarted {
            campaign_id: campaign(),
            worker_id: w0,
            sender_seq: 4,
            timestamp_monotonic_ns: 5,
            dedup_key: CampaignEvent::worker_dedup_key(w0, 4),
            previous_seq: 3,
            unix_ms: 5,
        };
        let delta = CampaignEvent::CorpusDelta {
            campaign_id: campaign(),
            sequence: 1,
            admitted: vec![InputId::from_bytes(b"a")],
            unix_ms: 4,
        };
        let once = reconstruct_events(vec![restart.clone(), delta.clone()]);
        let twice = reconstruct_events(vec![restart.clone(), delta.clone(), restart, delta]);
        assert_eq!(once.workers[&w0].restarts, 1);
        assert_eq!(twice.workers[&w0].restarts, 1);
        assert_eq!(once.deltas, 1);
        assert_eq!(twice.deltas, 1);
    }

    fn once_more(
        _state: &ReconstructedCampaign,
        a: InputId,
        b: InputId,
        w0: WorkerId,
        w1: WorkerId,
    ) -> Vec<CampaignEvent> {
        vec![
            CampaignEvent::CanonicalAdmitted {
                campaign_id: campaign(),
                input_id: a,
                digest: CoverageDigest([0; 32]),
                new_edges: 1,
                total_edges: 1,
                canonical_build: BuildId([2; 32]),
                unix_ms: 2,
            },
            CampaignEvent::CanonicalRejected {
                campaign_id: campaign(),
                input_id: b,
                digest: CoverageDigest([0; 32]),
                canonical_build: BuildId([2; 32]),
                unix_ms: 3,
            },
            CampaignEvent::WorkerRegistered {
                schema_version: CampaignEvent::SCHEMA_VERSION,
                campaign_id: campaign(),
                worker_id: w1,
                sender_seq: 0,
                timestamp_monotonic_ns: 0,
                dedup_key: CampaignEvent::worker_dedup_key(w1, 0),
                strategy: StrategyId::Havoc,
                producer_build: BuildId([0; 32]),
                protocol_version: CampaignEvent::PROTOCOL_VERSION,
                slot: 1,
                unix_ms: 0,
            },
            CampaignEvent::WorkerRestarted {
                campaign_id: campaign(),
                worker_id: w0,
                sender_seq: 4,
                timestamp_monotonic_ns: 5,
                dedup_key: CampaignEvent::worker_dedup_key(w0, 4),
                previous_seq: 3,
                unix_ms: 5,
            },
        ]
    }
}
