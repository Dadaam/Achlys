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
    /// Next unused worker generation number (`producer_seq`).
    pub next_producer_seq: u64,
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
    /// Stable control-notice ids already in the journal, mapped to event_seq.
    pub seen_notices: BTreeMap<String, u64>,
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
            next_producer_seq: 0,
        })
    }

    fn note_notice(&mut self, notice_id: &str, sender_seq: u64) {
        if !notice_id.is_empty() {
            self.seen_notices.insert(notice_id.to_string(), sender_seq);
        }
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
                envelope,
                notice_id,
                strategy,
                slot,
                ..
            } => {
                out.note_notice(&notice_id, envelope.sender_seq);
                {
                    let rec = out.worker_mut(envelope.worker_id);
                    rec.strategy = Some(strategy);
                    rec.slot = Some(slot);
                    rec.left = false;
                }
                out.note_seq(envelope.worker_id, envelope.sender_seq);
            }
            CampaignEvent::WorkerLeft {
                envelope,
                notice_id,
                next_producer_seq,
                ..
            } => {
                out.note_notice(&notice_id, envelope.sender_seq);
                {
                    let rec = out.worker_mut(envelope.worker_id);
                    rec.left = true;
                    if next_producer_seq > rec.next_producer_seq {
                        rec.next_producer_seq = next_producer_seq;
                    }
                }
                out.note_seq(envelope.worker_id, envelope.sender_seq);
            }
            CampaignEvent::WorkerRestarted {
                envelope,
                notice_id,
                previous_seq,
                ..
            } => {
                out.note_notice(&notice_id, envelope.sender_seq);
                let already = out
                    .workers
                    .get(&envelope.worker_id)
                    .is_some_and(|rec| envelope.sender_seq <= rec.last_seq);
                if !already {
                    let rec = out.worker_mut(envelope.worker_id);
                    rec.left = false;
                    rec.restarts = rec.restarts.saturating_add(1);
                    if previous_seq > rec.last_seq {
                        rec.last_seq = previous_seq;
                    }
                    out.note_seq(envelope.worker_id, envelope.sender_seq);
                }
            }
            CampaignEvent::CandidateDiscovered {
                envelope,
                producer_seq,
                ..
            } => {
                out.note_seq(envelope.worker_id, envelope.sender_seq);
                let rec = out.worker_mut(envelope.worker_id);
                let next = producer_seq.saturating_add(1);
                if next > rec.next_producer_seq {
                    rec.next_producer_seq = next;
                }
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
    use crate::events::{CampaignEvent, EventEnvelope, WorkerEnvelope};
    use crate::ids::{BuildId, CampaignId, CoverageDigest};

    fn wenv(worker: WorkerId, seq: u64) -> WorkerEnvelope {
        WorkerEnvelope::new(
            campaign(),
            worker,
            seq,
            seq,
            CampaignEvent::worker_dedup_key(worker, seq),
        )
    }

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
                envelope: wenv(w0, 0),
                notice_id: "reg-0".into(),
                strategy: StrategyId::Havoc,
                producer_build: BuildId([0; 32]),
                slot: 0,
                unix_ms: 0,
            },
            CampaignEvent::WorkerRegistered {
                envelope: wenv(w1, 0),
                notice_id: "reg-1".into(),
                strategy: StrategyId::Havoc,
                producer_build: BuildId([0; 32]),
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
                envelope: EventEnvelope::new(campaign(), "delta:1"),
                sequence: 1,
                admitted: vec![a],
                unix_ms: 4,
            },
            CampaignEvent::WorkerRestarted {
                envelope: wenv(w0, 4),
                notice_id: "rst-0".into(),
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
            envelope: wenv(w0, 4),
            notice_id: "rst-0".into(),
            previous_seq: 3,
            unix_ms: 5,
        };
        let delta = CampaignEvent::CorpusDelta {
            envelope: EventEnvelope::new(campaign(), "delta:1"),
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

    #[test]
    fn worker_left_restores_next_producer_seq() {
        let w0 = WorkerId::from_slot(0);
        let events = vec![
            CampaignEvent::WorkerRegistered {
                envelope: wenv(w0, 0),
                notice_id: "reg-0".into(),
                strategy: StrategyId::Havoc,
                producer_build: BuildId([0; 32]),
                slot: 0,
                unix_ms: 0,
            },
            CampaignEvent::CandidateDiscovered {
                envelope: wenv(w0, 1),
                input_id: InputId::from_bytes(b"x"),
                parent_ids: vec![],
                producing_strategy: StrategyId::Havoc,
                producer_build: BuildId([0; 32]),
                producer_seq: 25,
                local_coverage: None,
                local_delta_count: 0,
                execution_ns: 0,
                generation_ns: 0,
                unix_ms: 1,
            },
            CampaignEvent::WorkerLeft {
                envelope: wenv(w0, 2),
                notice_id: "left-0-26".into(),
                next_producer_seq: 26,
                reason: "budget".into(),
                unix_ms: 2,
            },
        ];
        let rec = reconstruct_events(events);
        assert_eq!(rec.workers[&w0].last_seq, 2);
        assert_eq!(rec.workers[&w0].next_producer_seq, 26);
        assert_ne!(
            rec.workers[&w0].last_seq.saturating_add(1),
            rec.workers[&w0].next_producer_seq,
            "producer_seq must not be derived from event_seq"
        );
        assert!(rec.seen_notices.contains_key("reg-0"));
        assert!(rec.seen_notices.contains_key("left-0-26"));
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
                envelope: wenv(w1, 0),
                notice_id: "reg-1".into(),
                strategy: StrategyId::Havoc,
                producer_build: BuildId([0; 32]),
                slot: 1,
                unix_ms: 0,
            },
            CampaignEvent::WorkerRestarted {
                envelope: wenv(w0, 4),
                notice_id: "rst-0".into(),
                previous_seq: 3,
                unix_ms: 5,
            },
        ]
    }
}
