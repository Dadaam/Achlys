use serde::{Deserialize, Serialize};

use crate::identity::BuildIdentity;
use crate::ids::{BuildId, CampaignId, CoverageDigest, InputId, StrategyId, WorkerId};

/// Provenance stored next to a content-addressed input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputMetadata {
    pub input_id: InputId,
    #[serde(default)]
    pub parent_ids: Vec<InputId>,
    pub producer: String,
    pub producer_build: BuildId,
    pub campaign_id: CampaignId,
    #[serde(default)]
    pub local_coverage: Option<CoverageDigest>,
    #[serde(default)]
    pub canonical_delta: Option<u32>,
    pub stored_unix_ms: u64,
    #[serde(default)]
    pub worker_id: Option<WorkerId>,
    #[serde(default)]
    pub producer_seq: Option<u64>,
    #[serde(default)]
    pub strategy: Option<StrategyId>,
}

/// Crash-pipeline counters. Raw file count is never a verified-bug metric.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashStats {
    pub candidates: usize,
    pub unique_candidates: usize,
    pub replays_attempted: usize,
    pub reproduced_crashes: usize,
    pub unique_crash_signatures: usize,
    pub clean_replays: usize,
    pub timeouts: usize,
    pub infra_failures: usize,
}

/// Periodic, coarse metrics. Not a per-execution hot-path message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub executions: u64,
    pub corpus_count: usize,
    pub objectives: usize,
    pub canonical_edges: u32,
    pub elapsed_ms: u64,
    #[serde(default)]
    pub crash: CrashStats,
}

/// Append-only campaign event. Versioned for artifact replay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum CampaignEvent {
    CampaignStarted {
        schema_version: u32,
        campaign_id: CampaignId,
        target_id: String,
        fast_build: BuildIdentity,
        #[serde(default)]
        canonical_build: Option<BuildIdentity>,
        #[serde(default)]
        sanitizer_build: Option<BuildIdentity>,
        unix_ms: u64,
    },
    InputStored {
        campaign_id: CampaignId,
        input_id: InputId,
        bytes: u64,
        unix_ms: u64,
    },
    CanonicalAdmitted {
        campaign_id: CampaignId,
        input_id: InputId,
        digest: CoverageDigest,
        new_edges: u32,
        total_edges: u32,
        canonical_build: BuildId,
        unix_ms: u64,
    },
    CanonicalRejected {
        campaign_id: CampaignId,
        input_id: InputId,
        digest: CoverageDigest,
        canonical_build: BuildId,
        unix_ms: u64,
    },
    CrashDiscovered {
        campaign_id: CampaignId,
        input_id: InputId,
        producer_build: BuildId,
        unix_ms: u64,
    },
    CrashVerified {
        campaign_id: CampaignId,
        input_id: InputId,
        class: String,
        stack_signature: Option<String>,
        dedup_key: String,
        sanitizer_build: BuildId,
        reproducible: bool,
        unix_ms: u64,
    },
    Metrics {
        campaign_id: CampaignId,
        snapshot: MetricsSnapshot,
        unix_ms: u64,
    },
    CampaignFinished {
        campaign_id: CampaignId,
        snapshot: MetricsSnapshot,
        unix_ms: u64,
    },
    WorkerRegistered {
        schema_version: u32,
        campaign_id: CampaignId,
        worker_id: WorkerId,
        sender_seq: u64,
        timestamp_monotonic_ns: u64,
        dedup_key: String,
        strategy: StrategyId,
        producer_build: BuildId,
        protocol_version: u32,
        slot: u32,
        unix_ms: u64,
    },
    WorkerLeft {
        campaign_id: CampaignId,
        worker_id: WorkerId,
        sender_seq: u64,
        timestamp_monotonic_ns: u64,
        dedup_key: String,
        reason: String,
        unix_ms: u64,
    },
    WorkerRestarted {
        campaign_id: CampaignId,
        worker_id: WorkerId,
        sender_seq: u64,
        timestamp_monotonic_ns: u64,
        dedup_key: String,
        previous_seq: u64,
        unix_ms: u64,
    },
    CandidateDiscovered {
        campaign_id: CampaignId,
        worker_id: WorkerId,
        sender_seq: u64,
        timestamp_monotonic_ns: u64,
        dedup_key: String,
        input_id: InputId,
        parent_ids: Vec<InputId>,
        producing_strategy: StrategyId,
        producer_build: BuildId,
        local_coverage: Option<CoverageDigest>,
        local_delta_count: u32,
        execution_ns: u64,
        generation_ns: u64,
        unix_ms: u64,
    },
    CorpusDelta {
        campaign_id: CampaignId,
        sequence: u64,
        admitted: Vec<InputId>,
        unix_ms: u64,
    },
}

/// Immutable campaign header written once at `begin`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignRecord {
    pub schema_version: u32,
    pub campaign_id: CampaignId,
    pub target_id: String,
    pub label: String,
    pub seed: u64,
    pub max_iters: Option<u64>,
    pub max_seconds: Option<u64>,
    pub max_input_len: usize,
    pub timeout_ms: u64,
    pub tool: String,
    pub host: String,
    pub rustc: String,
    pub git: String,
    /// Tracked dirty files only (`git status --porcelain`, excluding `??`).
    #[serde(default, alias = "git_dirty")]
    pub git_dirty_tracked: u32,
    /// Untracked paths (`??`). Not included in `git_dirty_tracked`.
    #[serde(default)]
    pub git_untracked: u32,
    pub fast_build: BuildIdentity,
    pub canonical_build: Option<BuildIdentity>,
    pub sanitizer_build: Option<BuildIdentity>,
    pub started_unix_ms: u64,
}

impl CampaignEvent {
    pub const SCHEMA_VERSION: u32 = 1;
    /// T2 worker protocol. Independent of campaign artifact schema_version.
    pub const PROTOCOL_VERSION: u32 = 1;

    /// One JSON object, no trailing newline.
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_jsonl(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line)
    }

    /// Envelope dedup key for a worker-originated control event.
    #[must_use]
    pub fn worker_dedup_key(worker_id: WorkerId, sender_seq: u64) -> String {
        format!("{}:{sender_seq}", worker_id.to_hex())
    }

    /// Envelope dedup key for a content-addressed candidate.
    #[must_use]
    pub fn input_dedup_key(input_id: InputId) -> String {
        format!("input:{}", input_id.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{BuildIdentity, BuildIdentityParts};
    use crate::ids::TargetId;
    use crate::manifest::BuildKind;
    use std::collections::BTreeMap;

    #[test]
    fn event_jsonl_roundtrip() {
        let campaign = CampaignId::from_label("evt");
        let input = InputId::from_bytes(b"crash");
        let ev = CampaignEvent::CrashDiscovered {
            campaign_id: campaign,
            input_id: input,
            producer_build: BuildId([0; 32]),
            unix_ms: 1,
        };
        let line = ev.to_jsonl().unwrap();
        assert!(!line.contains('\n'));
        assert_eq!(CampaignEvent::from_jsonl(&line).unwrap(), ev);
    }

    #[test]
    fn started_event_embeds_build_identity() {
        let id = BuildIdentity::compute(BuildIdentityParts {
            target_id: TargetId("t".into()),
            kind: BuildKind::Fast,
            compiler: "clang".into(),
            flags: vec!["-O3".into()],
            source_hashes: BTreeMap::new(),
            artifact_hash: None,
        });
        let ev = CampaignEvent::CampaignStarted {
            schema_version: CampaignEvent::SCHEMA_VERSION,
            campaign_id: CampaignId::from_label("s"),
            target_id: "t".into(),
            fast_build: id,
            canonical_build: None,
            sanitizer_build: None,
            unix_ms: 0,
        };
        let parsed = CampaignEvent::from_jsonl(&ev.to_jsonl().unwrap()).unwrap();
        assert!(matches!(parsed, CampaignEvent::CampaignStarted { .. }));
    }

    #[test]
    fn t1_started_json_still_parses_without_worker_fields() {
        let line = ev_started_without_t2_fields();
        let parsed = CampaignEvent::from_jsonl(&line).unwrap();
        assert!(matches!(parsed, CampaignEvent::CampaignStarted { .. }));
    }

    #[test]
    fn candidate_discovered_jsonl_roundtrip() {
        let ev = CampaignEvent::CandidateDiscovered {
            campaign_id: CampaignId::from_label("t2"),
            worker_id: WorkerId::from_slot(0),
            sender_seq: 3,
            timestamp_monotonic_ns: 9,
            dedup_key: CampaignEvent::input_dedup_key(InputId::from_bytes(b"x")),
            input_id: InputId::from_bytes(b"x"),
            parent_ids: vec![],
            producing_strategy: StrategyId::Havoc,
            producer_build: BuildId([1; 32]),
            local_coverage: None,
            local_delta_count: 1,
            execution_ns: 2,
            generation_ns: 3,
            unix_ms: 4,
        };
        let parsed = CampaignEvent::from_jsonl(&ev.to_jsonl().unwrap()).unwrap();
        assert_eq!(parsed, ev);
    }

    fn ev_started_without_t2_fields() -> String {
        let id = BuildIdentity::compute(BuildIdentityParts {
            target_id: TargetId("t".into()),
            kind: BuildKind::Fast,
            compiler: "clang".into(),
            flags: vec!["-O3".into()],
            source_hashes: BTreeMap::new(),
            artifact_hash: None,
        });
        let ev = CampaignEvent::CampaignStarted {
            schema_version: CampaignEvent::SCHEMA_VERSION,
            campaign_id: CampaignId::from_label("s"),
            target_id: "t".into(),
            fast_build: id,
            canonical_build: None,
            sanitizer_build: None,
            unix_ms: 0,
        };
        ev.to_jsonl().unwrap()
    }
}
