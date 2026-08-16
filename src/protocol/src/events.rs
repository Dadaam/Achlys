use serde::{Deserialize, Serialize};

use crate::identity::BuildIdentity;
use crate::ids::{BuildId, CampaignId, CoverageDigest, InputId};

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
}

/// Periodic, coarse metrics. Not a per-execution hot-path message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub executions: u64,
    pub corpus_count: usize,
    pub objectives: usize,
    pub canonical_edges: u32,
    pub elapsed_ms: u64,
}

/// Append-only campaign event. Versioned for artifact replay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CampaignEvent {
    CampaignStarted {
        schema_version: u32,
        campaign_id: CampaignId,
        target_id: String,
        build: BuildIdentity,
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
        unix_ms: u64,
    },
    CanonicalRejected {
        campaign_id: CampaignId,
        input_id: InputId,
        digest: CoverageDigest,
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
}

impl CampaignEvent {
    pub const SCHEMA_VERSION: u32 = 1;

    /// One JSON object, no trailing newline.
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_jsonl(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line)
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
            build: id,
            unix_ms: 0,
        };
        let parsed = CampaignEvent::from_jsonl(&ev.to_jsonl().unwrap()).unwrap();
        assert!(matches!(parsed, CampaignEvent::CampaignStarted { .. }));
    }
}
