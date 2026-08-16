//! Versioned identifiers, target manifests, and campaign artifact events.
//!
//! This crate is the Tranche 1/2 contract surface. It must stay free of
//! LibAFL, ONNX, leases, and ML. T2 adds worker ids, discovery events,
//! and event-log reconstruction only.

pub mod events;
pub mod identity;
pub mod ids;
pub mod manifest;
pub mod reconstruct;

pub use events::{
    CampaignEvent, CampaignRecord, CrashStats, EventEnvelope, InputMetadata, MetricsSnapshot,
    WorkerEnvelope,
};
pub use identity::{BuildIdentity, BuildIdentityParts};
pub use ids::{BuildId, CampaignId, CoverageDigest, InputId, StrategyId, TargetId, WorkerId};
pub use manifest::{
    BuildKind, BuildSpec, Builds, InputMode, Instrumentation, ManifestError, SourceSpec,
    TargetManifest,
};
pub use reconstruct::{ReconstructedCampaign, WorkerRecord, reconstruct_events};
