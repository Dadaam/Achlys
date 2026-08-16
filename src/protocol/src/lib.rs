//! Versioned identifiers, target manifests, and campaign artifact events.
//!
//! This crate is the Tranche 1 contract surface. It must stay free of
//! LibAFL, ONNX, and orchestration. Do not add leases, LLMP, or ML types
//! here until those tranches exist.

pub mod events;
pub mod identity;
pub mod ids;
pub mod manifest;

pub use events::{CampaignEvent, InputMetadata, MetricsSnapshot};
pub use identity::{BuildIdentity, BuildIdentityParts};
pub use ids::{BuildId, CampaignId, CoverageDigest, InputId, TargetId};
pub use manifest::{
    BuildKind, BuildSpec, Builds, InputMode, Instrumentation, ManifestError, SourceSpec,
    TargetManifest,
};
