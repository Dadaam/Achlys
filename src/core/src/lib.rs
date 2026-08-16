//! Achlys fuzzing engine.
//!
//! Provides the `FuzzerBuilder` for configuring and running fuzzing campaigns,
//! with plateau detection and automatic escalation between mutation strategies.

pub mod ai_mutator;
pub mod ai_stage;
pub mod builder;
pub mod config;
pub mod cortex_interface;
pub mod escalation;
pub mod feedback;
pub mod plateau;

pub use ai_mutator::AiMutator;
pub use ai_stage::HybridStage;
pub use builder::FuzzerBuilder;
pub use config::FuzzerConfig;
pub use cortex_interface::CortexInterface;
pub use escalation::{
    EscalatingStage, EscalationManager, FuzzStage, SharedLogSink, shared_log_sink,
};
pub use feedback::PlateauAwareFeedback;
pub use plateau::{PlateauDetector, SharedPlateauDetector, shared_detector};
