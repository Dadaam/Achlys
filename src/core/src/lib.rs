//! Achlys fuzzing engine.
//!
//! Provides the `FuzzerBuilder` for configuring and running fuzzing campaigns,
//! with plateau detection and automatic escalation between mutation strategies.

pub mod config;
pub mod builder;
pub mod plateau;
pub mod feedback;
pub mod escalation;
pub mod cortex_interface;
pub mod ai_mutator;
pub mod ai_stage;

pub use config::FuzzerConfig;
pub use builder::FuzzerBuilder;
pub use plateau::{PlateauDetector, SharedPlateauDetector, shared_detector};
pub use feedback::PlateauAwareFeedback;
pub use escalation::{FuzzStage, EscalationManager, EscalatingStage};
pub use cortex_interface::CortexInterface;
pub use ai_mutator::AiMutator;
pub use ai_stage::HybridStage;
