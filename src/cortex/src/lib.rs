//! AI brain for Achlys.
//!
//! Provides ONNX model loading and inference (`CortexModel`),
//! autonomous training (`AutoTrainer`), and hot-swapping (`HotSwapCortex`).

pub mod hotswap;
pub mod model;
pub mod passthrough;
pub mod trainer;

pub use hotswap::HotSwapCortex;
pub use model::CortexModel;
pub use passthrough::PassthroughCortex;
pub use trainer::AutoTrainer;
