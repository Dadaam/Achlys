//! AI brain for Achlys.
//!
//! Provides ONNX model loading and inference (`CortexModel`),
//! autonomous training (`AutoTrainer`), and hot-swapping (`HotSwapCortex`).

pub mod model;
pub mod passthrough;
pub mod trainer;
pub mod hotswap;

pub use model::CortexModel;
pub use passthrough::PassthroughCortex;
pub use trainer::AutoTrainer;
pub use hotswap::HotSwapCortex;
