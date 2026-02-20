use anyhow::Result;

/// Interface that achlys-core uses to request AI-guided mutations.
///
/// This trait lives in core (not cortex) to enable dependency inversion:
/// core defines what it needs, cortex provides it. The CLI wires them together.
///
/// Implementations:
/// - `CortexModel` in achlys-cortex: real ONNX inference
/// - `PassthroughCortex` in achlys-cortex: random mutations for testing
pub trait CortexInterface: Send + Sync {
    /// Given corpus samples (byte sequences that found new coverage),
    /// predict mutations likely to discover more coverage.
    ///
    /// Returns `count` mutated byte vectors, each a complete input candidate.
    fn predict_mutations(
        &self,
        corpus_samples: &[&[u8]],
        count: usize,
    ) -> Result<Vec<Vec<u8>>>;

    /// Whether the model is loaded and ready for inference.
    fn is_ready(&self) -> bool;
}
