use anyhow::Result;

use achlys_core::cortex_interface::CortexInterface;

/// Test double for integration testing without a real ONNX model.
///
/// Returns slightly mutated versions of the input corpus samples
/// (random byte flips). Validates the full AI pipeline integration
/// without requiring a trained model.
pub struct PassthroughCortex {
    mutation_rate: f64,
}

impl PassthroughCortex {
    /// Create a passthrough cortex with a given mutation rate (0.0 - 1.0).
    /// Each byte has `mutation_rate` probability of being flipped.
    pub fn new(mutation_rate: f64) -> Self {
        Self {
            mutation_rate: mutation_rate.clamp(0.0, 1.0),
        }
    }
}

impl Default for PassthroughCortex {
    fn default() -> Self {
        Self::new(0.05) // 5% mutation rate
    }
}

impl CortexInterface for PassthroughCortex {
    fn predict_mutations(
        &self,
        corpus_samples: &[&[u8]],
        count: usize,
    ) -> Result<Vec<Vec<u8>>> {
        if corpus_samples.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::with_capacity(count);

        // Simple LCG for deterministic-ish random without pulling in rand
        let mut rng_state: u64 = 0xdeadbeef;
        let mut next_rng = || -> u64 {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            rng_state
        };

        for i in 0..count {
            let sample = corpus_samples[i % corpus_samples.len()];
            let mut mutated = sample.to_vec();

            for byte in mutated.iter_mut() {
                let r = (next_rng() % 1000) as f64 / 1000.0;
                if r < self.mutation_rate {
                    *byte ^= (next_rng() & 0xFF) as u8;
                }
            }

            results.push(mutated);
        }

        Ok(results)
    }

    fn is_ready(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passthrough_returns_correct_count() {
        let cortex = PassthroughCortex::default();
        let samples: Vec<&[u8]> = vec![b"hello", b"world"];
        let result = cortex.predict_mutations(&samples, 5).unwrap();
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_passthrough_preserves_length() {
        let cortex = PassthroughCortex::new(0.0); // no mutations
        let samples: Vec<&[u8]> = vec![b"test"];
        let result = cortex.predict_mutations(&samples, 1).unwrap();
        assert_eq!(result[0].len(), 4);
        assert_eq!(result[0], b"test"); // 0% mutation = identical
    }

    #[test]
    fn test_passthrough_empty_corpus() {
        let cortex = PassthroughCortex::default();
        let samples: Vec<&[u8]> = vec![];
        let result = cortex.predict_mutations(&samples, 5).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_passthrough_is_ready() {
        let cortex = PassthroughCortex::default();
        assert!(cortex.is_ready());
    }
}
