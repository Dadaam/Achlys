use std::collections::VecDeque;
use std::sync::Arc;

use libafl::{
    corpus::{Corpus, CorpusId},
    inputs::{BytesInput, HasTargetBytes},
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasRand},
    Error,
};
use libafl_bolts::{rands::Rand, AsSlice, Named};

use std::borrow::Cow;

use crate::cortex_interface::CortexInterface;

/// A LibAFL Mutator that uses the cortex AI to predict mutations.
///
/// Calls `CortexInterface::predict_mutations()` in batches and caches
/// the results. Each call to `mutate()` consumes one cached prediction.
/// When the cache is empty, a new batch is requested from the cortex.
pub struct AiMutator {
    cortex: Arc<dyn CortexInterface>,
    cache: VecDeque<Vec<u8>>,
    batch_size: usize,
    name: Cow<'static, str>,
}

impl AiMutator {
    pub fn new(cortex: Arc<dyn CortexInterface>, batch_size: usize) -> Self {
        Self {
            cortex,
            cache: VecDeque::with_capacity(batch_size),
            batch_size,
            name: Cow::Borrowed("AiMutator"),
        }
    }
}

impl Named for AiMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Mutator<BytesInput, S> for AiMutator
where
    S: HasCorpus<BytesInput> + HasRand,
    S::Corpus: Corpus<BytesInput>,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        // Refill cache from cortex if empty
        if self.cache.is_empty() {
            let count = state.corpus().count();

            if count == 0 {
                return Ok(MutationResult::Skipped);
            }

            // Pre-compute random indices to avoid borrow conflict
            let sample_count = count.min(self.batch_size);
            let indices: Vec<CorpusId> = (0..sample_count)
                .map(|i| {
                    if count > sample_count {
                        CorpusId::from(
                            state
                                .rand_mut()
                                .below(std::num::NonZeroUsize::new(count).unwrap()),
                        )
                    } else {
                        CorpusId::from(i)
                    }
                })
                .collect();

            // Now borrow corpus immutably to read samples
            let mut samples_data: Vec<Vec<u8>> = Vec::with_capacity(sample_count);
            let corpus = state.corpus();
            for idx in indices {
                if let Ok(testcase) = corpus.get(idx) {
                    let tc = testcase.borrow();
                    if let Some(inp) = tc.input() {
                        let bytes: &BytesInput = inp;
                        let target = bytes.target_bytes();
                        samples_data.push(target.as_slice().to_vec());
                    }
                }
            }

            if samples_data.is_empty() {
                return Ok(MutationResult::Skipped);
            }

            let sample_refs: Vec<&[u8]> = samples_data.iter().map(|s| s.as_slice()).collect();

            match self.cortex.predict_mutations(&sample_refs, self.batch_size) {
                Ok(predictions) => {
                    self.cache.extend(predictions);
                }
                Err(e) => {
                    eprintln!("[achlys] cortex prediction error: {}", e);
                    return Ok(MutationResult::Skipped);
                }
            }
        }

        // Use a cached prediction to replace the input
        if let Some(predicted) = self.cache.pop_front() {
            *input = BytesInput::new(predicted);
            Ok(MutationResult::Mutated)
        } else {
            Ok(MutationResult::Skipped)
        }
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cortex_interface::CortexInterface;

    struct MockCortex;

    impl CortexInterface for MockCortex {
        fn predict_mutations(
            &self,
            corpus_samples: &[&[u8]],
            count: usize,
        ) -> anyhow::Result<Vec<Vec<u8>>> {
            Ok((0..count)
                .map(|i| {
                    let sample = corpus_samples[i % corpus_samples.len()];
                    let mut mutated = sample.to_vec();
                    if let Some(b) = mutated.first_mut() {
                        *b = b.wrapping_add(1);
                    }
                    mutated
                })
                .collect())
        }

        fn is_ready(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_ai_mutator_creation() {
        let cortex = Arc::new(MockCortex);
        let mutator = AiMutator::new(cortex, 32);
        assert_eq!(mutator.name().as_ref(), "AiMutator");
        assert!(mutator.cache.is_empty());
    }
}
