use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};

use achlys_core::cortex_interface::CortexInterface;

use crate::model::CortexModel;

/// A CortexInterface implementation that supports hot-swapping the underlying model.
///
/// Starts empty (no model loaded). When `load_model()` is called, the new model
/// replaces the current one atomically. During the swap, ongoing predictions
/// complete with the old model; new predictions use the new one.
///
/// Used by the AutoTrainer to inject newly trained models into a running fuzzer
/// without stopping the fuzz loop.
pub struct HotSwapCortex {
    inner: Mutex<Option<CortexModel>>,
    max_seq_len: usize,
    has_model: AtomicBool,
}

impl HotSwapCortex {
    /// Create an empty hot-swap cortex (no model loaded yet).
    #[must_use]
    pub fn empty(max_seq_len: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(None),
            max_seq_len,
            has_model: AtomicBool::new(false),
        })
    }

    /// Create a hot-swap cortex with an initial model.
    #[must_use]
    pub fn with_model(model: CortexModel, max_seq_len: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(model)),
            max_seq_len,
            has_model: AtomicBool::new(true),
        })
    }

    /// Load a new model from an ONNX file, replacing the current one.
    pub fn load_model(&self, path: impl AsRef<Path>) -> Result<()> {
        let new_model = CortexModel::load(path.as_ref(), self.max_seq_len)
            .context("failed to load new model for hot-swap")?;

        let mut guard = self
            .inner
            .lock()
            .map_err(|e| anyhow::anyhow!("hot-swap lock poisoned: {}", e))?;

        *guard = Some(new_model);
        self.has_model.store(true, Ordering::Release);

        println!("[achlys-cortex] hot-swapped model: {}", path.as_ref().display());
        Ok(())
    }

    /// Check if a model is currently loaded.
    pub fn has_loaded_model(&self) -> bool {
        self.has_model.load(Ordering::Acquire)
    }
}

impl CortexInterface for HotSwapCortex {
    fn predict_mutations(
        &self,
        corpus_samples: &[&[u8]],
        count: usize,
    ) -> Result<Vec<Vec<u8>>> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| anyhow::anyhow!("cortex lock poisoned: {}", e))?;

        match &*guard {
            Some(model) => model.predict_mutations(corpus_samples, count),
            None => Ok(Vec::new()), // No model yet, skip AI mutations
        }
    }

    fn is_ready(&self) -> bool {
        self.has_model.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_cortex_returns_empty() {
        let cortex = HotSwapCortex::empty(256);
        assert!(!cortex.is_ready());
        assert!(!cortex.has_loaded_model());

        let samples: Vec<&[u8]> = vec![b"hello"];
        let result = cortex.predict_mutations(&samples, 5).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_empty_cortex_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HotSwapCortex>();
    }
}
