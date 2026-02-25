use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use ort::session::Session;
use ort::tensor::Shape;
use ort::value::Tensor;

use achlys_core::cortex_interface::CortexInterface;

/// ONNX-based AI brain for predicting promising mutations.
///
/// Loads an LSTM/GRU model trained on corpus byte patterns.
/// Input: byte sequences normalized to [0, 1] (divided by 255).
/// Output: predicted byte sequences (mutation candidates).
pub struct CortexModel {
    session: Mutex<Session>,
    max_seq_len: usize,
}

impl CortexModel {
    /// Load an ONNX model from a file.
    ///
    /// Expected model format:
    /// - Input: `[batch_size, max_seq_len]` float32 (bytes normalized to [0, 1])
    /// - Output: `[batch_size, max_seq_len]` float32 (predicted bytes in [0, 1])
    pub fn load(model_path: impl AsRef<Path>, max_seq_len: usize) -> Result<Self> {
        let session = Session::builder()
            .context("failed to create ONNX session builder")?
            .commit_from_file(model_path.as_ref())
            .with_context(|| {
                format!(
                    "failed to load ONNX model: {}",
                    model_path.as_ref().display()
                )
            })?;

        // Validate model inputs/outputs
        let inputs = session.inputs();
        let outputs = session.outputs();

        if inputs.is_empty() {
            anyhow::bail!("ONNX model has no inputs");
        }
        if outputs.is_empty() {
            anyhow::bail!("ONNX model has no outputs");
        }

        println!(
            "[achlys-cortex] loaded ONNX model: {}",
            model_path.as_ref().display()
        );
        println!(
            "[achlys-cortex] model input: {} ({:?})",
            inputs[0].name(),
            inputs[0].dtype()
        );
        println!(
            "[achlys-cortex] model output: {} ({:?})",
            outputs[0].name(),
            outputs[0].dtype()
        );
        println!(
            "[achlys-cortex] max_seq_len: {}",
            max_seq_len
        );

        Ok(Self {
            session: Mutex::new(session),
            max_seq_len,
        })
    }

    /// Encode byte sequences into float32 vectors normalized to [0, 1].
    fn encode_samples(&self, samples: &[&[u8]], batch_size: usize) -> Vec<f32> {
        let mut tensor = vec![0.0f32; batch_size * self.max_seq_len];

        for (i, sample) in samples.iter().take(batch_size).enumerate() {
            let len = sample.len().min(self.max_seq_len);
            for (j, &byte) in sample[..len].iter().enumerate() {
                tensor[i * self.max_seq_len + j] = byte as f32 / 255.0;
            }
        }

        tensor
    }

    /// Decode float32 data back to byte sequences.
    fn decode_predictions(&self, data: &[f32], count: usize) -> Vec<Vec<u8>> {
        let mut results = Vec::with_capacity(count);

        for i in 0..count {
            let start = i * self.max_seq_len;
            let end = (start + self.max_seq_len).min(data.len());

            if start >= data.len() {
                break;
            }

            let bytes: Vec<u8> = data[start..end]
                .iter()
                .map(|&v| (v.clamp(0.0, 1.0) * 255.0) as u8)
                .collect();

            results.push(bytes);
        }

        results
    }
}

impl CortexInterface for CortexModel {
    fn predict_mutations(
        &self,
        corpus_samples: &[&[u8]],
        count: usize,
    ) -> Result<Vec<Vec<u8>>> {
        if corpus_samples.is_empty() {
            return Ok(Vec::new());
        }

        let batch_size = corpus_samples.len().min(count);
        let input_data = self.encode_samples(corpus_samples, batch_size);

        let shape = Shape::new([batch_size as i64, self.max_seq_len as i64]);
        let input_tensor = Tensor::<f32>::from_array((shape, input_data))
            .context("failed to create input tensor")?;

        let mut session = self
            .session
            .lock()
            .map_err(|e| anyhow::anyhow!("session lock poisoned: {}", e))?;

        let outputs = session
            .run(ort::inputs![input_tensor])
            .context("ONNX inference failed")?;

        let output_tensor = outputs[0]
            .try_extract_tensor::<f32>()
            .context("failed to extract output tensor")?;

        let (_shape, data) = output_tensor;
        let output_data: Vec<f32> = data.iter().copied().collect();
        let predictions = self.decode_predictions(&output_data, count);

        Ok(predictions)
    }

    fn is_ready(&self) -> bool {
        self.session.lock().is_ok()
    }
}
