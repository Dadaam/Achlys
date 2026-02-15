use std::path::PathBuf;
use std::time::Duration;

/// Configuration for the Achlys fuzzer.
#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    /// Directory containing seed corpus files. If None, random inputs are generated.
    pub corpus_dir: Option<PathBuf>,
    /// Directory to store crash-triggering inputs.
    pub crashes_dir: PathBuf,
    /// Number of random initial inputs to generate (if no corpus_dir).
    pub initial_inputs: usize,
    /// Maximum input size in bytes for the random generator.
    pub max_input_len: usize,
    /// Duration of no new coverage before declaring a plateau.
    pub plateau_timeout: Duration,
    /// Optional path to an ONNX model for Stage 2 (AI Hybrid).
    pub model_path: Option<PathBuf>,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            corpus_dir: None,
            crashes_dir: PathBuf::from("./crashes"),
            initial_inputs: 8,
            max_input_len: 4096,
            plateau_timeout: Duration::from_secs(600),
            model_path: None,
        }
    }
}
