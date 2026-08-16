use std::path::PathBuf;
use std::time::Duration;

use libafl_bolts::current_nanos;

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
    /// RNG seed. Required for H0 paired trials; default is `current_nanos()`.
    pub rng_seed: u64,
    /// Stop after this many `fuzz_loop_for` iterations (substrate only).
    pub max_iters: Option<u64>,
    /// Stop after this wall-clock budget (substrate only).
    pub max_time: Option<Duration>,
    /// Per-execution timeout passed to `InProcessExecutor::with_timeout`.
    pub exec_timeout: Duration,
    /// If set, queue is `InMemoryOnDiskCorpus`. `None` is for unit tests only.
    pub persist_corpus_dir: Option<PathBuf>,
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
            rng_seed: current_nanos(),
            max_iters: None,
            max_time: None,
            exec_timeout: Duration::from_millis(1000),
            persist_corpus_dir: None,
        }
    }
}

/// Outcome of a bounded substrate (H0) campaign.
#[derive(Debug, Clone)]
pub struct SubstrateReport {
    pub executions: u64,
    pub corpus_count: usize,
    pub objectives: usize,
    pub elapsed: Duration,
}
