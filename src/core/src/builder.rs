use std::fs;
use std::num::NonZero;
use std::path::PathBuf;
use std::ptr::addr_of_mut;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    executors::inprocess::InProcessExecutor,
    feedbacks::{ConstFeedback, CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice};

use achlys_bridge::Target;

/// Callback type for custom monitor output (TUI, logging, etc.).
type MonitorCallback = Box<dyn FnMut(&str)>;

use crate::ai_mutator::{AiMutator, DEFAULT_PREDICTION_BATCH};
use crate::ai_stage::HybridStage;
use crate::config::FuzzerConfig;
use crate::cortex_interface::CortexInterface;
use crate::escalation::EscalatingStage;
use crate::feedback::PlateauAwareFeedback;
use crate::plateau::shared_detector;

/// Builder for configuring and running an Achlys fuzzer instance.
///
/// Reduces the ~100 lines of LibAFL boilerplate to a fluent API.
/// All LibAFL generics stay internal — the public API only exposes
/// `FuzzerConfig`, `Target`, and optionally a `CortexInterface`.
#[must_use]
pub struct FuzzerBuilder {
    config: FuzzerConfig,
    cortex: Option<Arc<dyn CortexInterface>>,
    monitor_fn: Option<MonitorCallback>,
}

impl FuzzerBuilder {
    pub fn new() -> Self {
        Self {
            config: FuzzerConfig::default(),
            cortex: None,
            monitor_fn: None,
        }
    }

    pub fn config(mut self, config: FuzzerConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the AI cortex for Stage 2 mutations.
    pub fn cortex(mut self, cortex: Option<Arc<dyn CortexInterface>>) -> Self {
        self.cortex = cortex;
        self
    }

    pub fn corpus_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.corpus_dir = Some(path.into());
        self
    }

    pub fn crashes_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.crashes_dir = path.into();
        self
    }

    pub fn plateau_timeout(mut self, duration: Duration) -> Self {
        self.config.plateau_timeout = duration;
        self
    }

    pub fn model_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.model_path = Some(path.into());
        self
    }

    pub fn initial_inputs(mut self, count: usize) -> Self {
        self.config.initial_inputs = count;
        self
    }

    pub fn max_input_len(mut self, len: usize) -> Self {
        self.config.max_input_len = len;
        self
    }

    /// Set a custom monitor callback (replaces the default println output).
    /// Used by the TUI to intercept stats updates.
    pub fn monitor(mut self, f: impl FnMut(&str) + 'static) -> Self {
        self.monitor_fn = Some(Box::new(f));
        self
    }

    /// Build and run the fuzzer with the given target.
    pub fn run(self, mut target: impl Target) -> Result<()> {
        if target.has_coverage() {
            self.run_graybox(target)
        } else {
            self.run_blackbox(target)
        }
    }

    fn make_monitor(&mut self) -> SimpleMonitor<MonitorCallback> {
        let print_fn = self
            .monitor_fn
            .take()
            .unwrap_or_else(|| Box::new(|s: &str| println!("{s}")));
        SimpleMonitor::new(print_fn)
    }

    fn run_graybox(mut self, mut target: impl Target) -> Result<()> {
        let coverage = target
            .coverage_map()
            .context("target reported coverage but returned None")?;
        let coverage_len = coverage.len();
        let coverage_ptr = coverage.as_mut_ptr();
        // Intentional leak: StdMapObserver requires a &'static str for the name.
        // The fuzzer runs until process exit, so this is effectively static.
        let obs_name: &'static str =
            Box::leak(target.observer_name().to_string().into_boxed_str());

        let observer = unsafe {
            let slice = std::slice::from_raw_parts_mut(coverage_ptr, coverage_len);
            StdMapObserver::new(obs_name, slice)
        };

        // Wrap feedback with plateau detection (always active for monitoring)
        let detector = shared_detector(self.config.plateau_timeout);
        let inner_feedback = MaxMapFeedback::new(&observer);
        let mut feedback = PlateauAwareFeedback::new(inner_feedback, detector.clone());
        let mut objective = CrashFeedback::new();

        let mut state = StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryCorpus::<BytesInput>::new(),
            OnDiskCorpus::new(&self.config.crashes_dir)
                .context("failed to create crashes corpus")?,
            &mut feedback,
            &mut objective,
        )
        .context("failed to create fuzzer state")?;

        let scheduler = QueueScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut harness = |input: &BytesInput| {
            let bytes = input.target_bytes();
            target.execute(bytes.as_slice())
        };

        let mon = self.make_monitor();
        let mut mgr = SimpleEventManager::new(mon);

        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .context("failed to create executor")?;

        // Load seed corpus or generate random inputs
        if let Some(ref corpus_dir) = self.config.corpus_dir {
            let count = load_seeds_from_dir(&mut state, corpus_dir)?;
            println!("[achlys] loaded {} seed files from {}", count, corpus_dir.display());
        } else {
            let mut generator = RandBytesGenerator::new(
                NonZero::new(self.config.max_input_len).unwrap_or(NonZero::new(4096).expect("4096 is non-zero")),
            );
            state
                .generate_initial_inputs(
                    &mut fuzzer, &mut executor, &mut generator, &mut mgr,
                    self.config.initial_inputs,
                )
                .context("failed to generate initial inputs")?;
        }

        // Branch: with AI cortex or plain havoc
        if let Some(cortex) = self.cortex {
            // Full escalation pipeline
            let havoc_stage = StdMutationalStage::new(
                HavocScheduledMutator::new(havoc_mutations()),
            );

            let ai_mutator = AiMutator::new(cortex, DEFAULT_PREDICTION_BATCH);
            let ai_stage = StdMutationalStage::new(ai_mutator);
            let hybrid_havoc = StdMutationalStage::new(
                HavocScheduledMutator::new(havoc_mutations()),
            );
            let hybrid = HybridStage::new(hybrid_havoc, ai_stage, 10);

            let escalating = EscalatingStage::with_ai(havoc_stage, hybrid, detector);
            let mut stages = tuple_list!(escalating);

            println!(
                "[achlys] fuzzing started (graybox + AI, {} edges, plateau: {}s)",
                coverage_len, self.config.plateau_timeout.as_secs()
            );

            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .context("fatal error in fuzz loop")?;
        } else {
            // Plain havoc (no AI)
            let mutator = HavocScheduledMutator::new(havoc_mutations());
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            println!(
                "[achlys] fuzzing started (graybox, {} edges)",
                coverage_len
            );

            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .context("fatal error in fuzz loop")?;
        }

        Ok(())
    }

    fn run_blackbox(mut self, mut target: impl Target) -> Result<()> {
        static mut DUMMY_MAP: [u8; 16] = [0; 16];

        let observer = unsafe {
            let ptr = addr_of_mut!(DUMMY_MAP) as *mut u8;
            let slice = std::slice::from_raw_parts_mut(ptr, 16);
            StdMapObserver::new("dummy_map", slice)
        };

        let mut feedback = ConstFeedback::new(true);
        let mut objective = CrashFeedback::new();

        let mut state = StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryCorpus::<BytesInput>::new(),
            OnDiskCorpus::new(&self.config.crashes_dir)
                .context("failed to create crashes corpus")?,
            &mut feedback,
            &mut objective,
        )
        .context("failed to create fuzzer state")?;

        let scheduler = QueueScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut harness = |input: &BytesInput| {
            let bytes = input.target_bytes();
            target.execute(bytes.as_slice())
        };

        let mon = self.make_monitor();
        let mut mgr = SimpleEventManager::new(mon);

        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .context("failed to create executor")?;

        if let Some(ref corpus_dir) = self.config.corpus_dir {
            let count = load_seeds_from_dir(&mut state, corpus_dir)?;
            println!("[achlys] loaded {} seed files from {}", count, corpus_dir.display());
        } else {
            let mut generator = RandBytesGenerator::new(
                NonZero::new(self.config.max_input_len).unwrap_or(NonZero::new(4096).expect("4096 is non-zero")),
            );
            state
                .generate_initial_inputs(
                    &mut fuzzer, &mut executor, &mut generator, &mut mgr,
                    self.config.initial_inputs,
                )
                .context("failed to generate initial inputs")?;
        }

        // In blackbox mode, the plateau detector triggers on time alone
        // (on_new_coverage is never called → fires after plateau_timeout)
        if let Some(cortex) = self.cortex {
            let detector = shared_detector(self.config.plateau_timeout);

            let havoc_stage = StdMutationalStage::new(
                HavocScheduledMutator::new(havoc_mutations()),
            );

            let ai_mutator = AiMutator::new(cortex, DEFAULT_PREDICTION_BATCH);
            let ai_stage = StdMutationalStage::new(ai_mutator);
            let hybrid_havoc = StdMutationalStage::new(
                HavocScheduledMutator::new(havoc_mutations()),
            );
            let hybrid = HybridStage::new(hybrid_havoc, ai_stage, 10);

            let escalating = EscalatingStage::with_ai(havoc_stage, hybrid, detector);
            let mut stages = tuple_list!(escalating);

            println!(
                "[achlys] fuzzing started (blackbox + AI, plateau: {}s)",
                self.config.plateau_timeout.as_secs()
            );

            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .context("fatal error in fuzz loop")?;
        } else {
            let mutator = HavocScheduledMutator::new(havoc_mutations());
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            println!("[achlys] fuzzing started (blackbox mode)");

            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .context("fatal error in fuzz loop")?;
        }

        Ok(())
    }
}

/// Load seed files from a directory into any corpus-bearing state.
fn load_seeds_from_dir(state: &mut impl HasCorpus<BytesInput>, dir: &std::path::Path) -> Result<usize> {
    let mut count = 0;
    for entry in fs::read_dir(dir).context("failed to read corpus directory")? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let data = fs::read(&path)
                .with_context(|| format!("failed to read seed: {}", path.display()))?;
            state.corpus_mut().add(Testcase::new(BytesInput::new(data)))?;
            count += 1;
        }
    }
    Ok(count)
}

impl Default for FuzzerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
