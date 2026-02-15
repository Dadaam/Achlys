use std::fs;
use std::num::NonZero;
use std::path::PathBuf;
use std::ptr::addr_of_mut;
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

use crate::config::FuzzerConfig;

/// Builder for configuring and running an Achlys fuzzer instance.
///
/// Reduces the ~100 lines of LibAFL boilerplate to a fluent API.
/// All LibAFL generics stay internal — the public API only exposes
/// `FuzzerConfig` and `Target`.
pub struct FuzzerBuilder {
    config: FuzzerConfig,
}

impl FuzzerBuilder {
    pub fn new() -> Self {
        Self {
            config: FuzzerConfig::default(),
        }
    }

    pub fn config(mut self, config: FuzzerConfig) -> Self {
        self.config = config;
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

    /// Build and run the fuzzer with the given target.
    ///
    /// This method blocks until the fuzzer exits (Ctrl+C, fatal error).
    /// All LibAFL setup happens internally.
    pub fn run(self, mut target: impl Target) -> Result<()> {
        if target.has_coverage() {
            self.run_graybox(target)
        } else {
            self.run_blackbox(target)
        }
    }

    fn run_graybox(self, mut target: impl Target) -> Result<()> {
        let coverage = target
            .coverage_map()
            .context("target reported coverage but returned None")?;
        let coverage_len = coverage.len();
        let coverage_ptr = coverage.as_mut_ptr();
        // Leak the name so it has 'static lifetime (StdMapObserver requires it)
        let obs_name: &'static str = Box::leak(target.observer_name().to_string().into_boxed_str());

        // SAFETY: the coverage map pointer comes from the target and remains valid
        // for the duration of the fuzz loop. Single-threaded access.
        let observer = unsafe {
            let slice = std::slice::from_raw_parts_mut(coverage_ptr, coverage_len);
            StdMapObserver::new(obs_name, slice)
        };

        let mut feedback = MaxMapFeedback::new(&observer);
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

        let mon = SimpleMonitor::new(|s| println!("{s}"));
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
            let mut count = 0;
            for entry in fs::read_dir(corpus_dir).context("failed to read corpus directory")? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let data = fs::read(&path)
                        .with_context(|| format!("failed to read seed: {}", path.display()))?;
                    let input = BytesInput::new(data);
                    state.corpus_mut().add(Testcase::new(input))?;
                    count += 1;
                }
            }
            println!("[achlys] loaded {} seed files from {}", count, corpus_dir.display());
        } else {
            let mut generator = RandBytesGenerator::new(
                NonZero::new(self.config.max_input_len).unwrap_or(NonZero::new(4096).unwrap()),
            );
            state
                .generate_initial_inputs(
                    &mut fuzzer,
                    &mut executor,
                    &mut generator,
                    &mut mgr,
                    self.config.initial_inputs,
                )
                .context("failed to generate initial inputs")?;
        }

        let mutator = HavocScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        println!(
            "[achlys] fuzzing started (graybox mode, {} coverage edges)",
            coverage_len
        );

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .context("fatal error in fuzz loop")?;

        Ok(())
    }

    fn run_blackbox(self, mut target: impl Target) -> Result<()> {
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

        let mon = SimpleMonitor::new(|s| println!("{s}"));
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
            let mut count = 0;
            for entry in fs::read_dir(corpus_dir).context("failed to read corpus directory")? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let data = fs::read(&path)
                        .with_context(|| format!("failed to read seed: {}", path.display()))?;
                    let input = BytesInput::new(data);
                    state.corpus_mut().add(Testcase::new(input))?;
                    count += 1;
                }
            }
            println!("[achlys] loaded {} seed files from {}", count, corpus_dir.display());
        } else {
            let mut generator = RandBytesGenerator::new(
                NonZero::new(self.config.max_input_len).unwrap_or(NonZero::new(4096).unwrap()),
            );
            state
                .generate_initial_inputs(
                    &mut fuzzer,
                    &mut executor,
                    &mut generator,
                    &mut mgr,
                    self.config.initial_inputs,
                )
                .context("failed to generate initial inputs")?;
        }

        let mutator = HavocScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        println!("[achlys] fuzzing started (blackbox mode)");

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .context("fatal error in fuzz loop")?;

        Ok(())
    }
}

impl Default for FuzzerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
