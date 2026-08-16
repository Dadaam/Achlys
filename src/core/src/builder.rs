use std::fs;
use std::num::NonZero;
use std::path::PathBuf;
use std::ptr::addr_of_mut;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, InMemoryOnDiskCorpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    executors::{ExitKind, inprocess::InProcessExecutor},
    feedback_or_fast,
    feedbacks::{ConstFeedback, CrashFeedback, MaxMapFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::{NopMonitor, SimpleMonitor},
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::{HitcountsMapObserver, StdMapObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasExecutions, HasMaxSize, HasSolutions, StdState},
};
use libafl_bolts::{AsSlice, current_nanos, rands::StdRand, tuples::tuple_list};

use achlys_bridge::{InfraError, Target};

use crate::config::SubstrateReport;

/// Callback type for custom monitor output (TUI, logging, etc.).
type MonitorCallback = Box<dyn FnMut(&str)>;

use crate::ai_mutator::{AiMutator, DEFAULT_PREDICTION_BATCH};
use crate::ai_stage::HybridStage;
use crate::config::FuzzerConfig;
use crate::cortex_interface::CortexInterface;
use crate::escalation::{EscalatingStage, SharedLogSink};
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
    log_sink: Option<SharedLogSink>,
}

impl FuzzerBuilder {
    pub fn new() -> Self {
        Self {
            config: FuzzerConfig::default(),
            cortex: None,
            monitor_fn: None,
            log_sink: None,
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

    /// Pin the LibAFL RNG seed (required for H0 paired trials).
    pub fn rng_seed(mut self, seed: u64) -> Self {
        self.config.rng_seed = seed;
        self
    }

    /// Bound the substrate campaign to `fuzz_loop_for(iters)`.
    pub fn max_iters(mut self, iters: u64) -> Self {
        self.config.max_iters = Some(iters);
        self
    }

    /// Bound the substrate campaign by wall clock (`fuzz_loop_for(1)` until elapsed).
    pub fn max_time(mut self, duration: Duration) -> Self {
        self.config.max_time = Some(duration);
        self
    }

    /// Per-execution timeout for `InProcessExecutor::with_timeout`.
    pub fn exec_timeout(mut self, timeout: Duration) -> Self {
        self.config.exec_timeout = timeout;
        self
    }

    /// Persist the working corpus (`InMemoryOnDiskCorpus`). Required for H0 binaries.
    pub fn persist_corpus_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.persist_corpus_dir = Some(path.into());
        self
    }

    /// Set a shared log sink for escalation events (visible in TUI).
    pub fn log_sink(mut self, sink: SharedLogSink) -> Self {
        self.log_sink = Some(sink);
        self
    }

    /// Set a custom monitor callback (replaces the default println output).
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

    /// LibAFL-only graybox worker (no cortex, plateau, or escalation).
    pub fn run_substrate(self, mut target: impl Target) -> Result<SubstrateReport> {
        if !target.has_coverage() {
            anyhow::bail!("run_substrate requires a coverage-capable target");
        }
        if self.config.max_iters.is_none() && self.config.max_time.is_none() {
            anyhow::bail!("run_substrate requires max_iters or max_time");
        }

        if let Some(dir) = self.config.persist_corpus_dir.clone() {
            let corpus = InMemoryOnDiskCorpus::<BytesInput>::new(&dir).with_context(|| {
                format!("failed to create persistent corpus at {}", dir.display())
            })?;
            self.run_substrate_with_corpus(target, corpus)
        } else {
            self.run_substrate_with_corpus(target, InMemoryCorpus::<BytesInput>::new())
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
        let obs_name: &'static str = Box::leak(target.observer_name().to_string().into_boxed_str());

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

        let infra = Arc::new(Mutex::new(None::<InfraError>));
        let infra_h = Arc::clone(&infra);
        let mut harness = move |input: &BytesInput| {
            let bytes = input.target_bytes();
            match target.execute(bytes.as_slice()) {
                Ok(kind) => kind,
                Err(err) => {
                    *infra_h.lock().expect("infra mutex poisoned") = Some(err);
                    // Not a target result. Avoid Crash so CrashFeedback
                    // does not persist this input as a finding.
                    ExitKind::Ok
                }
            }
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
        take_infra_error(&infra)?;

        // Load seed corpus or generate random inputs
        if let Some(ref corpus_dir) = self.config.corpus_dir {
            load_seeds_from_dir(&mut state, corpus_dir)?;
            // Seed loading info visible through TUI logs or --no-tui output
        } else {
            let mut generator = RandBytesGenerator::new(
                NonZero::new(self.config.max_input_len)
                    .unwrap_or(NonZero::new(4096).expect("4096 is non-zero")),
            );
            let gen_res = state.generate_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut generator,
                &mut mgr,
                self.config.initial_inputs,
            );
            take_infra_error(&infra)?;
            gen_res.context("failed to generate initial inputs")?;
        }

        // Branch: with AI cortex or plain havoc
        if let Some(cortex) = self.cortex {
            // Full escalation pipeline
            let havoc_stage =
                StdMutationalStage::new(HavocScheduledMutator::new(havoc_mutations()));

            let ai_mutator = AiMutator::new(cortex, DEFAULT_PREDICTION_BATCH);
            let ai_stage = StdMutationalStage::new(ai_mutator);
            let hybrid_havoc =
                StdMutationalStage::new(HavocScheduledMutator::new(havoc_mutations()));
            let hybrid = HybridStage::new(hybrid_havoc, ai_stage, 10);

            let mut escalating = EscalatingStage::with_ai(havoc_stage, hybrid, detector);
            if let Some(ref sink) = self.log_sink {
                escalating = escalating.with_log_sink(sink.clone());
            }
            let mut stages = tuple_list!(escalating);

            fuzz_loop_abort_on_infra(
                || {
                    fuzzer
                        .fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1)
                        .map(|_| ())
                },
                &infra,
            )?;
        } else {
            // Plain havoc (no AI)
            let mutator = HavocScheduledMutator::new(havoc_mutations());
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            fuzz_loop_abort_on_infra(
                || {
                    fuzzer
                        .fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1)
                        .map(|_| ())
                },
                &infra,
            )?;
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

        // Blackbox has no novelty signal. Admitting every exec is unbounded
        // and forbidden (Master Plan 24.2). Seeds still load via
        // load_seeds_from_dir; crashes still go through CrashFeedback.
        let mut feedback = ConstFeedback::new(false);
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

        let infra = Arc::new(Mutex::new(None::<InfraError>));
        let infra_h = Arc::clone(&infra);
        let mut harness = move |input: &BytesInput| {
            let bytes = input.target_bytes();
            match target.execute(bytes.as_slice()) {
                Ok(kind) => kind,
                Err(err) => {
                    *infra_h.lock().expect("infra mutex poisoned") = Some(err);
                    // Not a target result. Avoid Crash so CrashFeedback
                    // does not persist this input as a finding.
                    ExitKind::Ok
                }
            }
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
        take_infra_error(&infra)?;

        if let Some(ref corpus_dir) = self.config.corpus_dir {
            load_seeds_from_dir(&mut state, corpus_dir)?;
            // Seed loading info visible through TUI logs or --no-tui output
        } else {
            let mut generator = RandBytesGenerator::new(
                NonZero::new(self.config.max_input_len)
                    .unwrap_or(NonZero::new(4096).expect("4096 is non-zero")),
            );
            // ConstFeedback(false) will not admit generated inputs; force-seed
            // so the campaign has a bounded starting corpus.
            let gen_res = state.generate_initial_inputs_forced(
                &mut fuzzer,
                &mut executor,
                &mut generator,
                &mut mgr,
                self.config.initial_inputs,
            );
            take_infra_error(&infra)?;
            gen_res.context("failed to generate initial inputs")?;
        }

        // In blackbox mode, the plateau detector triggers on time alone
        // (on_new_coverage is never called → fires after plateau_timeout)
        if let Some(cortex) = self.cortex {
            let detector = shared_detector(self.config.plateau_timeout);

            let havoc_stage =
                StdMutationalStage::new(HavocScheduledMutator::new(havoc_mutations()));

            let ai_mutator = AiMutator::new(cortex, DEFAULT_PREDICTION_BATCH);
            let ai_stage = StdMutationalStage::new(ai_mutator);
            let hybrid_havoc =
                StdMutationalStage::new(HavocScheduledMutator::new(havoc_mutations()));
            let hybrid = HybridStage::new(hybrid_havoc, ai_stage, 10);

            let mut escalating = EscalatingStage::with_ai(havoc_stage, hybrid, detector);
            if let Some(ref sink) = self.log_sink {
                escalating = escalating.with_log_sink(sink.clone());
            }
            let mut stages = tuple_list!(escalating);

            fuzz_loop_abort_on_infra(
                || {
                    fuzzer
                        .fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1)
                        .map(|_| ())
                },
                &infra,
            )?;
        } else {
            let mutator = HavocScheduledMutator::new(havoc_mutations());
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            fuzz_loop_abort_on_infra(
                || {
                    fuzzer
                        .fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1)
                        .map(|_| ())
                },
                &infra,
            )?;
        }

        Ok(())
    }

    fn run_substrate_with_corpus<T, C>(
        self,
        mut target: T,
        corpus: C,
    ) -> Result<SubstrateReport>
    where
        T: Target,
        C: Corpus<BytesInput> + serde::Serialize + serde::de::DeserializeOwned,
    {
        let (coverage_ptr, coverage_len) = {
            let coverage = target
                .coverage_map()
                .context("target reported coverage but returned None")?;
            (coverage.as_mut_ptr(), coverage.len())
        };
        // StdMapObserver wants a 'static name; the process owns this campaign.
        let obs_name: &'static str = Box::leak(target.observer_name().to_string().into_boxed_str());

        // SAFETY: same-process SanCov / test map, valid for the campaign.
        let observer = HitcountsMapObserver::new(unsafe {
            StdMapObserver::from_mut_ptr(obs_name, coverage_ptr, coverage_len)
        });

        let mut feedback = MaxMapFeedback::new(&observer);
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        let mut state = StdState::new(
            StdRand::with_seed(self.config.rng_seed),
            corpus,
            OnDiskCorpus::new(&self.config.crashes_dir)
                .context("failed to create crashes corpus")?,
            &mut feedback,
            &mut objective,
        )
        .context("failed to create fuzzer state")?;
        state.set_max_size(self.config.max_input_len.max(1));

        let scheduler = QueueScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let infra = Arc::new(Mutex::new(None::<InfraError>));
        let infra_h = Arc::clone(&infra);
        let mut harness = move |input: &BytesInput| {
            let bytes = input.target_bytes();
            match target.execute(bytes.as_slice()) {
                Ok(kind) => kind,
                Err(err) => {
                    *infra_h.lock().expect("infra mutex poisoned") = Some(err);
                    ExitKind::Ok
                }
            }
        };

        // Measurement path: no per-event formatting. Verbose monitors
        // belong in a separate observability experiment.
        let mon = NopMonitor::new();
        let mut mgr = SimpleEventManager::new(mon);

        let mut executor = InProcessExecutor::with_timeout(
            &mut harness,
            tuple_list!(observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            self.config.exec_timeout,
        )
        .context("failed to create in-process executor")?;
        take_infra_error(&infra)?;

        if let Some(ref corpus_dir) = self.config.corpus_dir {
            let load_res = state.load_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut mgr,
                std::slice::from_ref(corpus_dir),
            );
            take_infra_error(&infra)?;
            load_res.with_context(|| {
                format!(
                    "failed to load initial inputs from {}",
                    corpus_dir.display()
                )
            })?;
        } else {
            let mut generator = RandBytesGenerator::new(
                NonZero::new(self.config.max_input_len)
                    .unwrap_or(NonZero::new(4096).expect("4096 is non-zero")),
            );
            let gen_res = state.generate_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut generator,
                &mut mgr,
                self.config.initial_inputs,
            );
            take_infra_error(&infra)?;
            gen_res.context("failed to generate initial inputs")?;
        }

        if state.corpus().count() == 0 {
            anyhow::bail!(
                "no initial inputs were admitted (empty seeds or no novelty). \
                 Provide a non-empty corpus directory or a target that reports coverage"
            );
        }

        let mutator = HavocScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        let start = Instant::now();
        match (self.config.max_iters, self.config.max_time) {
            (Some(iters), None) => {
                let step_res =
                    fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, iters);
                take_infra_error(&infra)?;
                step_res.context("fatal error in substrate fuzz loop")?;
            }
            (iters, Some(max_time)) => {
                let mut remaining = iters.unwrap_or(u64::MAX);
                while remaining > 0 && start.elapsed() < max_time {
                    let step_res =
                        fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1);
                    take_infra_error(&infra)?;
                    step_res.context("fatal error in substrate fuzz loop")?;
                    remaining -= 1;
                }
            }
            (None, None) => unreachable!("run_substrate checks bounds"),
        }

        let elapsed = start.elapsed();
        let report = SubstrateReport {
            executions: *state.executions(),
            corpus_count: state.corpus().count(),
            objectives: state.solutions().count(),
            elapsed,
        };
        print_h0_result(&report);
        Ok(report)
    }
}

fn print_h0_result(report: &SubstrateReport) {
    let elapsed_ms = report.elapsed.as_millis();
    let exec_per_sec = if report.elapsed.as_secs_f64() > 0.0 {
        report.executions as f64 / report.elapsed.as_secs_f64()
    } else {
        0.0
    };
    println!(
        "H0_RESULT execs={} elapsed_ms={} corpus={} objectives={} exec_per_sec={:.2}",
        report.executions, elapsed_ms, report.corpus_count, report.objectives, exec_per_sec
    );
}

fn take_infra_error(infra: &Mutex<Option<InfraError>>) -> Result<()> {
    match infra.lock().expect("infra mutex poisoned").take() {
        Some(err) => Err(anyhow!(err)),
        None => Ok(()),
    }
}

fn fuzz_loop_abort_on_infra<F>(mut step: F, infra: &Mutex<Option<InfraError>>) -> Result<()>
where
    F: FnMut() -> Result<(), libafl::Error>,
{
    loop {
        let step_res = step();
        take_infra_error(infra)?;
        step_res.context("fatal error in fuzz loop")?;
    }
}

/// Load seed files from a directory into any corpus-bearing state.
fn load_seeds_from_dir(
    state: &mut impl HasCorpus<BytesInput>,
    dir: &std::path::Path,
) -> Result<usize> {
    let mut count = 0;
    for entry in fs::read_dir(dir).context("failed to read corpus directory")? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let data = fs::read(&path)
                .with_context(|| format!("failed to read seed: {}", path.display()))?;
            state
                .corpus_mut()
                .add(Testcase::new(BytesInput::new(data)))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use achlys_bridge::{CoverageMap, InProcessTarget};

    #[test]
    fn run_substrate_tiny_map_reports_executions() {
        let mut map = [0u8; 32];
        let ptr = map.as_mut_ptr();
        let target = unsafe {
            InProcessTarget::with_coverage(
                move |input| {
                    if let Some(&b) = input.first() {
                        *ptr.add((b as usize) % 32) = 1;
                    }
                    ExitKind::Ok
                },
                CoverageMap::new(ptr, 32),
                "edges",
            )
        };

        let tmp = std::env::temp_dir().join(format!(
            "achlys_h0_unit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));

        let report = FuzzerBuilder::new()
            .rng_seed(1)
            .max_iters(2)
            .max_input_len(16)
            .initial_inputs(2)
            .crashes_dir(tmp.join("crashes"))
            .monitor(|_| {})
            .run_substrate(target)
            .expect("run_substrate");

        let _ = fs::remove_dir_all(&tmp);

        assert!(report.executions > 0, "expected at least one execution");
        assert!(report.corpus_count > 0, "novelty policy should keep a seed");
        let _ = report.objectives;
        let _ = report.elapsed;
    }
}
