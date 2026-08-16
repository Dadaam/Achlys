//! Homogeneous havoc worker used by T2.
//!
//! Same substrate ingredients as H0/T1 (`run_substrate`). The LLMP loop
//! lives in `examples/fuzzers/achlys_t2.rs` because LibAFL 0.15 manager
//! generics are not object-safe. This module is the SimpleEventManager
//! reference plus corpus-scan helpers used at sync points.

use std::collections::HashSet;
use std::fs;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use achlys_bridge::{InfraError, Target};
use achlys_protocol::InputId;
use anyhow::{Context, Result, anyhow};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, inprocess::InProcessExecutor},
    feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::NopMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::{HitcountsMapObserver, StdMapObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasExecutions, HasMaxSize, HasSolutions, StdState},
};
use libafl_bolts::{AsSlice, rands::StdRand, tuples::tuple_list};

use crate::config::{FuzzerConfig, SubstrateReport};

/// Regular files in a LibAFL on-disk corpus, skipping sidecars.
pub fn list_corpus_files(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", dir.display()))?;
        let path = entry.path();
        if path.is_file() && !is_libafl_sidecar(&path) {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// New content-addressed inputs since `seen` was last updated.
pub fn scan_new_inputs(dir: &Path, seen: &mut HashSet<InputId>) -> Result<Vec<(InputId, Vec<u8>)>> {
    let mut out = Vec::new();
    for path in list_corpus_files(dir)? {
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        if bytes.is_empty() {
            continue;
        }
        let id = InputId::from_bytes(&bytes);
        if seen.insert(id) {
            out.push((id, bytes));
        }
    }
    Ok(out)
}

fn is_libafl_sidecar(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.starts_with('.') || name.ends_with(".metadata")
}

/// Bounded homogeneous worker with `SimpleEventManager`.
pub fn run_homogeneous_simple<T, F>(
    mut target: T,
    config: &FuzzerConfig,
    extra_seed_dirs: &[PathBuf],
    mut on_sync: F,
) -> Result<SubstrateReport>
where
    T: Target,
    F: FnMut(&Path) -> Result<()>,
{
    if !target.has_coverage() {
        anyhow::bail!("homogeneous worker requires a coverage-capable target");
    }
    if config.max_iters.is_none() && config.max_time.is_none() {
        anyhow::bail!("homogeneous worker requires max_iters or max_time");
    }
    let persist = config
        .persist_corpus_dir
        .clone()
        .ok_or_else(|| anyhow!("homogeneous worker requires persist_corpus_dir"))?;
    fs::create_dir_all(&persist).with_context(|| format!("create {}", persist.display()))?;
    fs::create_dir_all(&config.crashes_dir)
        .with_context(|| format!("create {}", config.crashes_dir.display()))?;

    let (coverage_ptr, coverage_len) = {
        let coverage = target
            .coverage_map()
            .context("target reported coverage but returned None")?;
        (coverage.as_mut_ptr(), coverage.len())
    };
    let obs_name: &'static str = Box::leak(target.observer_name().to_string().into_boxed_str());
    let observer = HitcountsMapObserver::new(unsafe {
        StdMapObserver::from_mut_ptr(obs_name, coverage_ptr, coverage_len)
    });

    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    let corpus = InMemoryOnDiskCorpus::<BytesInput>::new(&persist).with_context(|| {
        format!(
            "failed to create persistent corpus at {}",
            persist.display()
        )
    })?;
    let mut state = StdState::new(
        StdRand::with_seed(config.rng_seed),
        corpus,
        OnDiskCorpus::new(&config.crashes_dir).context("failed to create crashes corpus")?,
        &mut feedback,
        &mut objective,
    )
    .context("failed to create fuzzer state")?;
    state.set_max_size(config.max_input_len.max(1));

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

    let mon = NopMonitor::new();
    let mut mgr = SimpleEventManager::new(mon);

    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        config.exec_timeout,
    )
    .context("failed to create in-process executor")?;
    take_infra(&infra)?;

    let mut seed_dirs = Vec::new();
    if let Some(dir) = &config.corpus_dir {
        seed_dirs.push(dir.clone());
    }
    seed_dirs.extend(extra_seed_dirs.iter().cloned());
    if seed_dirs.is_empty() {
        let mut generator = RandBytesGenerator::new(
            NonZero::new(config.max_input_len)
                .unwrap_or(NonZero::new(4096).expect("4096 is non-zero")),
        );
        let gen_res = state.generate_initial_inputs(
            &mut fuzzer,
            &mut executor,
            &mut generator,
            &mut mgr,
            config.initial_inputs,
        );
        take_infra(&infra)?;
        gen_res.context("failed to generate initial inputs")?;
    } else {
        let load_res = state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &seed_dirs);
        take_infra(&infra)?;
        load_res.context("failed to load initial inputs")?;
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
    match (config.max_iters, config.max_time) {
        (Some(iters), None) => {
            let step_res =
                fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, iters);
            take_infra(&infra)?;
            step_res.context("fatal error in homogeneous fuzz loop")?;
            on_sync(&persist)?;
        }
        (iters, Some(max_time)) => {
            let mut remaining = iters.unwrap_or(u64::MAX);
            while remaining > 0 && start.elapsed() < max_time {
                let step_res =
                    fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1);
                take_infra(&infra)?;
                step_res.context("fatal error in homogeneous fuzz loop")?;
                on_sync(&persist)?;
                remaining -= 1;
            }
        }
        (None, None) => unreachable!("bounds checked above"),
    }

    Ok(SubstrateReport {
        executions: *state.executions(),
        corpus_count: state.corpus().count(),
        objectives: state.solutions().count(),
        elapsed: start.elapsed(),
    })
}

fn take_infra(infra: &Mutex<Option<InfraError>>) -> Result<()> {
    match infra.lock().expect("infra mutex poisoned").take() {
        Some(err) => Err(anyhow!(err)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use achlys_bridge::{CoverageMap, InProcessTarget};

    #[test]
    fn homogeneous_simple_tiny_map_runs() {
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
            "achlys_t2_unit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let persist = tmp.join("corpus");
        let mut syncs = 0usize;
        let config = FuzzerConfig {
            persist_corpus_dir: Some(persist.clone()),
            crashes_dir: tmp.join("crashes"),
            rng_seed: 1,
            max_iters: Some(2),
            max_input_len: 16,
            initial_inputs: 2,
            exec_timeout: std::time::Duration::from_millis(1000),
            ..FuzzerConfig::default()
        };
        let report = run_homogeneous_simple(target, &config, &[], |_| {
            syncs += 1;
            Ok(())
        })
        .expect("run_homogeneous_simple");
        let _ = fs::remove_dir_all(&tmp);
        assert!(report.executions > 0);
        assert!(report.corpus_count > 0);
        assert!(syncs >= 1);
    }

    #[test]
    fn scan_new_inputs_skips_sidecars_and_dups() {
        let tmp = std::env::temp_dir().join(format!(
            "achlys_t2_scan_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("a"), b"alpha").unwrap();
        fs::write(tmp.join("b"), b"alpha").unwrap();
        fs::write(tmp.join(".id.metadata"), b"nope").unwrap();
        let mut seen = HashSet::new();
        let first = scan_new_inputs(&tmp, &mut seen).unwrap();
        let second = scan_new_inputs(&tmp, &mut seen).unwrap();
        let _ = fs::remove_dir_all(&tmp);
        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
    }
}
