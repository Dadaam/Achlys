//! Homogeneous havoc worker used by T2.
//!
//! Same substrate ingredients as H0/T1 (`run_substrate`). The LLMP loop
//! lives in `examples/fuzzers/achlys_t2.rs` because LibAFL 0.15 manager
//! generics are not object-safe. This module is the SimpleEventManager
//! reference plus corpus-scan helpers used at sync points.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::time::UNIX_EPOCH;

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

/// How a corpus directory is walked at a sync point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Skip paths already inspected. Corpus files are treated as immutable.
    Incremental,
    /// Re-read every file. A/B control against the old seconds-mode tax.
    Rescan,
}

/// Identity of an on-disk corpus file. A same path with a new stamp is re-read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    mtime_secs: Option<u64>,
    mtime_nanos: Option<u32>,
}

impl FileStamp {
    fn from_meta(meta: &fs::Metadata) -> Self {
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok());
        Self {
            len: meta.len(),
            mtime_secs: mtime.map(|d| d.as_secs()),
            mtime_nanos: mtime.map(|d| d.subsec_nanos()),
        }
    }
}

/// Paths already inspected by [`scan_new_inputs`].
#[derive(Debug, Default)]
pub struct CorpusScanCursor {
    seen_paths: HashMap<PathBuf, FileStamp>,
    seen_ids: HashSet<InputId>,
}

impl CorpusScanCursor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn path_count(&self) -> usize {
        self.seen_paths.len()
    }
}

/// One walk of a persist corpus directory.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CorpusScanStats {
    pub paths_listed: usize,
    pub paths_read: usize,
    pub bytes_read: u64,
    pub new_inputs: usize,
}

/// Newly seen corpus objects plus the walk counters for one sync.
pub type CorpusScanResult = (Vec<(InputId, Vec<u8>)>, CorpusScanStats);

/// Cap on stored sync samples used for p95. Max is tracked separately.
const SYNC_SAMPLE_CAP: usize = 512;

/// Accumulated control-plane sync cost for one worker.
#[derive(Debug, Default, Clone)]
pub struct SyncMetrics {
    pub calls: u64,
    pub ns_total: u64,
    pub ns_max: u64,
    samples_ns: Vec<u64>,
    pub paths_listed: u64,
    pub paths_read: u64,
    pub bytes_read: u64,
    pub inputs_spooled: u64,
}

impl SyncMetrics {
    pub fn record(&mut self, ns: u64, stats: &CorpusScanStats, spooled: usize) {
        self.calls = self.calls.saturating_add(1);
        self.ns_total = self.ns_total.saturating_add(ns);
        if ns > self.ns_max {
            self.ns_max = ns;
        }
        if self.samples_ns.len() < SYNC_SAMPLE_CAP {
            self.samples_ns.push(ns);
        } else {
            let idx = (self.calls as usize - 1) % SYNC_SAMPLE_CAP;
            self.samples_ns[idx] = ns;
        }
        self.paths_listed = self.paths_listed.saturating_add(stats.paths_listed as u64);
        self.paths_read = self.paths_read.saturating_add(stats.paths_read as u64);
        self.bytes_read = self.bytes_read.saturating_add(stats.bytes_read);
        self.inputs_spooled = self.inputs_spooled.saturating_add(spooled as u64);
    }

    #[must_use]
    pub fn p95_ns(&self) -> u64 {
        if self.samples_ns.is_empty() {
            return 0;
        }
        let mut xs = self.samples_ns.clone();
        xs.sort_unstable();
        let idx = xs
            .len()
            .saturating_mul(95)
            .saturating_div(100)
            .min(xs.len() - 1);
        xs[idx]
    }

    #[must_use]
    pub fn sample_len(&self) -> usize {
        self.samples_ns.len()
    }
}

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

/// New content-addressed inputs since `cursor` was last updated.
///
/// Incremental mode skips a path only when its size and mtime are unchanged.
/// Listing the directory is still O(corpus); publishing via a LibAFL hook
/// is the T3 follow-up (do not rescan to learn what this worker just wrote).
pub fn scan_new_inputs(
    dir: &Path,
    cursor: &mut CorpusScanCursor,
    mode: ScanMode,
) -> Result<CorpusScanResult> {
    let files = list_corpus_files(dir)?;
    let mut stats = CorpusScanStats {
        paths_listed: files.len(),
        ..CorpusScanStats::default()
    };
    let mut out = Vec::new();
    for path in files {
        let meta = fs::metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        let stamp = FileStamp::from_meta(&meta);
        if mode == ScanMode::Incremental
            && cursor
                .seen_paths
                .get(&path)
                .is_some_and(|prev| *prev == stamp)
        {
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        stats.paths_read = stats.paths_read.saturating_add(1);
        stats.bytes_read = stats.bytes_read.saturating_add(bytes.len() as u64);
        if bytes.is_empty() {
            cursor.seen_paths.insert(path, stamp);
            continue;
        }
        let id = InputId::from_bytes(&bytes);
        cursor.seen_paths.insert(path, stamp);
        if cursor.seen_ids.insert(id) {
            stats.new_inputs = stats.new_inputs.saturating_add(1);
            out.push((id, bytes));
        }
    }
    Ok((out, stats))
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
    let sync_every = config.sync_every.max(1);
    let mut remaining = config.max_iters.unwrap_or(u64::MAX);
    let mut since_sync = 0u64;
    while remaining > 0 {
        if config
            .max_time
            .is_some_and(|max_time| start.elapsed() >= max_time)
        {
            break;
        }
        let step_res = fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1);
        take_infra(&infra)?;
        step_res.context("fatal error in homogeneous fuzz loop")?;
        remaining = remaining.saturating_sub(1);
        since_sync = since_sync.saturating_add(1);
        if since_sync >= sync_every {
            on_sync(&persist)?;
            since_sync = 0;
        }
    }
    on_sync(&persist)?;

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
        let mut cursor = CorpusScanCursor::new();
        let (first, first_stats) =
            scan_new_inputs(&tmp, &mut cursor, ScanMode::Incremental).unwrap();
        let (second, second_stats) =
            scan_new_inputs(&tmp, &mut cursor, ScanMode::Incremental).unwrap();
        let (rescan, rescan_stats) = scan_new_inputs(&tmp, &mut cursor, ScanMode::Rescan).unwrap();
        fs::write(tmp.join("a"), b"zzzzzz").unwrap();
        let (replaced, replaced_stats) =
            scan_new_inputs(&tmp, &mut cursor, ScanMode::Incremental).unwrap();
        let mut reread = 0u64;
        for _ in 0..32 {
            let (_, s) = scan_new_inputs(&tmp, &mut cursor, ScanMode::Incremental).unwrap();
            reread = reread.saturating_add(s.bytes_read);
        }
        let _ = fs::remove_dir_all(&tmp);
        assert_eq!(first.len(), 1);
        assert_eq!(first_stats.paths_read, 2);
        assert!(second.is_empty());
        assert_eq!(second_stats.paths_read, 0);
        assert_eq!(second_stats.bytes_read, 0);
        assert!(rescan.is_empty());
        assert_eq!(rescan_stats.paths_read, 2);
        assert_eq!(rescan_stats.bytes_read, 10);
        assert_eq!(replaced.len(), 1);
        assert_eq!(replaced_stats.paths_read, 1);
        assert_eq!(reread, 0, "immutable files must not be re-read");
    }

    #[test]
    fn sync_metrics_p95_is_ordered() {
        let mut m = SyncMetrics::default();
        for ns in [10, 20, 30, 40, 100] {
            m.record(
                ns,
                &CorpusScanStats {
                    paths_listed: 1,
                    paths_read: 1,
                    bytes_read: 4,
                    new_inputs: 0,
                },
                0,
            );
        }
        assert_eq!(m.calls, 5);
        assert_eq!(m.ns_max, 100);
        assert_eq!(m.p95_ns(), 100);
        assert_eq!(m.bytes_read, 20);
        for ns in 0..600 {
            m.record(ns, &CorpusScanStats::default(), 0);
        }
        assert_eq!(m.sample_len(), 512);
        assert_eq!(m.calls, 605);
    }
}
