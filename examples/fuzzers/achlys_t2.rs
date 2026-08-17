//! Tranche 2: homogeneous multi-worker havoc over LibAFL LLMP.
//!
//! Control plane (admit + DumpOracle + CampaignStore) is a separate process.
//! Workers do not call the oracle on the hot path.

use std::env;
use std::fs;
use std::num::NonZero;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::ptr::addr_of_mut;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use achlys_bridge::{
    CoverageMap, DumpOracle, InProcessTarget, Target, WorkerTarget, compile_canonical,
};
use achlys_core::{
    CampaignSession, CandidateSpool, CorpusAuthority, CorpusScanCursor, FuzzerConfig, ScanMode,
    SyncMetrics, WorkerExit, WorkerRegistration, WorkerResume, scan_new_inputs,
};
use achlys_protocol::{
    BuildIdentity, BuildKind, CampaignEvent, CampaignId, CampaignRecord, InputId, InputMetadata,
    MetricsSnapshot, StrategyId, TargetManifest, WorkerId, reconstruct_events,
};
use anyhow::{Context, Result, anyhow};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{EventConfig, Launcher, LlmpRestartingEventManager, SendExiting},
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
use libafl_bolts::{
    AsSlice,
    core_affinity::{Cores, get_core_ids},
    rands::StdRand,
    shmem::{ShMemProvider, StdShMem, StdShMemProvider},
    tuples::tuple_list,
};

const MAX_EDGES: usize = 65536;
const MICRO_MAP_LEN: usize = 256;
const DEFAULT_OUT: &str = "./campaigns/t2";
const DEFAULT_MANIFEST: &str = "benchmarks/manifests/cjson-parse.toml";
const DEFAULT_SECONDS: u64 = 10;
const EXTRA_IDENTITY: &[&str] = &[
    "rust-toolchain.toml",
    "Cargo.lock",
    "build.rs",
    "examples/fuzzers/achlys_t2.rs",
];

#[link(name = "cjson_graybox")]
unsafe extern "C" {
    fn achlys_cjson_test_one_input(data: *const u8, size: usize) -> c_int;
    static mut EDGES_MAP: [u8; MAX_EDGES];
    static mut EDGES_COUNT: std::ffi::c_ulong;
}

#[link(name = "micro_crash_if_magic")]
unsafe extern "C" {
    fn achlys_micro_crash_if_magic(data: *const u8, len: usize) -> c_int;
}

#[link(name = "micro_nonzero_exit")]
unsafe extern "C" {
    fn achlys_micro_nonzero_exit(data: *const u8, len: usize) -> c_int;
}

#[link(name = "micro_coverage_stable")]
unsafe extern "C" {
    fn achlys_micro_coverage_stable(data: *const u8, len: usize) -> c_int;
}

static mut MICRO_MAP: [u8; MICRO_MAP_LEN] = [0; MICRO_MAP_LEN];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Launcher,
    Admit,
}

struct Args {
    seed: u64,
    iters: Option<u64>,
    seconds: Option<u64>,
    corpus: Option<PathBuf>,
    out: PathBuf,
    manifest: PathBuf,
    label: String,
    workers: usize,
    cores: Option<String>,
    broker_port: u16,
    join: bool,
    role: Role,
    canonical_bin: Option<PathBuf>,
    canonical_dir: Option<PathBuf>,
    pending_bound: usize,
    sync_every: u64,
    rescan: bool,
}

fn parse_args() -> Args {
    let mut seed = 1u64;
    let mut iters = None;
    let mut seconds = None;
    let mut corpus = None;
    let mut out = PathBuf::from(DEFAULT_OUT);
    let mut manifest = PathBuf::from(DEFAULT_MANIFEST);
    let mut label = "t2".to_string();
    let mut workers = 2usize;
    let mut cores = None;
    let mut broker_port = 1337u16;
    let mut join = false;
    let mut role = Role::Launcher;
    let mut canonical_bin = None;
    let mut canonical_dir = None;
    let mut pending_bound = achlys_core::DEFAULT_PENDING_BOUND;
    let mut sync_every = None;
    let mut rescan = env::var("ACHLYS_T2_RESCAN").ok().is_some_and(|v| v != "0");

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut need = |name: &str| {
            args.next()
                .unwrap_or_else(|| die(&format!("{name} requires a value")))
        };
        match arg.as_str() {
            "--seed" => {
                seed = need("--seed")
                    .parse()
                    .unwrap_or_else(|_| die("--seed must be u64"));
            }
            "--iters" => {
                iters = Some(
                    need("--iters")
                        .parse()
                        .unwrap_or_else(|_| die("--iters must be u64")),
                );
            }
            "--seconds" => {
                seconds = Some(
                    need("--seconds")
                        .parse()
                        .unwrap_or_else(|_| die("--seconds must be u64")),
                );
            }
            "--corpus" => corpus = Some(PathBuf::from(need("--corpus"))),
            "--out" => out = PathBuf::from(need("--out")),
            "--manifest" => manifest = PathBuf::from(need("--manifest")),
            "--label" => label = need("--label"),
            "--workers" => {
                workers = need("--workers")
                    .parse()
                    .unwrap_or_else(|_| die("--workers must be usize"));
            }
            "--cores" => cores = Some(need("--cores")),
            "--broker-port" => {
                broker_port = need("--broker-port")
                    .parse()
                    .unwrap_or_else(|_| die("--broker-port must be u16"));
            }
            "--join" => join = true,
            "--canonical-bin" => canonical_bin = Some(PathBuf::from(need("--canonical-bin"))),
            "--canonical-dir" => canonical_dir = Some(PathBuf::from(need("--canonical-dir"))),
            "--pending-bound" => {
                pending_bound = need("--pending-bound")
                    .parse()
                    .unwrap_or_else(|_| die("--pending-bound must be usize"));
                if pending_bound == 0 {
                    die("--pending-bound must be >= 1");
                }
            }
            "--sync-every" => {
                sync_every = Some(
                    need("--sync-every")
                        .parse()
                        .unwrap_or_else(|_| die("--sync-every must be u64")),
                );
            }
            "--rescan" => rescan = true,
            "--role" => {
                role = match need("--role").as_str() {
                    "launcher" => Role::Launcher,
                    "admit" => Role::Admit,
                    other => die(&format!("unknown --role {other}")),
                };
            }
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            other => die(&format!("unknown argument: {other}")),
        }
    }

    if workers == 0 {
        die("--workers must be >= 1");
    }
    if iters.is_some() && seconds.is_some() {
        die("--iters and --seconds are mutually exclusive");
    }
    if role == Role::Launcher && iters.is_none() && seconds.is_none() {
        seconds = Some(DEFAULT_SECONDS);
    }
    if canonical_bin.is_some() && canonical_dir.is_some() {
        die("--canonical-bin and --canonical-dir are mutually exclusive");
    }
    let sync_every = sync_every
        .or_else(|| {
            env::var("ACHLYS_T2_SYNC_EVERY")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(achlys_core::DEFAULT_SYNC_EVERY);
    if sync_every == 0 {
        die("--sync-every must be >= 1");
    }

    Args {
        seed,
        iters,
        seconds,
        corpus,
        out,
        manifest,
        label,
        workers,
        cores,
        broker_port,
        join,
        role,
        canonical_bin,
        canonical_dir,
        pending_bound,
        sync_every,
        rescan,
    }
}

fn print_help() {
    eprintln!(
        "achlys_t2 --manifest PATH --out DIR --workers N [--seed N] \
         [--iters N | --seconds N] [--cores LIST] [--broker-port P] \
         [--corpus DIR] [--label NAME] [--canonical-dir DIR] \
         [--canonical-bin PATH] [--pending-bound N] [--sync-every N] [--rescan]\n\
         [--join] [--role launcher|admit]\n\
         --canonical-dir must contain canonical + identity.json compiled for this target.\n\
         --join is offline continuation of a stopped campaign, not a live late join.\n\
         --sync-every is the fuzz_loop_for(1) batch between spool syncs (default 256).\n\
         --rescan re-reads every corpus file at each sync (A/B against incremental scan)."
    );
}

fn die(msg: &str) -> ! {
    eprintln!("achlys_t2: {msg}");
    process::exit(2);
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn require_fresh(path: &Path) {
    if !path.exists() {
        return;
    }
    if path.is_file() {
        die(&format!("{} exists and is a file", path.display()));
    }
    let occupied = fs::read_dir(path)
        .ok()
        .map(|it| it.flatten().any(|e| e.file_name() != ".DS_Store"))
        .unwrap_or(true);
    if occupied {
        die(&format!(
            "--out {} is not empty; reuse is forbidden (pick a new directory or pass --join)",
            path.display()
        ));
    }
}

fn worker_target(kind: WorkerTarget) -> InProcessTarget {
    match kind {
        WorkerTarget::CjsonParse => {
            let (ptr, len) = unsafe {
                let count = if EDGES_COUNT > 0 {
                    EDGES_COUNT as usize
                } else {
                    MAX_EDGES
                };
                (addr_of_mut!(EDGES_MAP) as *mut u8, count)
            };
            unsafe {
                InProcessTarget::with_coverage(
                    move |buf| {
                        let _ = achlys_cjson_test_one_input(buf.as_ptr(), buf.len());
                        ExitKind::Ok
                    },
                    CoverageMap::new(ptr, len),
                    "edges",
                )
            }
        }
        other => {
            // Worker-local map is synthetic (first byte + nonzero return).
            // Published coverage comes only from the compiled SanCov dump.
            let ptr = addr_of_mut!(MICRO_MAP) as *mut u8;
            unsafe {
                InProcessTarget::with_coverage(
                    move |buf| {
                        let map = std::slice::from_raw_parts_mut(ptr, MICRO_MAP_LEN);
                        map.fill(0);
                        let rc = match other {
                            WorkerTarget::CjsonParse => unreachable!(),
                            WorkerTarget::MicroCrashIfMagic => {
                                achlys_micro_crash_if_magic(buf.as_ptr(), buf.len())
                            }
                            WorkerTarget::MicroNonzeroExit => {
                                achlys_micro_nonzero_exit(buf.as_ptr(), buf.len())
                            }
                            WorkerTarget::MicroCoverageStable => {
                                achlys_micro_coverage_stable(buf.as_ptr(), buf.len())
                            }
                        };
                        if let Some(&b) = buf.first() {
                            map[b as usize] = 1;
                        }
                        if rc != 0 {
                            map[1] = 1;
                        }
                        ExitKind::Ok
                    },
                    CoverageMap::new(ptr, MICRO_MAP_LEN),
                    "edges",
                )
            }
        }
    }
}

fn fingerprint_git(root: &Path) -> (String, u32, u32) {
    let sha = Command::new("git")
        .args(["-C", &root.display().to_string(), "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let porcelain = Command::new("git")
        .args(["-C", &root.display().to_string(), "status", "--porcelain"])
        .output()
        .ok();
    let (dirty, untracked) = porcelain
        .map(|o| {
            let mut dirty = 0u32;
            let mut untracked = 0u32;
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                if line.is_empty() {
                    continue;
                }
                if line.starts_with("??") {
                    untracked += 1;
                } else {
                    dirty += 1;
                }
            }
            (dirty, untracked)
        })
        .unwrap_or((0, 0));
    (sha, dirty, untracked)
}

fn rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "rustc-unknown".into())
}

fn open_shmem_provider() -> StdShMemProvider {
    match StdShMemProvider::new() {
        Ok(provider) => provider,
        Err(err) => {
            let sock = Path::new("libafl_unix_shmem_server");
            if sock.exists() {
                let _ = fs::remove_file(sock);
            }
            StdShMemProvider::new().unwrap_or_else(|retry| {
                die(&format!(
                    "shmem: {retry} (after removing stale {sock:?}; first error: {err})"
                ))
            })
        }
    }
}

fn artifacts_dir(out: &Path) -> PathBuf {
    out.join("artifacts")
}

fn spool_dir(out: &Path) -> PathBuf {
    out.join("spool")
}

fn control_notice_id(
    kind: &str,
    worker_id: WorkerId,
    next_producer_seq: u64,
    previous_event_seq: Option<u64>,
) -> String {
    format!(
        "{kind}-{}-p{next_producer_seq}-e{}",
        worker_id.to_hex(),
        previous_event_seq.unwrap_or(0)
    )
}

fn run_admit(out: &Path) -> Result<()> {
    let bound = env::var("ACHLYS_T2_PENDING_BOUND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(achlys_core::DEFAULT_PENDING_BOUND);
    let store = achlys_core::CampaignStore::open(artifacts_dir(out), read_campaign_id(out)?)?;
    let mut auth = CorpusAuthority::reconstruct(store, bound)?;
    let spool = CandidateSpool::open(spool_dir(out))?;
    let record = read_campaign_record(out)?;
    let canonical = record
        .canonical_build
        .as_ref()
        .ok_or_else(|| anyhow!("campaign.json missing canonical_build"))?;
    let bin = out.join("builds").join("canonical").join("canonical");
    let on_disk = BuildIdentity::hash_file(&bin).map_err(|e| anyhow!(e))?;
    match &canonical.artifact_hash {
        Some(expected) if expected == &on_disk => {}
        Some(expected) => {
            anyhow::bail!("canonical dump hash {on_disk} != campaign artifact_hash {expected}");
        }
        None => anyhow::bail!("campaign canonical_build missing artifact_hash"),
    }
    let id_path = out.join("builds").join("canonical").join("identity.json");
    if id_path.is_file() {
        let stored = load_identity_json(&id_path)?;
        if stored.target_id.as_str() != record.target_id {
            anyhow::bail!(
                "identity.json target_id {} != campaign {}",
                stored.target_id,
                record.target_id
            );
        }
        if stored.build_id != canonical.build_id {
            anyhow::bail!("identity.json build_id does not match campaign.json");
        }
    } else {
        anyhow::bail!("canonical identity.json missing at {}", id_path.display());
    }
    let mut oracle = DumpOracle::new(&bin, canonical.build_id)?;

    auth.warm_oracle(&mut oracle)?;
    let mut idle = 0u32;
    loop {
        admit_once(&mut auth, &spool, &record, &mut oracle)?;
        let quiet = spool.inbox_len() == 0
            && spool.overflow_len() == 0
            && spool.processing_len() == 0
            && spool.leftover_control_notices() == 0
            && auth.pending_len() == 0;
        if quiet {
            idle = idle.saturating_add(1);
        } else {
            idle = 0;
        }
        if spool.stop_requested() && idle >= 3 {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    // Final drain: keep going until every stage is empty or we hit a bound
    // that still has overflow (then keep draining pending to free slots).
    for _ in 0..1_000_000 {
        let progress = admit_once(&mut auth, &spool, &record, &mut oracle)?;
        if !progress
            && spool.inbox_len() == 0
            && spool.overflow_len() == 0
            && spool.processing_len() == 0
            && spool.leftover_control_notices() == 0
            && auth.pending_len() == 0
        {
            break;
        }
    }
    if spool.inbox_len() != 0
        || spool.processing_len() != 0
        || spool.overflow_len() != 0
        || spool.leftover_control_notices() != 0
        || auth.pending_len() != 0
    {
        anyhow::bail!(
            "admit shutdown incomplete: inbox={} processing={} overflow={} pending={} control={}",
            spool.inbox_len(),
            spool.processing_len(),
            spool.overflow_len(),
            auth.pending_len(),
            spool.leftover_control_notices()
        );
    }
    auth.write_canonical_report(
        &oracle,
        record
            .canonical_build
            .as_ref()
            .and_then(|b| b.artifact_hash.clone()),
    )?;
    let report = serde_json::json!({
        "queue_full": auth.queue_full_count(),
        "replayed": auth.replayed(),
        "admitted": auth.admitted_ids().len(),
        "rejected": auth.rejected_len(),
        "pending": auth.pending_len(),
        "inbox": spool.inbox_len(),
        "processing": spool.processing_len(),
        "overflow": spool.overflow_len(),
        "control": spool.leftover_control_notices(),
    });
    let metrics_dir = artifacts_dir(out).join("metrics");
    fs::create_dir_all(&metrics_dir)?;
    fs::write(
        metrics_dir.join("admission.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(())
}

fn admit_once(
    auth: &mut CorpusAuthority,
    spool: &CandidateSpool,
    record: &CampaignRecord,
    oracle: &mut DumpOracle,
) -> Result<bool> {
    let mut progress = false;
    if auth.apply_spooled_registrations(spool, record.fast_build.build_id)? > 0 {
        progress = true;
    }
    if auth.ingest_spool(spool)? > 0 {
        progress = true;
    }
    let stats = auth.drain(oracle, 64)?;
    if let Some(seq) = stats.delta_seq {
        spool.write_delta(seq, &stats.delta_admitted)?;
        progress = true;
    }
    if stats.replayed > 0 {
        progress = true;
    }
    if auth.apply_spooled_exits(spool)? > 0 {
        progress = true;
    }
    Ok(progress)
}

fn read_campaign_id(out: &Path) -> Result<CampaignId> {
    Ok(read_campaign_record(out)?.campaign_id)
}

fn read_campaign_record(out: &Path) -> Result<CampaignRecord> {
    let path = artifacts_dir(out).join("campaign.json");
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let record: CampaignRecord =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    record
        .fast_build
        .validate()
        .map_err(|err| anyhow!("campaign fast_build: {err}"))?;
    if let Some(canon) = &record.canonical_build {
        canon
            .validate()
            .map_err(|err| anyhow!("campaign canonical_build: {err}"))?;
    }
    Ok(record)
}

fn assert_join_compatible(
    record: &CampaignRecord,
    manifest: &TargetManifest,
    fast: &BuildIdentity,
    out: &Path,
    workspace: &Path,
) {
    if record.target_id != manifest.target_id {
        die(&format!(
            "--join target mismatch: campaign is {}, manifest is {}",
            record.target_id, manifest.target_id
        ));
    }
    let stored_manifest = artifacts_dir(out).join("manifest.toml");
    let stored = TargetManifest::from_path(&stored_manifest).unwrap_or_else(|e| {
        die(&format!(
            "--join cannot load stored manifest {}: {e}",
            stored_manifest.display()
        ))
    });
    if stored.target_id != manifest.target_id {
        die("--join stored manifest target_id differs");
    }
    if stored.max_input_len != manifest.max_input_len {
        die("--join max_input_len differs from stored campaign");
    }
    if stored.builds.fast.flags != manifest.builds.fast.flags
        || stored.builds.canonical.flags != manifest.builds.canonical.flags
    {
        die("--join build flags differ from stored campaign");
    }
    if stored.builds.fast.instrumentation != manifest.builds.fast.instrumentation
        || stored.builds.canonical.instrumentation != manifest.builds.canonical.instrumentation
    {
        die("--join instrumentation differs from stored campaign");
    }
    if record.fast_build.build_id != fast.build_id {
        die(&format!(
            "--join fast_build mismatch: campaign {} vs current {}",
            record.fast_build.build_id.to_hex(),
            fast.build_id.to_hex()
        ));
    }
    let Some(canon) = &record.canonical_build else {
        die("--join campaign missing canonical_build");
    };
    let bin = out.join("builds").join("canonical").join("canonical");
    if !bin.is_file() {
        die(&format!("--join missing canonical dump {}", bin.display()));
    }
    verify_canonical_file(&bin, canon);
    let expected = BuildIdentity::from_executed(
        manifest,
        BuildKind::Canonical,
        workspace,
        EXTRA_IDENTITY,
        Some(&bin),
    )
    .unwrap_or_else(|e| die(&format!("--join recompute canonical identity: {e}")));
    if expected.build_id != canon.build_id {
        die(&format!(
            "--join canonical identity drifted: campaign {} vs recomputed {}",
            canon.build_id.to_hex(),
            expected.build_id.to_hex()
        ));
    }
}

fn verify_canonical_file(bin: &Path, identity: &BuildIdentity) {
    let got = BuildIdentity::hash_file(bin).unwrap_or_else(|e| die(&e));
    match &identity.artifact_hash {
        Some(expected) if expected == &got => {}
        Some(expected) => die(&format!(
            "canonical dump {} hash {got} != campaign artifact_hash {expected}",
            bin.display()
        )),
        None => die("campaign canonical_build missing artifact_hash"),
    }
}

fn load_identity_json(path: &Path) -> Result<BuildIdentity> {
    let text =
        fs::read_to_string(path).with_context(|| format!("read identity {}", path.display()))?;
    let identity: BuildIdentity = serde_json::from_str(&text)
        .with_context(|| format!("parse identity {}", path.display()))?;
    identity
        .validate()
        .map_err(|err| anyhow!("identity.json {}: {err}", path.display()))?;
    Ok(identity)
}

fn write_identity_json(path: &Path, identity: &BuildIdentity) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(identity)?)
        .with_context(|| format!("write {}", path.display()))
}

fn assert_identity_matches_manifest(identity: &BuildIdentity, manifest: &TargetManifest) {
    if identity.target_id.as_str() != manifest.target_id {
        die(&format!(
            "canonical identity target_id {} != manifest {}",
            identity.target_id, manifest.target_id
        ));
    }
    if identity.kind != BuildKind::Canonical {
        die(&format!(
            "canonical identity kind is {:?}, want Canonical",
            identity.kind
        ));
    }
    if identity.flags != manifest.builds.canonical.flags {
        die("canonical identity flags do not match the requested manifest");
    }
}

fn resolve_canonical_bundle(
    manifest: &TargetManifest,
    existing: Option<&CampaignRecord>,
    dir: Option<&Path>,
    bin_arg: Option<&Path>,
) -> Result<achlys_bridge::CompiledArtifact> {
    let (bin, id_path) = if let Some(dir) = dir {
        (dir.join("canonical"), dir.join("identity.json"))
    } else if let Some(bin) = bin_arg {
        let parent = bin
            .parent()
            .ok_or_else(|| anyhow!("--canonical-bin has no parent directory: {}", bin.display()))?;
        (bin.to_path_buf(), parent.join("identity.json"))
    } else {
        anyhow::bail!("internal: no canonical bundle");
    };
    if !bin.is_file() {
        anyhow::bail!("canonical dump missing: {}", bin.display());
    }
    if !id_path.is_file() {
        anyhow::bail!(
            "canonical identity.json missing next to {} (refusing to invent identity from the requested manifest)",
            bin.display()
        );
    }
    let identity = load_identity_json(&id_path)?;
    verify_canonical_file(&bin, &identity);
    assert_identity_matches_manifest(&identity, manifest);
    if let Some(record) = existing {
        let Some(want) = &record.canonical_build else {
            anyhow::bail!("--join campaign missing canonical_build");
        };
        if want.build_id != identity.build_id {
            anyhow::bail!(
                "pinned canonical build_id {} != campaign {}",
                identity.build_id.to_hex(),
                want.build_id.to_hex()
            );
        }
        if want.target_id != identity.target_id {
            anyhow::bail!(
                "pinned canonical target_id {} != campaign {}",
                identity.target_id,
                want.target_id
            );
        }
    }
    Ok(achlys_bridge::CompiledArtifact {
        path: bin,
        identity,
    })
}

fn main() {
    let args = parse_args();
    match args.role {
        Role::Admit => run_admit(&args.out).unwrap_or_else(|e| die(&format!("admit: {e:#}"))),
        Role::Launcher => run_launcher(args),
    }
}

fn run_launcher(args: Args) {
    let started = Instant::now();
    let root = workspace_root();
    let manifest_path = if args.manifest.is_absolute() {
        args.manifest.clone()
    } else {
        root.join(&args.manifest)
    };
    let manifest = TargetManifest::from_path(&manifest_path)
        .unwrap_or_else(|e| die(&format!("manifest {}: {e}", manifest_path.display())));
    if manifest.input_mode != achlys_protocol::InputMode::Inprocess {
        die("achlys_t2 only runs in-process manifests in this tranche");
    }
    let kind = WorkerTarget::parse(&manifest.target_id).unwrap_or_else(|e| die(&e.to_string()));
    if kind.as_str() != manifest.target_id {
        die("internal target id mismatch");
    }

    if !args.join {
        require_fresh(&args.out);
    }

    let ncores = get_core_ids().map(|c| c.len()).unwrap_or(1);
    if args.workers > ncores {
        die(&format!(
            "--workers {} exceeds {} visible cores",
            args.workers, ncores
        ));
    }

    let cores_spec = args.cores.clone().unwrap_or_else(|| {
        if args.workers == 1 {
            "0".into()
        } else {
            format!("0-{}", args.workers - 1)
        }
    });
    let cores = Cores::from_cmdline(&cores_spec)
        .unwrap_or_else(|e| die(&format!("--cores {cores_spec}: {e}")));
    if cores.ids.len() != args.workers {
        die(&format!(
            "--cores selects {} ids, --workers is {} (they must match)",
            cores.ids.len(),
            args.workers
        ));
    }

    fs::create_dir_all(&args.out)
        .unwrap_or_else(|e| die(&format!("create {}: {e}", args.out.display())));

    let exe = env::current_exe().unwrap_or_else(|e| die(&format!("current_exe: {e}")));
    let fast = BuildIdentity::from_executed(
        &manifest,
        BuildKind::Fast,
        &root,
        EXTRA_IDENTITY,
        Some(&exe),
    )
    .unwrap_or_else(|e| die(&format!("fast identity: {e}")));

    let measure_dir = args.out.join("builds");
    let canonical_dir = measure_dir.join("canonical");
    let default_bin = canonical_dir.join("canonical");
    let existing_record = if args.join {
        Some(read_campaign_record(&args.out).unwrap_or_else(|e| die(&format!("join: {e:#}"))))
    } else {
        None
    };

    if args.join {
        let record = existing_record.as_ref().expect("join record");
        assert_join_compatible(record, &manifest, &fast, &args.out, &root);
    }

    let canonical = if args.canonical_dir.is_some() || args.canonical_bin.is_some() {
        resolve_canonical_bundle(
            &manifest,
            existing_record.as_ref(),
            args.canonical_dir.as_deref(),
            args.canonical_bin.as_deref(),
        )
        .unwrap_or_else(|e| die(&format!("canonical artifact: {e:#}")))
    } else if args.join && default_bin.is_file() {
        let record = existing_record.as_ref().expect("join record");
        let identity = record
            .canonical_build
            .clone()
            .unwrap_or_else(|| die("--join campaign missing canonical_build"));
        let id_path = canonical_dir.join("identity.json");
        if id_path.is_file() {
            let on_disk = load_identity_json(&id_path)
                .unwrap_or_else(|e| die(&format!("join identity.json: {e:#}")));
            if on_disk.build_id != identity.build_id
                || on_disk.target_id.as_str() != record.target_id
            {
                die("join identity.json does not match campaign.json");
            }
        }
        verify_canonical_file(&default_bin, &identity);
        if identity.target_id.as_str() != manifest.target_id {
            die("join canonical target_id does not match requested manifest");
        }
        achlys_bridge::CompiledArtifact {
            path: default_bin.clone(),
            identity,
        }
    } else {
        let art = compile_canonical(&root, &manifest, &canonical_dir, EXTRA_IDENTITY)
            .unwrap_or_else(|e| die(&format!("canonical compile: {e:#}")));
        write_identity_json(&canonical_dir.join("identity.json"), &art.identity)
            .unwrap_or_else(|e| die(&format!("write identity.json: {e:#}")));
        art
    };

    let (git, dirty, untracked) = fingerprint_git(&root);
    let campaign_id = if args.join {
        existing_record
            .as_ref()
            .map(|r| r.campaign_id)
            .unwrap_or_else(|| die("join missing campaign id"))
    } else {
        CampaignId::from_label(&format!(
            "{}-{}-{}",
            args.label, manifest.target_id, args.seed
        ))
    };

    if !args.join {
        let record = CampaignRecord {
            schema_version: CampaignEvent::SCHEMA_VERSION,
            campaign_id,
            target_id: manifest.target_id.clone(),
            label: args.label.clone(),
            seed: args.seed,
            max_iters: args.iters,
            max_seconds: args.seconds,
            max_input_len: manifest.max_input_len,
            timeout_ms: manifest.timeout_ms,
            tool: "achlys_t2".into(),
            host: format!("{} {}", env::consts::OS, env::consts::ARCH),
            rustc: rustc_version(),
            git,
            git_dirty_tracked: dirty,
            git_untracked: untracked,
            fast_build: fast.clone(),
            canonical_build: Some(canonical.identity.clone()),
            sanitizer_build: None,
            started_unix_ms: unix_ms(),
        };
        CampaignSession::begin(artifacts_dir(&args.out), &manifest, &record)
            .unwrap_or_else(|e| die(&format!("campaign begin: {e:#}")));
    }

    let spool = if args.join {
        CandidateSpool::open(spool_dir(&args.out))
    } else {
        CandidateSpool::create(spool_dir(&args.out))
    }
    .unwrap_or_else(|e| die(&format!("spool: {e:#}")));
    spool
        .clear_stop()
        .unwrap_or_else(|e| die(&format!("clear STOP: {e:#}")));

    if canonical.path != default_bin {
        fs::create_dir_all(&canonical_dir)
            .unwrap_or_else(|e| die(&format!("create {}: {e}", canonical_dir.display())));
        if !default_bin.is_file() {
            fs::copy(&canonical.path, &default_bin).unwrap_or_else(|e| {
                die(&format!(
                    "copy canonical {} -> {}: {e}",
                    canonical.path.display(),
                    default_bin.display()
                ))
            });
        } else {
            verify_canonical_file(&default_bin, &canonical.identity);
        }
    }
    write_identity_json(&canonical_dir.join("identity.json"), &canonical.identity)
        .unwrap_or_else(|e| die(&format!("write campaign identity.json: {e:#}")));

    let folded = {
        let store = achlys_core::CampaignStore::open(artifacts_dir(&args.out), campaign_id)
            .unwrap_or_else(|e| die(&format!("open store: {e:#}")));
        let mut auth = CorpusAuthority::reconstruct(store, args.pending_bound)
            .unwrap_or_else(|e| die(&format!("reconstruct: {e:#}")));
        let mut oracle = DumpOracle::new(&default_bin, canonical.identity.build_id)
            .unwrap_or_else(|e| die(&format!("recovery oracle: {e:#}")));
        auth.warm_oracle(&mut oracle)
            .unwrap_or_else(|e| die(&format!("warm recovery oracle: {e:#}")));
        auth.recover_from_spool(&spool, &mut oracle, fast.build_id)
            .unwrap_or_else(|e| die(&format!("recover spool: {e:#}")));
        if args.join {
            let snap = auth
                .snapshot_admitted_bytes()
                .unwrap_or_else(|e| die(&format!("snapshot: {e:#}")));
            spool
                .export_admitted_snapshot(&spool.root().join("snapshot"), &snap)
                .unwrap_or_else(|e| die(&format!("export snapshot: {e:#}")));
        }
        reconstruct_events(
            auth.store()
                .read_events()
                .unwrap_or_else(|e| die(&format!("read events: {e:#}"))),
        )
    };
    for slot in 0..args.workers {
        let slot = u32::try_from(slot).unwrap_or(u32::MAX);
        let worker_id = WorkerId::from_slot(slot);
        let resume = if let Some(rec) = folded.workers.get(&worker_id) {
            WorkerResume {
                worker_id,
                slot,
                restart: true,
                previous_event_seq: Some(rec.last_seq),
                next_producer_seq: rec.next_producer_seq,
            }
        } else {
            WorkerResume {
                worker_id,
                slot,
                restart: false,
                previous_event_seq: None,
                next_producer_seq: 0,
            }
        };
        spool
            .write_resume(&resume)
            .unwrap_or_else(|e| die(&format!("write resume slot {slot}: {e:#}")));
    }

    let admit_log = args.out.join("admit.log");
    let admit_out = fs::File::create(&admit_log)
        .unwrap_or_else(|e| die(&format!("create {}: {e}", admit_log.display())));
    let mut admit_cmd = Command::new(&exe);
    admit_cmd
        .arg("--role")
        .arg("admit")
        .arg("--out")
        .arg(&args.out)
        .arg("--manifest")
        .arg(&manifest_path)
        .env("ACHLYS_T2_PENDING_BOUND", args.pending_bound.to_string())
        .stdout(Stdio::from(admit_out.try_clone().unwrap()))
        .stderr(Stdio::from(admit_out));
    let mut admit_child = admit_cmd
        .spawn()
        .unwrap_or_else(|e| die(&format!("spawn admit: {e}")));

    let shmem = open_shmem_provider();
    let monitor = NopMonitor::new();

    let worker_seed = args.seed;
    let worker_iters = args.iters;
    let worker_seconds = args.seconds;
    let worker_corpus = args.corpus.clone();
    let worker_out = args.out.clone();
    let worker_timeout = Duration::from_millis(manifest.timeout_ms.max(1));
    let worker_max_len = manifest.max_input_len;
    let worker_fast = fast.build_id;
    let worker_kind = kind;
    let worker_sync_every = args.sync_every;
    let worker_rescan = args.rescan;
    let snapshot_dir = spool_dir(&args.out).join("snapshot");
    let campaign = campaign_id;

    let run_client =
        move |state: Option<WorkerState>, mut mgr, desc: libafl::events::ClientDescription| {
            let _ = state;
            let slot = u32::try_from(desc.id().saturating_sub(1)).unwrap_or(u32::MAX);
            let worker_id = WorkerId::from_slot(slot);
            let dir = worker_out.join("workers").join(slot.to_string());
            let persist = dir.join("corpus");
            let crashes = dir.join("crashes");
            fs::create_dir_all(&persist).map_err(|e| libafl::Error::unknown(e.to_string()))?;
            fs::create_dir_all(&crashes).map_err(|e| libafl::Error::unknown(e.to_string()))?;

            let spool = CandidateSpool::open(spool_dir(&worker_out))
                .map_err(|e| libafl::Error::unknown(e.to_string()))?;
            let resume = spool
                .read_resume(slot)
                .map_err(|e| libafl::Error::unknown(e.to_string()))?
                .unwrap_or(WorkerResume {
                    worker_id,
                    slot,
                    restart: false,
                    previous_event_seq: None,
                    next_producer_seq: 0,
                });
            if resume.worker_id != worker_id {
                return Err(libafl::Error::unknown(format!(
                    "resume worker_id {} != slot worker {worker_id}",
                    resume.worker_id
                )));
            }
            spool
                .write_worker(&WorkerRegistration {
                    notice_id: control_notice_id(
                        if resume.restart { "rst" } else { "reg" },
                        worker_id,
                        resume.next_producer_seq,
                        resume.previous_event_seq,
                    ),
                    worker_id,
                    slot,
                    restart: resume.restart,
                    previous_event_seq: resume.previous_event_seq,
                    next_producer_seq: resume.next_producer_seq,
                })
                .map_err(|e| libafl::Error::unknown(e.to_string()))?;

            let mut extra = Vec::new();
            if snapshot_dir.is_dir() {
                extra.push(snapshot_dir.clone());
            }
            let mut config = FuzzerConfig {
                corpus_dir: worker_corpus.clone(),
                crashes_dir: crashes,
                persist_corpus_dir: Some(persist.clone()),
                rng_seed: worker_seed.wrapping_add(u64::from(slot)),
                max_iters: worker_iters,
                max_time: worker_seconds.map(Duration::from_secs),
                max_input_len: worker_max_len,
                exec_timeout: worker_timeout,
                initial_inputs: 8,
                sync_every: worker_sync_every,
                ..FuzzerConfig::default()
            };
            // keep rustc happy if Default overwrites
            config.corpus_dir = worker_corpus.clone();
            config.persist_corpus_dir = Some(persist.clone());

            let target = worker_target(worker_kind);
            let mut seq = resume.next_producer_seq;
            let mut cursor = CorpusScanCursor::new();
            let mut sync = SyncMetrics::default();
            let scan_mode = if worker_rescan {
                ScanMode::Rescan
            } else {
                ScanMode::Incremental
            };
            let report = run_llmp_worker(target, &config, &mut mgr, &extra, |corpus_dir| {
                let started_sync = Instant::now();
                let (new, stats) = scan_new_inputs(corpus_dir, &mut cursor, scan_mode)?;
                let mut spooled = 0usize;
                for (_id, bytes) in new {
                    let meta = InputMetadata {
                        input_id: InputId::from_bytes(&bytes),
                        parent_ids: vec![],
                        producer: "havoc".into(),
                        producer_build: worker_fast,
                        campaign_id: campaign,
                        local_coverage: None,
                        canonical_delta: None,
                        stored_unix_ms: unix_ms(),
                        worker_id: Some(worker_id),
                        producer_seq: Some(seq),
                        strategy: Some(StrategyId::Havoc),
                    };
                    seq = seq.saturating_add(1);
                    spool.push(&bytes, &meta)?;
                    spooled = spooled.saturating_add(1);
                }
                let ns = u64::try_from(started_sync.elapsed().as_nanos()).unwrap_or(u64::MAX);
                sync.record(ns, &stats, spooled);
                Ok(())
            })
            .map_err(|e| libafl::Error::unknown(e.to_string()))?;

            let summary = serde_json::json!({
                "slot": slot,
                "worker_id": worker_id.to_hex(),
                "executions": report.executions,
                "corpus_count": report.corpus_count,
                "objectives": report.objectives,
                "elapsed_ms": report.elapsed.as_millis() as u64,
                "sync_calls": sync.calls,
                "sync_ns_total": sync.ns_total,
                "sync_ns_p95": sync.p95_ns(),
                "sync_ns_max": sync.ns_max,
                "paths_listed": sync.paths_listed,
                "paths_read": sync.paths_read,
                "bytes_read": sync.bytes_read,
                "inputs_spooled": sync.inputs_spooled,
            });
            fs::write(
                dir.join("report.json"),
                serde_json::to_vec_pretty(&summary)
                    .map_err(|e| libafl::Error::unknown(e.to_string()))?,
            )
            .map_err(|e| libafl::Error::unknown(e.to_string()))?;
            spool
                .write_left(&WorkerExit {
                    notice_id: control_notice_id("left", worker_id, seq, resume.previous_event_seq),
                    worker_id,
                    slot,
                    next_producer_seq: seq,
                    reason: "budget".into(),
                })
                .map_err(|e| libafl::Error::unknown(e.to_string()))?;
            mgr.send_exiting()?;
            Ok(())
        };

    let mut launcher = Launcher::builder()
        .shmem_provider(shmem)
        .monitor(monitor)
        .run_client(run_client)
        .cores(&cores)
        .broker_port(args.broker_port)
        .configuration(EventConfig::from_name("achlys-t2-havoc"))
        .build();

    let launcher_pid = process::id();
    match launcher.launch::<BytesInput, WorkerState>() {
        Ok(()) | Err(libafl::Error::ShuttingDown) => {}
        Err(err) => {
            if process::id() == launcher_pid {
                let _ = admit_child.kill();
            }
            die(&format!("launcher: {err}"));
        }
    }
    // Forked clients return from `launch`. Only the original parent
    // owns the admit child and writes T2_RESULT.
    if process::id() != launcher_pid {
        process::exit(0);
    }

    spool
        .write_stop()
        .unwrap_or_else(|e| die(&format!("stop admit: {e:#}")));
    let status = admit_child
        .wait()
        .unwrap_or_else(|e| die(&format!("wait admit: {e}")));
    if !status.success() {
        die(&format!(
            "admit process failed ({status}); see {}",
            admit_log.display()
        ));
    }

    let store = achlys_core::CampaignStore::open(artifacts_dir(&args.out), campaign_id)
        .unwrap_or_else(|e| die(&format!("open store: {e:#}")));
    let events = store
        .read_events()
        .unwrap_or_else(|e| die(&format!("read events: {e:#}")));
    let folded = reconstruct_events(events);
    let report_path = artifacts_dir(&args.out)
        .join("reports")
        .join("canonical.json");
    if !report_path.is_file() {
        die("admit did not write reports/canonical.json");
    }
    let canon: serde_json::Value = serde_json::from_slice(
        &fs::read(&report_path).unwrap_or_else(|e| die(&format!("read canonical: {e}"))),
    )
    .unwrap_or_else(|e| die(&format!("parse canonical: {e}")));
    let admitted = canon.get("admitted").and_then(|v| v.as_u64()).unwrap_or(0);
    let rejected = canon.get("rejected").and_then(|v| v.as_u64()).unwrap_or(0);
    let replayed = canon.get("replayed").and_then(|v| v.as_u64()).unwrap_or(0);
    let edges = canon
        .get("edge_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let objects = store
        .list_inputs()
        .map(|v| v.len())
        .unwrap_or(folded.stored.len());
    let mut execs = 0u64;
    let mut objectives = 0u64;
    let mut reports = 0usize;
    let mut sync_calls = 0u64;
    let mut sync_ns = 0u64;
    let mut sync_ns_p95 = 0u64;
    let mut sync_ns_max = 0u64;
    let mut paths_listed = 0u64;
    let mut paths_read = 0u64;
    let mut bytes_read = 0u64;
    let mut inputs_spooled = 0u64;
    for slot in 0..args.workers {
        let path = args
            .out
            .join("workers")
            .join(slot.to_string())
            .join("report.json");
        if !path.is_file() {
            die(&format!("missing worker report {}", path.display()));
        }
        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(&path).unwrap_or_else(|e| die(&format!("read {}: {e}", path.display()))),
        )
        .unwrap_or_else(|e| die(&format!("parse {}: {e}", path.display())));
        reports += 1;
        execs = execs.saturating_add(v.get("executions").and_then(|x| x.as_u64()).unwrap_or(0));
        objectives =
            objectives.saturating_add(v.get("objectives").and_then(|x| x.as_u64()).unwrap_or(0));
        sync_calls =
            sync_calls.saturating_add(v.get("sync_calls").and_then(|x| x.as_u64()).unwrap_or(0));
        sync_ns =
            sync_ns.saturating_add(v.get("sync_ns_total").and_then(|x| x.as_u64()).unwrap_or(0));
        sync_ns_p95 = sync_ns_p95.max(v.get("sync_ns_p95").and_then(|x| x.as_u64()).unwrap_or(0));
        sync_ns_max = sync_ns_max.max(v.get("sync_ns_max").and_then(|x| x.as_u64()).unwrap_or(0));
        paths_listed = paths_listed
            .saturating_add(v.get("paths_listed").and_then(|x| x.as_u64()).unwrap_or(0));
        paths_read =
            paths_read.saturating_add(v.get("paths_read").and_then(|x| x.as_u64()).unwrap_or(0));
        bytes_read =
            bytes_read.saturating_add(v.get("bytes_read").and_then(|x| x.as_u64()).unwrap_or(0));
        inputs_spooled = inputs_spooled.saturating_add(
            v.get("inputs_spooled")
                .and_then(|x| x.as_u64())
                .unwrap_or(0),
        );
    }
    if reports != args.workers {
        die(&format!(
            "worker reports {reports} != --workers {}",
            args.workers
        ));
    }

    let admission_path = artifacts_dir(&args.out)
        .join("metrics")
        .join("admission.json");
    let admission: serde_json::Value = if admission_path.is_file() {
        serde_json::from_slice(
            &fs::read(&admission_path).unwrap_or_else(|e| die(&format!("read admission: {e}"))),
        )
        .unwrap_or_else(|e| die(&format!("parse admission: {e}")))
    } else {
        die("admit did not write metrics/admission.json");
    };
    let queue_full = admission
        .get("queue_full")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let processing = admission
        .get("processing")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let inbox = admission
        .get("inbox")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let overflow = admission
        .get("overflow")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let pending = admission
        .get("pending")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    if processing != 0 || inbox != 0 || overflow != 0 || pending != 0 {
        die(&format!(
            "admit left work behind: inbox={inbox} processing={processing} overflow={overflow} pending={pending}"
        ));
    }
    if objects as u64 != replayed {
        die(&format!("objects {objects} != replayed {replayed}"));
    }
    if admitted + rejected != replayed {
        die(&format!(
            "admitted+rejected {} != replayed {replayed}",
            admitted + rejected
        ));
    }

    let wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let snapshot = MetricsSnapshot {
        executions: execs,
        corpus_count: objects,
        objectives: usize::try_from(objectives).unwrap_or(usize::MAX),
        canonical_edges: u32::try_from(edges).unwrap_or(u32::MAX),
        elapsed_ms: wall_ms,
        crash: Default::default(),
    };
    store
        .write_metrics(&snapshot)
        .unwrap_or_else(|e| die(&format!("write metrics: {e:#}")));
    store
        .append_event(&CampaignEvent::CampaignFinished {
            campaign_id,
            snapshot,
            unix_ms: unix_ms(),
        })
        .unwrap_or_else(|e| die(&format!("CampaignFinished: {e:#}")));

    println!(
        "T2_RESULT workers={} ingested={} admitted={} rejected={} replayed={} edges={} objects={} queue_full={} execs={} registered={} reports={} objectives={} wall_ms={} sync_every={} rescan={} sync_calls={} sync_ns={} sync_ns_p95={} sync_ns_max={} paths_listed={} paths_read={} bytes_read={} spooled={}",
        args.workers,
        objects,
        admitted,
        rejected,
        replayed,
        edges,
        objects,
        queue_full,
        execs,
        folded.workers.len(),
        reports,
        objectives,
        wall_ms,
        args.sync_every,
        u8::from(args.rescan),
        sync_calls,
        sync_ns,
        sync_ns_p95,
        sync_ns_max,
        paths_listed,
        paths_read,
        bytes_read,
        inputs_spooled
    );
}

type WorkerState =
    StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

type WorkerMgr =
    LlmpRestartingEventManager<(), BytesInput, WorkerState, StdShMem, StdShMemProvider>;

fn run_llmp_worker<F>(
    mut target: InProcessTarget,
    config: &FuzzerConfig,
    mgr: &mut WorkerMgr,
    extra_seed_dirs: &[PathBuf],
    mut on_sync: F,
) -> Result<achlys_core::SubstrateReport>
where
    F: FnMut(&Path) -> Result<()>,
{
    let persist = config
        .persist_corpus_dir
        .clone()
        .ok_or_else(|| anyhow!("persist_corpus_dir required"))?;
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
    let corpus = InMemoryOnDiskCorpus::<BytesInput>::new(&persist)?;
    let mut state = StdState::new(
        StdRand::with_seed(config.rng_seed),
        corpus,
        OnDiskCorpus::new(&config.crashes_dir)?,
        &mut feedback,
        &mut objective,
    )?;
    state.set_max_size(config.max_input_len.max(1));
    let mut fuzzer = StdFuzzer::new(QueueScheduler::new(), feedback, objective);
    let infra = Arc::new(Mutex::new(None::<achlys_bridge::InfraError>));
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
    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        mgr,
        config.exec_timeout,
    )?;
    if let Some(err) = infra.lock().expect("infra").take() {
        return Err(anyhow!(err));
    }

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
        state.generate_initial_inputs(
            &mut fuzzer,
            &mut executor,
            &mut generator,
            mgr,
            config.initial_inputs,
        )?;
    } else {
        state.load_initial_inputs(&mut fuzzer, &mut executor, mgr, &seed_dirs)?;
    }
    if state.corpus().count() == 0 {
        anyhow::bail!("no initial inputs were admitted");
    }

    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    let start = Instant::now();
    if config.max_iters.is_none() && config.max_time.is_none() {
        anyhow::bail!("worker needs a bound");
    }
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
        fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, mgr, 1)?;
        remaining = remaining.saturating_sub(1);
        since_sync = since_sync.saturating_add(1);
        if since_sync >= sync_every {
            on_sync(&persist)?;
            since_sync = 0;
        }
    }
    on_sync(&persist)?;
    if let Some(err) = infra.lock().expect("infra").take() {
        return Err(anyhow!(err));
    }
    Ok(achlys_core::SubstrateReport {
        executions: *state.executions(),
        corpus_count: state.corpus().count(),
        objectives: state.solutions().count(),
        elapsed: start.elapsed(),
    })
}
