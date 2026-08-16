//! Tranche 2: homogeneous multi-worker havoc over LibAFL LLMP.
//!
//! Control plane (admit + DumpOracle + CampaignStore) is a separate process.
//! Workers do not call the oracle on the hot path.

use std::collections::HashSet;
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
    CampaignSession, CandidateSpool, CorpusAuthority, FuzzerConfig, PendingCandidate,
    SubmitOutcome, WorkerRegistration, scan_new_inputs,
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
    }
}

fn print_help() {
    eprintln!(
        "achlys_t2 --manifest PATH --out DIR --workers N [--seed N] \
         [--iters N | --seconds N] [--cores LIST] [--broker-port P] \
         [--corpus DIR] [--label NAME] [--join] [--role launcher|admit]"
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

fn run_admit(out: &Path) -> Result<()> {
    let store = achlys_core::CampaignStore::open(artifacts_dir(out), read_campaign_id(out)?)?;
    let mut auth = CorpusAuthority::reconstruct(store, achlys_core::DEFAULT_PENDING_BOUND)?;
    let spool = CandidateSpool::open(spool_dir(out))?;
    let record: CampaignRecord =
        serde_json::from_slice(&fs::read(artifacts_dir(out).join("campaign.json"))?)?;
    let canonical = record
        .canonical_build
        .as_ref()
        .ok_or_else(|| anyhow!("campaign.json missing canonical_build"))?;
    let bin = out.join("builds").join("canonical").join("canonical");
    let mut oracle = DumpOracle::new(&bin, canonical.build_id)?;

    auth.warm_oracle(&mut oracle)?;
    let leftover = spool.take_processing(4096)?;
    ingest_batch(&mut auth, leftover)?;
    let mut idle = 0u32;
    loop {
        for reg in spool.take_worker_registrations()? {
            if reg.restart {
                auth.note_restarted(reg.worker_id, reg.sender_seq, reg.previous_seq.unwrap_or(0))?;
            } else {
                auth.register_worker(
                    reg.worker_id,
                    reg.slot,
                    record.fast_build.build_id,
                    reg.sender_seq,
                )?;
            }
        }
        let inbox = spool.take_inbox(64)?;
        let overflow = spool.take_overflow(64)?;
        let incoming = inbox.len() + overflow.len();
        ingest_batch(&mut auth, inbox)?;
        ingest_batch(&mut auth, overflow)?;
        let stats = auth.drain(&mut oracle, 64)?;
        if stats.admitted > 0 {
            let seq = auth.next_delta_seq().saturating_sub(1);
            let admitted = auth.admitted_ids();
            // Last delta is the batch just written; rewrite the file from events.
            if let Some(last) = last_delta_ids(&auth)? {
                spool.write_delta(seq, &last)?;
            } else if !admitted.is_empty() {
                spool.write_delta(seq, &admitted)?;
            }
        }
        if incoming == 0 && stats.replayed == 0 {
            idle = idle.saturating_add(1);
        } else {
            idle = 0;
        }
        if spool.stop_requested() && idle >= 3 {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    let leftover = spool.take_inbox(4096)?;
    ingest_batch(&mut auth, leftover)?;
    let leftover = spool.take_overflow(4096)?;
    ingest_batch(&mut auth, leftover)?;
    while auth.pending_len() > 0 {
        auth.drain(&mut oracle, 64)?;
    }
    auth.write_canonical_report(
        &oracle,
        record
            .canonical_build
            .as_ref()
            .and_then(|b| b.artifact_hash.clone()),
    )?;
    Ok(())
}

fn last_delta_ids(auth: &CorpusAuthority) -> Result<Option<Vec<InputId>>> {
    let events = auth.store().read_events()?;
    Ok(events.into_iter().rev().find_map(|ev| match ev {
        CampaignEvent::CorpusDelta { admitted, .. } => Some(admitted),
        _ => None,
    }))
}

fn ingest_batch(
    auth: &mut CorpusAuthority,
    batch: Vec<(InputId, Vec<u8>, InputMetadata)>,
) -> Result<()> {
    for (id, bytes, meta) in batch {
        let _ = id;
        if meta.worker_id.is_some() {
            let _ = auth.note_discovered(&meta);
        }
        match auth.submit(PendingCandidate {
            bytes,
            meta: meta.clone(),
        })? {
            SubmitOutcome::Queued | SubmitOutcome::Duplicate => {}
            SubmitOutcome::QueueFull => {
                // Object is stored; reconstruct will requeue. Keep going.
            }
        }
    }
    Ok(())
}

fn read_campaign_id(out: &Path) -> Result<CampaignId> {
    let record: CampaignRecord =
        serde_json::from_slice(&fs::read(artifacts_dir(out).join("campaign.json"))?)?;
    Ok(record.campaign_id)
}

fn main() {
    let args = parse_args();
    match args.role {
        Role::Admit => run_admit(&args.out).unwrap_or_else(|e| die(&format!("admit: {e:#}"))),
        Role::Launcher => run_launcher(args),
    }
}

fn run_launcher(args: Args) {
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
    let canonical = if args.join && measure_dir.join("canonical").join("canonical").is_file() {
        let record: CampaignRecord = serde_json::from_slice(
            &fs::read(artifacts_dir(&args.out).join("campaign.json"))
                .unwrap_or_else(|e| die(&format!("read campaign.json: {e}"))),
        )
        .unwrap_or_else(|e| die(&format!("parse campaign.json: {e}")));
        let identity = record
            .canonical_build
            .unwrap_or_else(|| die("--join campaign missing canonical_build"));
        achlys_bridge::CompiledArtifact {
            path: measure_dir.join("canonical").join("canonical"),
            identity,
        }
    } else {
        compile_canonical(
            &root,
            &manifest,
            &measure_dir.join("canonical"),
            EXTRA_IDENTITY,
        )
        .unwrap_or_else(|e| die(&format!("canonical compile: {e:#}")))
    };

    let (git, dirty, untracked) = fingerprint_git(&root);
    let campaign_id = if args.join {
        read_campaign_id(&args.out).unwrap_or_else(|e| die(&format!("join: {e:#}")))
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

    if args.join {
        let store = achlys_core::CampaignStore::open(artifacts_dir(&args.out), campaign_id)
            .unwrap_or_else(|e| die(&format!("open store: {e:#}")));
        let auth = CorpusAuthority::reconstruct(store, achlys_core::DEFAULT_PENDING_BOUND)
            .unwrap_or_else(|e| die(&format!("reconstruct: {e:#}")));
        let snap = auth
            .snapshot_admitted_bytes()
            .unwrap_or_else(|e| die(&format!("snapshot: {e:#}")));
        spool
            .export_admitted_snapshot(&spool.root().join("snapshot"), &snap)
            .unwrap_or_else(|e| die(&format!("export snapshot: {e:#}")));
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
        .stdout(Stdio::from(admit_out.try_clone().unwrap()))
        .stderr(Stdio::from(admit_out));
    let mut admit_child = admit_cmd
        .spawn()
        .unwrap_or_else(|e| die(&format!("spawn admit: {e}")));

    let cores_spec = args.cores.clone().unwrap_or_else(|| {
        if args.workers == 1 {
            "0".into()
        } else {
            format!("0-{}", args.workers - 1)
        }
    });
    let cores = Cores::from_cmdline(&cores_spec)
        .unwrap_or_else(|e| die(&format!("--cores {cores_spec}: {e}")));

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
            spool
                .write_worker(&WorkerRegistration {
                    worker_id,
                    slot,
                    sender_seq: 0,
                    restart: false,
                    previous_seq: None,
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
                ..FuzzerConfig::default()
            };
            // keep rustc happy if Default overwrites
            config.corpus_dir = worker_corpus.clone();
            config.persist_corpus_dir = Some(persist.clone());

            let target = worker_target(worker_kind);
            let mut seq = 1u64;
            let mut seen = HashSet::new();
            let report = run_llmp_worker(target, &config, &mut mgr, &extra, |corpus_dir| {
                let new = scan_new_inputs(corpus_dir, &mut seen)?;
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
                }
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
            });
            let _ = fs::write(
                dir.join("report.json"),
                serde_json::to_vec_pretty(&summary).unwrap_or_default(),
            );
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
    if let Ok(entries) = fs::read_dir(args.out.join("workers")) {
        for entry in entries.flatten() {
            let path = entry.path().join("report.json");
            if let Ok(text) = fs::read_to_string(path)
                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
            {
                execs =
                    execs.saturating_add(v.get("executions").and_then(|x| x.as_u64()).unwrap_or(0));
            }
        }
    }

    let snapshot = MetricsSnapshot {
        executions: execs,
        corpus_count: objects,
        objectives: 0,
        canonical_edges: u32::try_from(edges).unwrap_or(u32::MAX),
        elapsed_ms: 0,
        crash: Default::default(),
    };
    let _ = store.write_metrics(&snapshot);
    let _ = store.append_event(&CampaignEvent::CampaignFinished {
        campaign_id,
        snapshot,
        unix_ms: unix_ms(),
    });

    println!(
        "T2_RESULT workers={} ingested={} admitted={} rejected={} replayed={} edges={} objects={} queue_full=0 execs={} registered={}",
        args.workers,
        objects,
        admitted,
        rejected,
        replayed,
        edges,
        objects,
        execs,
        folded.workers.len()
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
    match (config.max_iters, config.max_time) {
        (Some(iters), None) => {
            fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, mgr, iters)?;
            on_sync(&persist)?;
        }
        (iters, Some(max_time)) => {
            let mut remaining = iters.unwrap_or(u64::MAX);
            while remaining > 0 && start.elapsed() < max_time {
                fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, mgr, 1)?;
                on_sync(&persist)?;
                remaining -= 1;
            }
        }
        (None, None) => anyhow::bail!("worker needs a bound"),
    }
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
