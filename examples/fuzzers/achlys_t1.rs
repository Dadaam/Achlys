//! Tranche 1 campaign: the manifest selects the harness, then substrate,
//! content-addressed store, independent canonical dump, and sanitizer verify.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::ptr::addr_of_mut;
use std::time::Duration;

use achlys_bridge::{
    CoverageMap, DumpOracle, InProcessTarget, ReplayClass, SanitizerReplayer, WorkerTarget,
    compile_canonical, compile_sanitizer, dedup_key,
};
use achlys_core::{CampaignSession, CanonicalReport, FuzzerBuilder};
use achlys_protocol::{
    BuildId, BuildIdentity, BuildKind, CampaignEvent, CampaignId, CampaignRecord, CrashStats,
    InputId, MetricsSnapshot, TargetManifest,
};
use libafl::executors::ExitKind;

const MAX_EDGES: usize = 65536;
const MICRO_MAP_LEN: usize = 256;
const DEFAULT_OUT: &str = "./campaigns/t1";
const DEFAULT_MANIFEST: &str = "benchmarks/manifests/cjson-parse.toml";
const DEFAULT_SECONDS: u64 = 10;
const EXTRA_IDENTITY: &[&str] = &[
    "rust-toolchain.toml",
    "Cargo.lock",
    "build.rs",
    "examples/fuzzers/achlys_t1.rs",
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

struct Args {
    seed: u64,
    iters: Option<u64>,
    seconds: Option<u64>,
    corpus: Option<PathBuf>,
    out: PathBuf,
    manifest: PathBuf,
    label: String,
}

fn parse_args() -> Args {
    let mut seed = 1u64;
    let mut iters = None;
    let mut seconds = None;
    let mut corpus = None;
    let mut out = PathBuf::from(DEFAULT_OUT);
    let mut manifest = PathBuf::from(DEFAULT_MANIFEST);
    let mut label = "t1".to_string();

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
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            other => die(&format!("unknown argument: {other}")),
        }
    }

    if iters.is_some() && seconds.is_some() {
        die("--iters and --seconds are mutually exclusive");
    }
    if iters.is_none() && seconds.is_none() {
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
    }
}

fn print_help() {
    eprintln!(
        "achlys_t1 --manifest PATH [--label NAME] --seed N [--iters N | --seconds N] \
         [--corpus DIR] [--out DIR]"
    );
}

fn die(msg: &str) -> ! {
    eprintln!("achlys_t1: {msg}");
    process::exit(2);
}

fn is_sidecar(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.starts_with('.') || name.ends_with(".metadata")
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
            "--out {} is not empty; reuse is forbidden (pick a new directory)",
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

fn list_regular_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && !is_sidecar(p))
        .collect();
    files.sort();
    files
}

fn ingest_crashes(
    session: &CampaignSession,
    dir: &Path,
    producer_build: BuildId,
) -> (usize, usize, Vec<(InputId, Vec<u8>)>) {
    let mut unique = HashSet::new();
    let mut items = Vec::new();
    for path in list_regular_files(dir) {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        let id = InputId::from_bytes(&bytes);
        if let Ok(stored) = session.store().put_crash(&bytes)
            && unique.insert(stored)
        {
            let _ = session
                .store()
                .append_event(&CampaignEvent::CrashDiscovered {
                    campaign_id: session.store().campaign_id(),
                    input_id: stored,
                    producer_build,
                    unix_ms: unix_ms(),
                });
            items.push((stored, bytes));
        }
        let _ = id;
    }
    (list_regular_files(dir).len(), unique.len(), items)
}

fn verify_crashes(
    session: &CampaignSession,
    candidates: &[(InputId, Vec<u8>)],
    sanitizer_id: BuildId,
    binary: &Path,
    timeout: Duration,
) -> Result<CrashStats, String> {
    let mut stats = CrashStats {
        candidates: candidates.len(),
        unique_candidates: candidates.len(),
        ..CrashStats::default()
    };
    if candidates.is_empty() {
        return Ok(stats);
    }
    let replayer = SanitizerReplayer::new(binary).with_timeout(timeout);
    let mut signatures = HashSet::new();
    for (id, bytes) in candidates {
        stats.replays_attempted += 1;
        let report = replayer
            .replay(bytes)
            .map_err(|err| format!("sanitizer infra: {err}"))?;
        match report.class {
            ReplayClass::ReproducibleCrash => {
                stats.reproduced_crashes += 1;
                if let Some(sig) = &report.stack_signature {
                    signatures.insert(sig.clone());
                } else {
                    signatures.insert(dedup_key(&report));
                }
            }
            ReplayClass::Clean => stats.clean_replays += 1,
            ReplayClass::Timeout => stats.timeouts += 1,
            ReplayClass::InfraFailure => stats.infra_failures += 1,
        }
        session
            .store()
            .append_event(&CampaignEvent::CrashVerified {
                campaign_id: session.store().campaign_id(),
                input_id: *id,
                class: format!("{:?}", report.class),
                stack_signature: report.stack_signature.clone(),
                dedup_key: dedup_key(&report),
                sanitizer_build: sanitizer_id,
                reproducible: report.class == ReplayClass::ReproducibleCrash,
                unix_ms: unix_ms(),
            })
            .map_err(|e| format!("event: {e:#}"))?;
    }
    stats.unique_crash_signatures = signatures.len();
    Ok(stats)
}

fn fingerprint_git(root: &Path) -> (String, u32) {
    let sha = Command::new("git")
        .args(["-C", &root.display().to_string(), "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let dirty = Command::new("git")
        .args(["-C", &root.display().to_string(), "status", "--porcelain"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty() && !l.starts_with("??"))
                .count() as u32
        })
        .unwrap_or(0);
    (sha, dirty)
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

fn main() {
    let args = parse_args();
    let root = workspace_root();
    let manifest_path = if args.manifest.is_absolute() {
        args.manifest.clone()
    } else {
        root.join(&args.manifest)
    };
    let manifest = TargetManifest::from_path(&manifest_path)
        .unwrap_or_else(|e| die(&format!("manifest {}: {e}", manifest_path.display())));

    if manifest.input_mode != achlys_protocol::InputMode::Inprocess {
        die("achlys_t1 only runs in-process manifests in this tranche");
    }

    let kind = WorkerTarget::parse(&manifest.target_id).unwrap_or_else(|e| die(&e.to_string()));
    if kind.as_str() != manifest.target_id {
        die("internal target id mismatch");
    }

    require_fresh(&args.out);

    let exe = env::current_exe().unwrap_or_else(|e| die(&format!("current_exe: {e}")));
    let fast = BuildIdentity::from_executed(
        &manifest,
        BuildKind::Fast,
        &root,
        EXTRA_IDENTITY,
        Some(&exe),
    )
    .unwrap_or_else(|e| die(&format!("fast identity: {e}")));

    fs::create_dir_all(&args.out)
        .unwrap_or_else(|e| die(&format!("create {}: {e}", args.out.display())));

    let artifacts = args.out.join("artifacts");
    let worker = args.out.join("worker");
    let persist_dir = worker.join("corpus");
    let crashes_dir = worker.join("crashes");
    let measure_dir = args.out.join("builds");

    let canonical = compile_canonical(
        &root,
        &manifest,
        &measure_dir.join("canonical"),
        EXTRA_IDENTITY,
    )
    .unwrap_or_else(|e| die(&format!("canonical compile: {e:#}")));
    let sanitizer = compile_sanitizer(
        &root,
        &manifest,
        &measure_dir.join("sanitizer"),
        EXTRA_IDENTITY,
    )
    .unwrap_or_else(|e| die(&format!("sanitizer compile: {e:#}")));

    let (git, dirty) = fingerprint_git(&root);
    let record = CampaignRecord {
        schema_version: CampaignEvent::SCHEMA_VERSION,
        campaign_id: CampaignId::from_label(&format!(
            "{}-{}-{}",
            args.label, manifest.target_id, args.seed
        )),
        target_id: manifest.target_id.clone(),
        label: args.label.clone(),
        seed: args.seed,
        max_iters: args.iters,
        max_seconds: args.seconds,
        max_input_len: manifest.max_input_len,
        timeout_ms: manifest.timeout_ms,
        tool: "achlys_t1".into(),
        host: format!("{} {}", env::consts::OS, env::consts::ARCH),
        rustc: rustc_version(),
        git,
        git_dirty: dirty,
        fast_build: fast.clone(),
        canonical_build: Some(canonical.identity.clone()),
        sanitizer_build: Some(sanitizer.identity.clone()),
        started_unix_ms: unix_ms(),
    };

    let session = CampaignSession::begin(&artifacts, &manifest, &record)
        .unwrap_or_else(|e| die(&format!("campaign begin: {e:#}")));

    let target = worker_target(kind);
    let mut builder = FuzzerBuilder::new()
        .rng_seed(args.seed)
        .max_input_len(manifest.max_input_len)
        .crashes_dir(&crashes_dir)
        .persist_corpus_dir(&persist_dir)
        .exec_timeout(Duration::from_millis(manifest.timeout_ms.max(1)));

    if let Some(dir) = args.corpus {
        builder = builder.corpus_dir(dir);
    }
    if let Some(iters) = args.iters {
        builder = builder.max_iters(iters);
    }
    if let Some(seconds) = args.seconds {
        builder = builder.max_time(Duration::from_secs(seconds));
    }

    let report = builder
        .run_substrate(target)
        .unwrap_or_else(|e| die(&format!("substrate: {e:#}")));

    let ingested = session
        .ingest_worker_dir(&persist_dir, "havoc-substrate", fast.build_id)
        .unwrap_or_else(|e| die(&format!("ingest corpus: {e:#}")));
    let (crash_files, unique_crashes, crash_items) =
        ingest_crashes(&session, &crashes_dir, fast.build_id);
    let crash = verify_crashes(
        &session,
        &crash_items,
        sanitizer.identity.build_id,
        &sanitizer.path,
        Duration::from_millis(manifest.timeout_ms.max(1)),
    )
    .unwrap_or_else(|e| die(&e));
    let mut crash = crash;
    crash.candidates = crash_files;
    crash.unique_candidates = unique_crashes;

    let mut oracle = DumpOracle::new(&canonical.path, canonical.identity.build_id)
        .unwrap_or_else(|e| die(&format!("oracle: {e:#}")));

    let mut admitted = 0usize;
    let mut rejected = 0usize;
    let mut replayed = 0usize;
    let ids = session
        .store()
        .list_inputs()
        .unwrap_or_else(|e| die(&format!("list inputs: {e:#}")));
    for id in &ids {
        let bytes = session
            .store()
            .get_input(id)
            .unwrap_or_else(|e| die(&format!("read {id}: {e:#}")));
        let admission = oracle
            .replay(&bytes)
            .unwrap_or_else(|e| die(&format!("replay {id}: {e}")));
        replayed += 1;
        let ev = if admission.admitted {
            admitted += 1;
            CampaignEvent::CanonicalAdmitted {
                campaign_id: session.store().campaign_id(),
                input_id: *id,
                digest: admission.digest,
                new_edges: admission.new_edges,
                total_edges: admission.total_edges,
                canonical_build: canonical.identity.build_id,
                unix_ms: unix_ms(),
            }
        } else {
            rejected += 1;
            CampaignEvent::CanonicalRejected {
                campaign_id: session.store().campaign_id(),
                input_id: *id,
                digest: admission.digest,
                canonical_build: canonical.identity.build_id,
                unix_ms: unix_ms(),
            }
        };
        session
            .store()
            .append_event(&ev)
            .unwrap_or_else(|e| die(&format!("event: {e:#}")));
    }

    let oracle_report = oracle.report(admitted, rejected, replayed);
    session
        .store()
        .write_canonical_report(&CanonicalReport {
            digest: oracle_report.digest,
            edge_count: oracle_report.edge_count,
            admitted: oracle_report.admitted,
            rejected: oracle_report.rejected,
            replayed: oracle_report.replayed,
            canonical_build: canonical.identity.build_id,
            artifact_hash: canonical.identity.artifact_hash.clone(),
        })
        .unwrap_or_else(|e| die(&format!("canonical report: {e:#}")));

    let snapshot = MetricsSnapshot {
        executions: report.executions,
        corpus_count: report.corpus_count,
        objectives: report.objectives,
        canonical_edges: oracle_report.edge_count,
        elapsed_ms: u64::try_from(report.elapsed.as_millis()).unwrap_or(u64::MAX),
        crash: crash.clone(),
    };
    session
        .finish(snapshot)
        .unwrap_or_else(|e| die(&format!("finish: {e:#}")));

    println!(
        "T1_RESULT target={} execs={} corpus={} ingested={} replayed={} admitted={} rejected={} edges={} digest={} crash_files={} unique_candidates={} replays={} reproduced={} unique_sigs={} clean={} timeouts={} infra={} canonical_build={}",
        manifest.target_id,
        report.executions,
        report.corpus_count,
        ingested,
        oracle_report.replayed,
        oracle_report.admitted,
        oracle_report.rejected,
        oracle_report.edge_count,
        oracle_report.digest.to_hex(),
        crash.candidates,
        crash.unique_candidates,
        crash.replays_attempted,
        crash.reproduced_crashes,
        crash.unique_crash_signatures,
        crash.clean_replays,
        crash.timeouts,
        crash.infra_failures,
        canonical.identity.build_id.to_hex()
    );
}
