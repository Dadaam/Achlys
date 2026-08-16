//! Tranche 1 single-worker campaign: manifest → substrate → store → canonical replay.
//!
//! The hot loop is still `FuzzerBuilder::run_substrate` (H0). Canonical
//! admission and artifact writes happen after the worker stops.

use std::env;
use std::ffi::CString;
use std::fs;
use std::os::raw::{c_char, c_void};
use std::path::{Path, PathBuf};
use std::process;
use std::ptr::addr_of_mut;
use std::time::Duration;

use achlys_bridge::{
    CanonicalOracle, CoverageMap, InProcessTarget, ReplayClass, SanitizerReplayer, dedup_key,
};
use achlys_core::{CampaignSession, CanonicalReport, FuzzerBuilder};
use achlys_protocol::{
    BuildId, BuildIdentity, BuildKind, CampaignEvent, MetricsSnapshot, TargetManifest,
};
use libafl::executors::ExitKind;

const MAX_EDGES: usize = 65536;
const DEFAULT_OUT: &str = "./campaigns/t1";
const DEFAULT_MANIFEST: &str = "benchmarks/manifests/cjson-parse.toml";
const DEFAULT_SECONDS: u64 = 10;

#[link(name = "cjson_graybox")]
unsafe extern "C" {
    fn cJSON_Parse(value: *const c_char) -> *mut c_void;
    fn cJSON_Delete(c: *mut c_void);

    static mut EDGES_MAP: [u8; MAX_EDGES];
    static mut EDGES_COUNT: std::ffi::c_ulong;
}

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
    let mut label = "t1-cjson".to_string();

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

fn coverage_ptr() -> (*mut u8, usize) {
    unsafe {
        let count = if EDGES_COUNT > 0 {
            EDGES_COUNT as usize
        } else {
            MAX_EDGES
        };
        (addr_of_mut!(EDGES_MAP) as *mut u8, count)
    }
}

fn cjson_target() -> InProcessTarget {
    let (edges_ptr, edges_len) = coverage_ptr();
    // SAFETY: EDGES_MAP is process-static; this campaign is single-threaded.
    unsafe {
        InProcessTarget::with_coverage(
            move |buf| {
                if let Ok(c_str) = CString::new(buf) {
                    let p = cJSON_Parse(c_str.as_ptr());
                    if !p.is_null() {
                        cJSON_Delete(p);
                    }
                }
                ExitKind::Ok
            },
            CoverageMap::new(edges_ptr, edges_len),
            "edges",
        )
    }
}

fn ingest_crashes(session: &CampaignSession, dir: &Path, producer_build: BuildId) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut n = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() || is_sidecar(&path) {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        if let Ok(id) = session.store().put_crash(&bytes) {
            let _ = session
                .store()
                .append_event(&CampaignEvent::CrashDiscovered {
                    campaign_id: session.store().campaign_id(),
                    input_id: id,
                    producer_build,
                    unix_ms: unix_ms(),
                });
            n += 1;
        }
    }
    n
}

fn verify_crashes(session: &CampaignSession, dir: &Path, asan_dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && !is_sidecar(p))
        .collect();
    if files.is_empty() {
        return 0;
    }
    let bin = match SanitizerReplayer::compile_cjson(asan_dir) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("achlys_t1: sanitizer compile skipped: {err:#}");
            return 0;
        }
    };
    let replayer = SanitizerReplayer::new(bin).with_timeout(Duration::from_secs(5));
    let mut verified = 0usize;
    for path in files {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        let id = achlys_protocol::InputId::from_bytes(&bytes);
        let (class, signature, reproducible) = match replayer.replay(&bytes) {
            Ok(report) => {
                let repro = report.class == ReplayClass::ReproducibleCrash;
                (
                    format!("{:?}", report.class),
                    Some(dedup_key(&report)),
                    repro,
                )
            }
            Err(err) => (format!("InfraFailure:{err}"), None, false),
        };
        if session
            .store()
            .append_event(&CampaignEvent::CrashVerified {
                campaign_id: session.store().campaign_id(),
                input_id: id,
                class,
                stack_signature: signature,
                reproducible,
                unix_ms: unix_ms(),
            })
            .is_ok()
        {
            verified += 1;
        }
    }
    verified
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

    let max_input_len = manifest.max_input_len;
    let exec_timeout = Duration::from_millis(manifest.timeout_ms.max(1));

    let build = BuildIdentity::from_manifest(&manifest, BuildKind::Fast, &root)
        .unwrap_or_else(|e| die(&format!("build identity: {e}")));

    fs::create_dir_all(&args.out)
        .unwrap_or_else(|e| die(&format!("create {}: {e}", args.out.display())));

    let artifacts = args.out.join("artifacts");
    let worker = args.out.join("worker");
    let persist_dir = worker.join("corpus");
    let crashes_dir = worker.join("crashes");

    let session = CampaignSession::begin(&artifacts, &args.label, &manifest, &build)
        .unwrap_or_else(|e| die(&format!("campaign begin: {e:#}")));

    let target = cjson_target();
    let mut builder = FuzzerBuilder::new()
        .rng_seed(args.seed)
        .max_input_len(max_input_len)
        .crashes_dir(&crashes_dir)
        .persist_corpus_dir(&persist_dir)
        .exec_timeout(exec_timeout);

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
        .ingest_worker_dir(&persist_dir, "havoc-substrate", build.build_id)
        .unwrap_or_else(|e| die(&format!("ingest corpus: {e:#}")));
    let crash_n = ingest_crashes(&session, &crashes_dir, build.build_id);
    let verified_n = verify_crashes(&session, &crashes_dir, &args.out.join("asan"));

    // Worker target dropped; reuse the same SanCov map for independent replay.
    let mut oracle =
        CanonicalOracle::new(cjson_target()).unwrap_or_else(|e| die(&format!("oracle: {e:#}")));

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
                unix_ms: unix_ms(),
            }
        } else {
            rejected += 1;
            CampaignEvent::CanonicalRejected {
                campaign_id: session.store().campaign_id(),
                input_id: *id,
                digest: admission.digest,
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
        })
        .unwrap_or_else(|e| die(&format!("canonical report: {e:#}")));

    let snapshot = MetricsSnapshot {
        executions: report.executions,
        corpus_count: report.corpus_count,
        objectives: report.objectives,
        canonical_edges: oracle_report.edge_count,
        elapsed_ms: u64::try_from(report.elapsed.as_millis()).unwrap_or(u64::MAX),
    };
    session
        .finish(snapshot.clone())
        .unwrap_or_else(|e| die(&format!("finish: {e:#}")));

    println!(
        "T1_RESULT execs={} corpus={} ingested={} crashes={} verified={} replayed={} admitted={} rejected={} edges={} digest={}",
        report.executions,
        report.corpus_count,
        ingested,
        crash_n,
        verified_n,
        oracle_report.replayed,
        oracle_report.admitted,
        oracle_report.rejected,
        oracle_report.edge_count,
        oracle_report.digest.to_hex()
    );
}
