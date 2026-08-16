//! Independent canonical coverage replay. Same cJSON / SanCov map as H0.
//! Does not fuzz: published coverage comes from this replay only.

use std::env;
use std::ffi::CString;
use std::fs;
use std::os::raw::{c_char, c_void};
use std::path::{Path, PathBuf};
use std::process;
use std::ptr::addr_of_mut;

use achlys_bridge::{CanonicalOracle, CoverageMap, InProcessTarget};
use libafl::executors::ExitKind;

const MAX_EDGES: usize = 65536;

#[link(name = "cjson_graybox")]
unsafe extern "C" {
    fn cJSON_Parse(value: *const c_char) -> *mut c_void;
    fn cJSON_Delete(c: *mut c_void);

    static mut EDGES_MAP: [u8; MAX_EDGES];
    static mut EDGES_COUNT: std::ffi::c_ulong;
}

struct Args {
    corpus: PathBuf,
    out: Option<PathBuf>,
    target: TargetKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Cjson,
}

fn parse_args() -> Args {
    let mut corpus = None;
    let mut out = None;
    let mut target = TargetKind::Cjson;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut need = |name: &str| {
            args.next()
                .unwrap_or_else(|| die(&format!("{name} requires a value")))
        };
        match arg.as_str() {
            "--corpus" => corpus = Some(PathBuf::from(need("--corpus"))),
            "--out" => out = Some(PathBuf::from(need("--out"))),
            "--target" => {
                target = match need("--target").as_str() {
                    "cjson" => TargetKind::Cjson,
                    other => die(&format!("unknown --target {other} (cjson)")),
                };
            }
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            other => die(&format!("unknown argument: {other}")),
        }
    }

    let Some(corpus) = corpus else {
        die("--corpus DIR is required");
    };

    Args {
        corpus,
        out,
        target,
    }
}

fn print_help() {
    eprintln!("achlys_oracle --corpus DIR [--out FILE] [--target cjson]");
}

fn die(msg: &str) -> ! {
    eprintln!("achlys_oracle: {msg}");
    process::exit(2);
}

fn coverage_ptr(kind: TargetKind) -> (*mut u8, usize) {
    match kind {
        TargetKind::Cjson => unsafe {
            let count = if EDGES_COUNT > 0 {
                EDGES_COUNT as usize
            } else {
                MAX_EDGES
            };
            (addr_of_mut!(EDGES_MAP) as *mut u8, count)
        },
    }
}

fn list_corpus(dir: &Path) -> Vec<PathBuf> {
    if !dir.is_dir() {
        die(&format!("corpus is not a directory: {}", dir.display()));
    }
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| die(&format!("read {}: {e}", dir.display())));
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| match entry {
            Ok(e) => {
                let path = e.path();
                path.is_file().then_some(path)
            }
            Err(e) => die(&format!("read {}: {e}", dir.display())),
        })
        .collect();
    files.sort();
    files
}

fn main() {
    let args = parse_args();
    let files = list_corpus(&args.corpus);

    let (edges_ptr, edges_len) = coverage_ptr(args.target);
    let harness = move |buf: &[u8]| {
        if let Ok(c_str) = CString::new(buf) {
            // SAFETY: cJSON_Parse/Delete are the in-process harness contract.
            unsafe {
                let p = cJSON_Parse(c_str.as_ptr());
                if !p.is_null() {
                    cJSON_Delete(p);
                }
            }
        }
        ExitKind::Ok
    };
    // SAFETY: EDGES_MAP is process-static; replay is single-threaded.
    let target = unsafe {
        InProcessTarget::with_coverage(harness, CoverageMap::new(edges_ptr, edges_len), "edges")
    };

    let mut oracle =
        CanonicalOracle::new(target).unwrap_or_else(|e| die(&format!("oracle: {e:#}")));

    let mut admitted = 0usize;
    let mut rejected = 0usize;
    let mut replayed = 0usize;

    for path in &files {
        let bytes =
            fs::read(path).unwrap_or_else(|e| die(&format!("read {}: {e}", path.display())));
        let admission = oracle
            .replay(&bytes)
            .unwrap_or_else(|e| die(&format!("replay {}: {e}", path.display())));
        replayed += 1;
        if admission.admitted {
            admitted += 1;
        } else {
            rejected += 1;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unnamed>");
        println!(
            "ORACLE_INPUT file={name} admitted={} new_edges={} total_edges={} digest={} exit={:?}",
            admission.admitted,
            admission.new_edges,
            admission.total_edges,
            admission.digest.to_hex(),
            admission.exit
        );
    }

    let report = oracle.report(admitted, rejected, replayed);
    println!(
        "ORACLE_RESULT replayed={} admitted={} rejected={} edges={} digest={}",
        report.replayed,
        report.admitted,
        report.rejected,
        report.edge_count,
        report.digest.to_hex()
    );

    if let Some(out) = args.out {
        let body = serde_json::json!({
            "replayed": report.replayed,
            "admitted": report.admitted,
            "rejected": report.rejected,
            "edges": report.edge_count,
            "digest": report.digest.to_hex(),
        });
        if let Some(parent) = out.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&out, format!("{body}\n"))
            .unwrap_or_else(|e| die(&format!("write {}: {e}", out.display())));
    }
}
