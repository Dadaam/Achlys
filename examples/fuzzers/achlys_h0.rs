//! Achlys H0 worker. Same cJSON / micro harnesses as `libafl_baseline`.

use std::env;
use std::ffi::CString;
use std::fs;
use std::os::raw::{c_char, c_void};
use std::path::PathBuf;
use std::process;
use std::ptr::addr_of_mut;
use std::time::Duration;

use achlys_bridge::{CoverageMap, InProcessTarget};
use achlys_core::FuzzerBuilder;
use libafl::executors::ExitKind;

const MAX_EDGES: usize = 65536;
const MICRO_MAP_LEN: usize = 256;
const DEFAULT_OUT: &str = "./campaigns/h0/achlys";
const DEFAULT_MAX_INPUT_LEN: usize = 64;
const DEFAULT_SECONDS: u64 = 10;
const EXEC_TIMEOUT_MS: u64 = 1000;

static mut MICRO_MAP: [u8; MICRO_MAP_LEN] = [0; MICRO_MAP_LEN];

#[link(name = "cjson_graybox")]
unsafe extern "C" {
    fn cJSON_Parse(value: *const c_char) -> *mut c_void;
    fn cJSON_Delete(c: *mut c_void);

    static mut EDGES_MAP: [u8; MAX_EDGES];
    static mut EDGES_COUNT: std::ffi::c_ulong;
}

#[link(name = "micro_crash_if_magic")]
unsafe extern "C" {
    fn parse(data: *const u8, size: usize) -> i32;
}

struct Args {
    seed: u64,
    iters: Option<u64>,
    seconds: Option<u64>,
    corpus: Option<PathBuf>,
    out: PathBuf,
    max_input_len: usize,
    target: TargetKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Cjson,
    Micro,
}

fn parse_args() -> Args {
    let mut seed = 1u64;
    let mut iters = None;
    let mut seconds = None;
    let mut corpus = None;
    let mut out = PathBuf::from(DEFAULT_OUT);
    let mut max_input_len = DEFAULT_MAX_INPUT_LEN;
    let mut target = TargetKind::Cjson;

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
            "--max-input-len" => {
                max_input_len = need("--max-input-len")
                    .parse()
                    .unwrap_or_else(|_| die("--max-input-len must be usize"));
            }
            "--target" => {
                target = match need("--target").as_str() {
                    "cjson" => TargetKind::Cjson,
                    "micro" => TargetKind::Micro,
                    other => die(&format!("unknown --target {other} (cjson|micro)")),
                };
            }
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
        max_input_len,
        target,
    }
}

fn print_help() {
    eprintln!(
        "achlys_h0 --seed N [--iters N | --seconds N] [--corpus DIR] [--out DIR] \
         [--max-input-len N] [--target cjson|micro]"
    );
}

fn die(msg: &str) -> ! {
    eprintln!("achlys_h0: {msg}");
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
        TargetKind::Micro => (addr_of_mut!(MICRO_MAP) as *mut u8, MICRO_MAP_LEN),
    }
}

fn run_micro(buf: &[u8]) {
    unsafe {
        let _ = parse(buf.as_ptr(), buf.len());
        if let Some(&b) = buf.first() {
            MICRO_MAP[b as usize] = 1;
        }
        if buf.len() >= 4 {
            MICRO_MAP[0] = 1;
        }
    }
}

fn main() {
    let args = parse_args();
    fs::create_dir_all(&args.out)
        .unwrap_or_else(|e| die(&format!("create {}: {e}", args.out.display())));

    let persist_dir = args.out.join("corpus");
    let crashes_dir = args.out.join("crashes");

    let (edges_ptr, edges_len) = coverage_ptr(args.target);

    let target_kind = args.target;
    // SAFETY: chosen map is process-static; harness is single-threaded.
    let target = unsafe {
        InProcessTarget::with_coverage(
            move |buf| {
                match target_kind {
                    TargetKind::Cjson => {
                        if let Ok(c_str) = CString::new(buf) {
                            let p = cJSON_Parse(c_str.as_ptr());
                            if !p.is_null() {
                                cJSON_Delete(p);
                            }
                        }
                    }
                    TargetKind::Micro => run_micro(buf),
                }
                ExitKind::Ok
            },
            CoverageMap::new(edges_ptr, edges_len),
            "edges",
        )
    };

    let mut builder = FuzzerBuilder::new()
        .rng_seed(args.seed)
        .max_input_len(args.max_input_len)
        .crashes_dir(crashes_dir)
        .persist_corpus_dir(persist_dir)
        .exec_timeout(Duration::from_millis(EXEC_TIMEOUT_MS));

    if let Some(dir) = args.corpus {
        builder = builder.corpus_dir(dir);
    }
    if let Some(iters) = args.iters {
        builder = builder.max_iters(iters);
    }
    if let Some(seconds) = args.seconds {
        builder = builder.max_time(Duration::from_secs(seconds));
    }

    builder
        .run_substrate(target)
        .unwrap_or_else(|e| die(&format!("{e:#}")));
}
