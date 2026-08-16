//! Minimal LibAFL graybox worker. Same hot-loop ingredients as `achlys_h0`.

use std::env;
use std::ffi::CString;
use std::fs;
use std::num::NonZero;
use std::os::raw::{c_char, c_void};
use std::path::PathBuf;
use std::process;
use std::ptr::addr_of_mut;
use std::time::{Duration, Instant};

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

const MAX_EDGES: usize = 65536;
const MICRO_MAP_LEN: usize = 256;
const DEFAULT_OUT: &str = "./campaigns/h0/baseline";
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
        "libafl_baseline --seed N [--iters N | --seconds N] [--corpus DIR] [--out DIR] \
         [--max-input-len N] [--target cjson|micro]"
    );
}

fn die(msg: &str) -> ! {
    eprintln!("libafl_baseline: {msg}");
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

fn print_h0_result(executions: u64, elapsed: Duration, corpus_count: usize, objectives: usize) {
    let elapsed_ms = elapsed.as_millis();
    let exec_per_sec = if elapsed.as_secs_f64() > 0.0 {
        executions as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    println!(
        "H0_RESULT execs={executions} elapsed_ms={elapsed_ms} corpus={corpus_count} \
         objectives={objectives} exec_per_sec={exec_per_sec:.2}"
    );
}

fn main() {
    let args = parse_args();
    fs::create_dir_all(&args.out)
        .unwrap_or_else(|e| die(&format!("create {}: {e}", args.out.display())));

    let persist_dir = args.out.join("corpus");
    let crashes_dir = args.out.join("crashes");

    let (edges_ptr, edges_len) = coverage_ptr(args.target);

    // SAFETY: EDGES_MAP is process-static and the fuzzer is single-threaded.
    let observer = HitcountsMapObserver::new(unsafe {
        StdMapObserver::from_mut_ptr("edges", edges_ptr, edges_len)
    });

    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    let mut state = StdState::new(
        StdRand::with_seed(args.seed),
        InMemoryOnDiskCorpus::<BytesInput>::new(&persist_dir).expect("persistent corpus"),
        OnDiskCorpus::new(&crashes_dir).expect("crashes corpus"),
        &mut feedback,
        &mut objective,
    )
    .expect("state");
    state.set_max_size(args.max_input_len.max(1));

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let target = args.target;
    let mut harness = move |input: &BytesInput| {
        let buf = input.target_bytes();
        let buf = buf.as_slice();
        match target {
            TargetKind::Cjson => {
                if let Ok(c_str) = CString::new(buf) {
                    unsafe {
                        let p = cJSON_Parse(c_str.as_ptr());
                        if !p.is_null() {
                            cJSON_Delete(p);
                        }
                    }
                }
            }
            TargetKind::Micro => run_micro(buf),
        }
        ExitKind::Ok
    };

    let mon = NopMonitor::new();
    let mut mgr = SimpleEventManager::new(mon);

    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_millis(EXEC_TIMEOUT_MS),
    )
    .expect("executor");

    if let Some(ref corpus_dir) = args.corpus {
        state
            .load_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut mgr,
                std::slice::from_ref(corpus_dir),
            )
            .unwrap_or_else(|e| die(&format!("load seeds from {}: {e}", corpus_dir.display())));
    } else {
        let mut generator = RandBytesGenerator::new(
            NonZero::new(args.max_input_len).unwrap_or(NonZero::new(64).expect("64")),
        );
        state
            .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
            .expect("generate initial inputs");
    }

    if state.corpus().count() == 0 {
        die("no initial inputs were admitted (empty seeds or no novelty)");
    }

    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let start = Instant::now();
    match (args.iters, args.seconds) {
        (Some(iters), None) => {
            fuzzer
                .fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, iters)
                .expect("fuzz loop");
        }
        (None, Some(seconds)) => {
            let max_time = Duration::from_secs(seconds);
            while start.elapsed() < max_time {
                fuzzer
                    .fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1)
                    .expect("fuzz loop");
            }
        }
        _ => unreachable!("iters XOR seconds"),
    }

    let elapsed = start.elapsed();
    print_h0_result(
        *state.executions(),
        elapsed,
        state.corpus().count(),
        state.solutions().count(),
    );
}
