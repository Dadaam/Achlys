# Decision: accept H0 (development experiment)

- Date: 2026-08-16
- Git: `201fea685bc7886d7cc60a24defeeabeeec5796f`
- Platform: macOS aarch64-apple-darwin, rustc 1.97.1
- Decision: **accept H0 on this workload**. Do not start orchestration or ML.

## Context

H0: a LibAFL-based Achlys worker must match behavior and stay within 5% of an equivalent minimal LibAFL baseline. Failure blocks later work.

This is a **development experiment** (5 × 30 s), not a release experiment. The Master Plan reference platform is Linux x86-64; this run is the development host.

## Comparison

| Side | Binary | Loop |
|---|---|---|
| Baseline | `examples/fuzzers/libafl_baseline.rs` | raw LibAFL |
| Achlys | `examples/fuzzers/achlys_h0.rs` | `FuzzerBuilder::run_substrate` |

Same ingredients on both sides: `InProcessExecutor::with_timeout(1s)`, `HitcountsMapObserver` + `StdMapObserver` over the SanCov `EDGES_MAP`, `MaxMapFeedback`, `feedback_or_fast!(Crash, Timeout)`, `InMemoryOnDiskCorpus` + `OnDiskCorpus`, `load_initial_inputs`, `QueueScheduler`, `HavocScheduledMutator` + `havoc_mutations()`, `StdMutationalStage` (default 128), `SimpleEventManager` + `SimpleMonitor`, seed `i` on trial `i`, one seed file `{"a":1}`, `max_input_len=64`, cJSON in-process parse, release profile.

Achlys extras on the measured path: `Target` / `InProcessTarget` hop and an infra `Result` match. No plateau, no AI, no TUI.

## Results

Protocol: `H0_SECONDS=30 H0_TRIALS=5 ./scripts/experiments/h0_throughput.sh`

| trial | seed | baseline exec/s | achlys exec/s | overhead |
|---:|---:|---:|---:|---:|
| 1 | 1 | 779116.22 | 780338.77 | −0.16% |
| 2 | 2 | 776592.28 | 773020.82 | +0.46% |
| 3 | 3 | 767826.16 | 773683.29 | −0.76% |
| 4 | 4 | 781918.48 | 765670.88 | +2.08% |
| 5 | 5 | 781308.00 | 772308.38 | +1.15% |

Mean baseline: **777352.23** exec/s  
Mean Achlys: **773004.43** exec/s  
Mean overhead: **0.559%** ≤ 5% → **H0_PASS**

Corpus sizes matched to ±1 entry per pair. Objectives: 0 / 0. `elapsed_ms=30000` on every run.

Raw TSV (also under `campaigns/h0/results.tsv` on the machine that ran this, gitignored):

```
trial	seed	baseline_execs	baseline_eps	achlys_execs	achlys_eps	overhead
1	1	23373553	779116.22	23410183	780338.77	-0.001569
2	2	23297789	776592.28	23190710	773020.82	0.004599
3	3	23034789	767826.16	23210592	773683.29	-0.007628
4	4	23457603	781918.48	22970192	765670.88	0.020779
5	5	23439263	781308.00	23169252	772308.38	0.011519
```

## Caveats

- Sequential pairing (baseline then Achlys) on a laptop. Trial 4’s 2% swing is noise, not a regression.
- One target (cJSON), one seed, 30 s. Not FuzzBench. Not AFL++.
- Not Level 1: no sanitizer replay, no canonical coverage oracle, no target manifests, CLI is still fork+exec blackbox.

## Expected consequence

Tranche 1 may continue (manifests, canonical replay, sanitizer pipeline, AFL++ column). Tranche 2+ (LLMP, adaptive allocation, ML) stay forbidden until those gates land. H0 must be re-run on Linux x86-64 before any public performance sentence.
