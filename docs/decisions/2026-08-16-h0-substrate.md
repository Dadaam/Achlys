# Decision: accept H0 (development experiment)

- Date: 2026-08-16
- Decision: **accept H0 on this workload**. Do not start orchestration or ML.
- Gate: mean overhead ≤ 5% versus an equivalent LibAFL baseline, plus identical corpus *contents* on a fixed-iter pair.

## Context

H0: a LibAFL-based Achlys worker must match behavior and stay within 5% of an equivalent minimal LibAFL baseline. Failure blocks later work.

This is a **development experiment**, not a release experiment. The Master Plan reference platform is Linux x86-64.

## Comparison

| Side | Binary | Loop |
|---|---|---|
| Baseline | `examples/fuzzers/libafl_baseline.rs` | raw LibAFL |
| Achlys | `examples/fuzzers/achlys_h0.rs` | `FuzzerBuilder::run_substrate` |

Same ingredients: `InProcessExecutor::with_timeout(1s)`, `HitcountsMapObserver` + `StdMapObserver` over SanCov `EDGES_MAP`, `MaxMapFeedback`, `feedback_or_fast!(Crash, Timeout)`, `InMemoryOnDiskCorpus` + `OnDiskCorpus`, `load_initial_inputs`, `QueueScheduler`, `HavocScheduledMutator` + `havoc_mutations()`, `StdMutationalStage` (default 128), `SimpleEventManager` + **`NopMonitor`**, one seed file `{"a":1}`, `max_input_len=64`, cJSON in-process parse, release profile.

Achlys extras on the measured path: `Target` / `InProcessTarget` hop and an infra `Result` match. No plateau, no AI, no TUI.

## Functional pair (stronger than “corpus ±1”)

- seed `4242`, `--iters 1000`, both sides
- **150** corpus file contents, identical SHA-256 **hash for hash**
- script fails the gate on any set difference (`H0_FUNCTIONAL`)

## Timed ladder (quiet monitor, warmup, AB/BA)

Protocol: `H0_SECONDS=30 H0_TRIALS=5 H0_WARMUP_SECONDS=3 H0_ORDER=abba`

Raw bundle: [`docs/evidence/h0/2026-08-16-macos-aarch64/`](../evidence/h0/2026-08-16-macos-aarch64/)

| trial | seed | order | baseline exec/s | achlys exec/s | overhead |
|---:|---:|:---:|---:|---:|---:|
| 1 | 1 | AB | 821305.11 | 804583.24 | +2.04% |
| 2 | 2 | BA | 805378.63 | 799904.37 | +0.68% |
| 3 | 3 | AB | 801489.98 | 796722.86 | +0.59% |
| 4 | 4 | BA | 808577.23 | 799002.44 | +1.18% |
| 5 | 5 | AB | 807094.00 | 799088.94 | +0.99% |

- mean overhead (point estimate): **1.10%**
- median: **0.99%**
- range: **0.59% .. 2.04%**
- descriptive t 95% interval (n=5): **0.38% .. 1.81%**

`H0_PASS`: the mean is below 5%. No trial exceeded 5%.

Stdout per 30 s run is a single `H0_RESULT` line (no Client Heartbeat).

The 2.04% swing on trial 1 is **compatible with machine noise**, but its cause was not isolated.

Do not treat 1.10% as a precise two-decimal constant. The robust claim is: **overhead is low and under 5% on this workload**.

## Earlier verbose sequential run (not the gate)

First development pair used `SimpleMonitor` (≈512 MB / 3.6 M heartbeat lines across ten runs) and always ran baseline then Achlys. Both sides paid that cost, so the comparison was still symmetric, but the common cost can shrink a percentage. TSV kept under [`docs/evidence/h0/2026-08-16-macos-aarch64-verbose-sequential/`](../evidence/h0/2026-08-16-macos-aarch64-verbose-sequential/). Mean overhead there was about 0.55%. That run is historical, not the protocol going forward.

## Caveats

- n=5 on a laptop. Linux x86-64 release evidence is still required before a public performance sentence.
- One target (cJSON), one seed family, 30 s. Not FuzzBench. Not AFL++.
- Not Level 1: no sanitizer replay, no canonical coverage oracle, no target manifests, CLI is still fork+exec blackbox.

## Expected consequence

Tranche 1 baseline infrastructure is accepted
([`2026-08-16-t1-baseline-accepted.md`](2026-08-16-t1-baseline-accepted.md)).
Tranche 2 implementation is open
([`2026-08-16-t2-homogeneous.md`](2026-08-16-t2-homogeneous.md)).
T2 is not accepted. T3+, adaptive allocation, and ML stay forbidden.
The Linux multi-trial ladder is defined in the T2 decision and must
run before any T2 exit-gate claim.
