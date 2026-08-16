# Achlys — Current Architecture

This note describes the **implemented** prototype only.

The target architecture, hypotheses (H0–H5), non-goals, and build order live in [`MASTER_PLAN.md`](MASTER_PLAN.md). **See the Master Plan for target architecture.** If the two documents conflict, the Master Plan wins.

Achlys is not a 4-stage product that escalates havoc → AI → symbolic execution. That framing is not implemented and is not the research direction.

Status: **Level 0** (buildable prototype). Public positioning until evidence exists:

> Achlys is an experimental cooperative fuzzing system built on LibAFL. It investigates whether typed cross-strategy assistance and cost-aware worker allocation can improve coverage and hard-branch discovery under equal resource budgets.

## Layout

```
Achlys/
├── Cargo.toml                 # workspace + root package (examples / cJSON build.rs)
├── build.rs                   # compiles vendored cJSON + micro target
├── src/
│   ├── protocol/              # achlys-protocol — manifests, IDs, campaign events (no LibAFL)
│   ├── cli/                   # achlys-cli  — `achlys fuzz`
│   ├── core/                  # achlys-core — FuzzerBuilder + campaign store
│   ├── bridge/                # achlys-bridge — Target, oracle, sanitizer replay
│   └── cortex/                # achlys-cortex — experimental ONNX / trainer (not H0)
├── examples/fuzzers/          # hand-wired LibAFL examples
├── benchmarks/manifests/      # versioned target manifests
└── examples/targets/cJSON     # vendored DaveGamble/cJSON v1.7.18 + SanCov callbacks
```

| Crate | What it actually does today |
|---|---|
| **achlys-protocol** | Target manifests, `BuildIdentity`, content-addressed `InputId`, campaign JSONL events. No LibAFL. |
| **achlys-cli** | Parses flags, always constructs `ForkExecTarget`, runs `FuzzerBuilder`, optional ratatui TUI. `--source` is rejected. |
| **achlys-core** | `FuzzerBuilder` wraps LibAFL havoc. `run()` is the CLI path (blackbox). `run_substrate()` is the H0/T1 in-process graybox worker. `CampaignStore` / `CampaignSession` write post-campaign artifacts. |
| **achlys-bridge** | `ForkExecTarget` (CLI): spawn binary, stdin or `@@`. `InProcessTarget` used by H0/T1. `DumpOracle` replays a separately compiled canonical dump binary. `SanitizerReplayer` verifies crashes off the hot path. |
| **achlys-cortex** | ONNX load, `AutoTrainer`, `HotSwapCortex`. Experimental. Not on the H0/T1 path. |

There is no QEMU backend, no network target, no symbolic engine, no orchestrator, and no multi-worker control plane. Canonical replay and sanitizer verification run **after** a worker campaign, not once per execution.

## CLI execution path

```
achlys fuzz <binary> [args]
        │
        ├─ --source …  → error (SanCov child coverage is not transported)
        │
        └─ otherwise   → ForkExecTarget(user binary)
                              │
                              ▼
                     FuzzerBuilder::run
                              │
                     ForkExecTarget::coverage_map() is None
                              │
                              ▼
                     FuzzerBuilder::run_blackbox
                              │
              InProcessExecutor around a harness that
              calls target.execute() → fork+exec the child
                              │
              ConstFeedback(false) + CrashFeedback
              HavocScheduledMutator / havoc_mutations()
```

`achlys fuzz` never constructs `InProcessTarget`. There is no coverage-guided CLI campaign.

`--source` is rejected. SanCov in a child process is not graybox (Master Plan §24.1).

## Corpus and results

- CLI queue: `InMemoryCorpus`. Seeds are read from `--corpus` once. New queue entries are not written back to that directory.
- H0 queue: `InMemoryOnDiskCorpus` under the example `--out` directory.
- Crashes: `OnDiskCorpus` under `--output` / `--out`.
- Blackbox admission: `ConstFeedback(false)` — seeds and crashes only. No novelty signal.
- `ForkExecTarget` returns `Err(InfraError)` on missing binary, spawn, write, and wait failures.

## Unused or disconnected pieces

These types exist. They are not a working product surface:

- **`FuzzerBuilder::run_graybox`.** Plateau-wrapped graybox. H0 uses `run_substrate` instead. The CLI never hits this path.
- **`EscalatingStage`, `PlateauDetector`, `AiMutator`, `HybridStage`.** Wired when a `CortexInterface` is supplied (`--model`). Not on the H0 path.
- **`AutoTrainer`.** Not started. The live corpus is still in-memory on the CLI path.
- **TUI.** Displays LibAFL monitor stats. It does not implement a campaign control plane.

## Examples

| Example | What it is |
|---|---|
| `simple_fuzzer` | In-process toy with a hand-written `SIGNALS` map. |
| `cjson_blackbox_fuzzer` | In-process cJSON via FFI; `ConstFeedback(true)`. |
| `cjson_graybox_fuzzer` | In-process cJSON + SanCov `EDGES_MAP` + `MaxMapFeedback`. |
| `libafl_baseline` / `achlys_h0` | H0 paired workers. Same LibAFL loop; Achlys adds `Target`. |
| `achlys_oracle` | Independent canonical replay of a corpus directory. Does not fuzz. |
| `achlys_t1` | Manifest → substrate → content-addressed store → canonical replay → optional sanitizer verify. |

Root `build.rs` compiles vendored `cJSON.c` twice (plain and SanCov) plus `benchmarks/micro/crash_if_magic.c`. A clean clone builds.

## Target architecture

Do not extend this note into the cooperative / cost-aware design. That design is specified only in [`MASTER_PLAN.md`](MASTER_PLAN.md).
