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
│   ├── cli/                   # achlys-cli  — `achlys fuzz`
│   ├── core/                  # achlys-core — FuzzerBuilder + LibAFL wiring
│   ├── bridge/                # achlys-bridge — Target, ForkExec, InProcess, AutoCompiler
│   └── cortex/                # achlys-cortex — experimental ONNX / trainer (not H0)
├── examples/fuzzers/          # hand-wired LibAFL examples
└── examples/targets/cJSON     # vendored DaveGamble/cJSON v1.7.18 + SanCov callbacks
```

| Crate | What it actually does today |
|---|---|
| **achlys-cli** | Parses flags, always constructs `ForkExecTarget`, runs `FuzzerBuilder`, optional ratatui TUI. `--source` is rejected. |
| **achlys-core** | `FuzzerBuilder` wraps LibAFL havoc. `run()` is the CLI path (blackbox). `run_substrate()` is the H0 in-process graybox worker. |
| **achlys-bridge** | `ForkExecTarget` (CLI): spawn binary, stdin or `@@`. Spawn/write/wait failures are `InfraError`. `InProcessTarget` used by `achlys_h0`. |
| **achlys-cortex** | ONNX load, `AutoTrainer`, `HotSwapCortex`. Experimental. Not on the H0 path. |

There is no QEMU backend, no network target, no symbolic engine, no orchestrator, and no multi-worker control plane.

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

Root `build.rs` compiles `cJSON.c` twice (plain and SanCov). `examples/targets/cJSON` is a gitlink with no `.gitmodules` entry, so a clean clone does not build these examples.

## Target architecture

Do not extend this note into the cooperative / cost-aware design. That design is specified only in [`MASTER_PLAN.md`](MASTER_PLAN.md).
