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
├── build.rs                   # compiles vendored cJSON; fails on a clean clone
├── src/
│   ├── cli/                   # achlys-cli  — `achlys fuzz`
│   ├── core/                  # achlys-core — FuzzerBuilder + LibAFL wiring
│   ├── bridge/                # achlys-bridge — Target, ForkExec, InProcess, AutoCompiler
│   └── cortex/                # achlys-cortex — experimental ONNX / trainer (not H0)
├── examples/fuzzers/          # hand-wired LibAFL examples
└── examples/targets/cJSON     # broken gitlink; not present after a clean clone
```

| Crate | What it actually does today |
|---|---|
| **achlys-cli** | Parses flags, optionally compiles `--source`, always constructs `ForkExecTarget`, runs `FuzzerBuilder`, optional ratatui TUI. |
| **achlys-core** | `FuzzerBuilder` wraps LibAFL havoc. `run()` dispatches to `run_blackbox` or `run_graybox`. CLI always hits blackbox. |
| **achlys-bridge** | `ForkExecTarget` (used): spawn binary, stdin or `@@`, crash/timeout from the child. `InProcessTarget` (unused by CLI). `AutoCompiler` (used only by `--source`). |
| **achlys-cortex** | ONNX load, `AutoTrainer`, `HotSwapCortex`. Experimental. Not on the H0 path. |

There is no QEMU backend, no network target, no symbolic engine, no orchestrator, and no multi-worker control plane.

## CLI execution path

```
achlys fuzz <binary> [args]
        │
        ├─ --source …  → AutoCompiler::compile_binary (SanCov in the child)
        │                    └── still ForkExecTarget(instrumented)
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
              ConstFeedback(true) + CrashFeedback
              HavocScheduledMutator / havoc_mutations()
```

`achlys fuzz` never constructs `InProcessTarget`. There is no coverage-guided CLI campaign.

`--source` is **not graybox**. SanCov writes a map inside the child process. The parent fuzzer does not transport or consume that map (Master Plan §24.1). The flag is unsupported and scheduled to be disabled.

## Corpus and results

- Queue: `InMemoryCorpus`. Seeds are read from `--corpus` once. New queue entries are not written back to that directory.
- Crashes: `OnDiskCorpus` under `--output` (default `./crashes`).
- Blackbox admission: `ConstFeedback(true)` — every execution is “interesting.” Unbounded. Not a novelty policy.
- `ForkExecTarget` maps several spawn/I/O errors to `ExitKind::Ok`. Those are infrastructure failures, not successful executions.

## Unused or disconnected pieces

These types exist. They are not a working product surface:

- **`InProcessTarget` + `FuzzerBuilder::run_graybox`.** Used only if a `Target` reports a coverage map. The CLI never does. The working graybox demonstration is `examples/fuzzers/cjson_graybox_fuzzer.rs` (requires cJSON sources).
- **`EscalatingStage`, `PlateauDetector`, `AiMutator`, `HybridStage`.** Wired when a `CortexInterface` is supplied. In CLI blackbox mode the plateau timer fires on wall time alone (no coverage events).
- **`AutoTrainer`.** Watches `--corpus` or `./runtime/corpus`. The fuzzer does not write that directory. Autonomous training is disconnected and not functional.
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
