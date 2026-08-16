# Achlys

> Achlys is an experimental cooperative fuzzing system built on LibAFL. It investigates whether typed cross-strategy assistance and cost-aware worker allocation can improve coverage and hard-branch discovery under equal resource budgets.

This repository is a **Level 0** prototype: it builds some crates and can run a bounded havoc campaign. It is not a production fuzzer, not an AI fuzzer, and not a zero-day hunter. There is no evidence yet that Achlys beats a strong LibAFL or AFL++ baseline.

The design source of truth is [`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md). If this README or [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) conflicts with the Master Plan, the Master Plan wins.

## What works today

- **`achlys fuzz` is blackbox fork+exec.** Every CLI campaign uses `ForkExecTarget`. Each input is delivered over stdin or via an AFL-style `@@` file argument, then the child is spawned. There is no in-process CLI path and no coverage feedback on this path.
- **Mutations are LibAFL havoc.** `HavocScheduledMutator` / `havoc_mutations()` is the working mutation engine.
- **Seeds and crashes.** `--corpus` loads seed files into an in-memory queue. Crash-triggering inputs are written to `--output` (default `./crashes`). The working corpus is **not** written back to disk.
- **TUI.** A ratatui monitor is the default display. Use `--no-tui` for plain text.
- **In-process graybox is an example only.** `examples/fuzzers/cjson_graybox_fuzzer.rs` links cJSON with SanCov and uses `MaxMapFeedback`. `InProcessTarget` and `FuzzerBuilder::run_graybox` exist in the crates but are unused by `achlys fuzz`. The cJSON examples require the vendored cJSON tree (see limitations).

## What does not work

Treat the following as **unsupported**, even if a flag or type still exists:

| Claim or flag | Actual behavior |
|---|---|
| `--source` “graybox” | Compiles C/C++ with SanCov, then **still fork+execs** the binary. The fuzzer never reads the child coverage map. This is not graybox. Scheduled to be disabled. |
| Autonomous / default AI training | `AutoTrainer` watches `--corpus` or `./runtime/corpus`. The fuzzer never writes that directory. Training is **disconnected** and **not functional**. |
| `--model`, ONNX, `achlys-cortex` | Experimental code. Not on the H0 (substrate correctness) path. Do not treat this as a working AI-guided fuzzer. |
| 4-stage escalation, symbolic execution, QEMU, network, distributed | Not implemented. Not the current product. |
| Clean-clone examples | `examples/targets/cJSON` is a broken gitlink. A clean clone does **not** currently build the root package or the cJSON examples. |

Use `--no-ai` so the CLI does not start the disconnected trainer.

## Build

Requirements:

- **Rust 1.97+** (edition 2024)
- **clang** only if you compile the cJSON examples (currently broken on a clean clone) or the unsupported `--source` path
- Python / PyTorch are **not** required. The fuzzer does not train a model.

```bash
git clone https://github.com/Dadaam/achlys.git
cd achlys

# CLI only — avoids the root build.rs that compiles missing cJSON sources
cargo build -p achlys-cli --release
```

A bare `cargo build` or `cargo build --release` at the workspace root will fail on a clean clone because `build.rs` expects `examples/targets/cJSON/cJSON.c`.

If the cJSON tree is present (it is not, on a clean clone):

```bash
cargo run --example cjson_graybox
```

## Usage

```bash
# Recommended: havoc-only blackbox fork+exec
./target/release/achlys fuzz ./parser @@ --corpus seeds/ --no-ai

# Same campaign without the TUI
./target/release/achlys fuzz ./parser @@ --corpus seeds/ --no-ai --no-tui

# stdin delivery (no @@)
./target/release/achlys fuzz ./parser --no-ai
```

From a source checkout:

```bash
cargo run -p achlys-cli --release -- fuzz ./parser @@ --corpus seeds/ --no-ai
```

`--source`, `--model`, and `--train-delay` still parse. They do not provide graybox coverage or working autonomous training.

## Limitations

- Success ladder **Level 0** only. No H0 throughput evidence. No coverage or “hard branch” claims.
- CLI campaigns have no coverage map. Blackbox admission currently uses `ConstFeedback(true)` (unbounded keep-everything).
- Spawn, write, and observer failures in `ForkExecTarget` can be reported as successful executions.
- No forkserver, persistent mode, shared-memory coverage, sanitizer replay, or multi-worker campaign.
- ML crates (`achlys-cortex`, `AiMutator`, `HybridStage`, `AutoTrainer`) are experimental leftovers, not the research baseline.

## Design

[`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) is the architecture and research plan. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) describes only what this tree implements today.
