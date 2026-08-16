# Achlys

> Achlys is an experimental cooperative fuzzing system built on LibAFL. It investigates whether typed cross-strategy assistance and cost-aware worker allocation can improve coverage and hard-branch discovery under equal resource budgets.

This repository is a **Level 0** prototype. A development H0 experiment on cJSON in-process (macOS aarch64, 5 × 30 s) found **low overhead, under the 5% gate**, versus a minimal LibAFL baseline. That is a point estimate under that protocol, not a release result, not an AFL++ comparison, and not Level 1.

The design source of truth is [`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md). If this README or [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) conflicts with the Master Plan, the Master Plan wins.

## What works today

- **`achlys fuzz` is blackbox fork+exec.** Every CLI campaign uses `ForkExecTarget`. Each input is delivered over stdin or via an AFL-style `@@` file argument, then the child is spawned. There is no in-process CLI path and no coverage feedback on this path.
- **Mutations are LibAFL havoc.** `HavocScheduledMutator` / `havoc_mutations()` is the working mutation engine.
- **Seeds and crashes.** `--corpus` loads seed files into an in-memory queue. Crash-triggering inputs are written to `--output` (default `./crashes`). The working corpus is **not** written back to disk.
- **TUI.** A ratatui monitor is the default display. Use `--no-tui` for plain text.
- **In-process graybox exists for H0/T1, not for the CLI.** `FuzzerBuilder::run_substrate` plus `examples/fuzzers/achlys_h0.rs` and `examples/fuzzers/libafl_baseline.rs` run the same LibAFL havoc loop on vendored cJSON. `examples/fuzzers/achlys_t1.rs` loads a target manifest, persists a content-addressed campaign, and replays coverage with `achlys_oracle`. `achlys fuzz` remains blackbox fork+exec.

## What does not work

Treat the following as **unsupported**, even if a flag or type still exists:

| Claim or flag | Actual behavior |
|---|---|
| `--source` “graybox” | **Rejected.** SanCov child coverage is not transported. The flag errors out. |
| Autonomous / default AI training | **Disabled.** `AutoTrainer` is not started. AI only loads if `--model` is given. |
| `--model`, ONNX, `achlys-cortex` | Experimental code. Not on the H0 (substrate correctness) path. Do not treat this as a working AI-guided fuzzer. |
| 4-stage escalation, symbolic execution, QEMU, network, distributed | Not implemented. Not the current product. |

Default CLI is havoc-only. `--model` is optional and experimental.

## Build

Requirements:

- **Rust 1.97.1** (`rust-toolchain.toml`)
- **clang** to compile the vendored cJSON examples and micro targets
- Python / PyTorch are **not** required

```bash
git clone https://github.com/Dadaam/achlys.git
cd achlys
cargo build --workspace --release
```

cJSON is vendored at `examples/targets/cJSON` (DaveGamble/cJSON v1.7.18). The root `build.rs` compiles the example libraries.

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

`--source` is rejected. `--train-delay` is ignored. `--model` is experimental.

## Limitations

- Success ladder **Level 0**, with a Tranche 1 single-worker baseline on top of H0. H0 development evidence: [`docs/decisions/2026-08-16-h0-substrate.md`](docs/decisions/2026-08-16-h0-substrate.md) and [`docs/evidence/h0/`](docs/evidence/h0/). T1 decision and smoke: [`docs/decisions/2026-08-16-t1-baseline.md`](docs/decisions/2026-08-16-t1-baseline.md), [`docs/evidence/t1/`](docs/evidence/t1/). Re-run on Linux x86-64 before quoting a number. AFL++ compare infrastructure exists (`scripts/experiments/t1_compare.sh`) but does **not** produce numbers when `afl-fuzz` is missing. No “hard branch” claims.
- CLI campaigns have no coverage map. Blackbox admission uses `ConstFeedback(false)` (seeds + crashes only).
- Spawn, write, and wait failures are `InfraError` and abort the campaign. They are not target crashes.
- Sanitizer replay and crash dedup exist **off** the hot path (`SanitizerReplayer`). They are not wired into `achlys fuzz`.
- No forkserver, LLMP, multi-worker campaign, or adaptive allocation.
- ML crates (`achlys-cortex`, `AiMutator`, `HybridStage`, `AutoTrainer`) are experimental leftovers, not the research baseline.

## Design

[`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) is the architecture and research plan. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) describes only what this tree implements today.
