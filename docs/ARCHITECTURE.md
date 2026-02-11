# Achlys — Architecture

*The death-mist descends on vulnerable code.*

---

## Reminder: What is Achlys?

Achlys is a **universal hybrid fuzzer**. It takes **any binary** — C, C++, Go, Rust, closed-source, whatever — and hunts for crashes. It doesn't care about the language, the format, or whether you have the source code.

The key insight: traditional fuzzers (AFL++, Honggfuzz) are **fast but blind**. LLMs and symbolic engines are **smart but slow**. Achlys doesn't pick a side — it **escalates** through three strategies, each one smarter and slower than the last, and only activates the heavy artillery when the cheap stuff stops working.

cJSON is the current **test target** for development and benchmarking. It is not the product.

---
## The Four-Stage Escalation Model

This is the core idea behind Achlys. Instead of running one strategy forever, the fuzzer **adapts**:

```
 ┌─────────────────────────────────────────────────────────────┐
 │                    STAGE 0: SEED CORPUS                     │
 │              Valid samples provided by the user             │
 │              (or auto-generated from format hints).         │
 │                                                             │
 │   Instant bootstrap. Lets the fuzzer skip the "rejected     │
 │   by the parser" phase entirely. Optional but powerful.     │
 └──────────────────────────┬──────────────────────────────────┘
                            │
              seeds loaded → havoc takes over
                            │
                            ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                    STAGE 1: HAVOC                           │
 │          Random bit-flipping, splicing, arithmetic          │
 │            Fast. Dumb. Covers the easy 0-70%.               │
 │                                                             │
 │      Thousands of execs/sec. No thinking, just speed.       │
 └──────────────────────────┬──────────────────────────────────┘
                            │
                coverage plateau detected
               (no new edges for N seconds)
                            │
                            ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                    STAGE 2: AI HYBRID                       │
 │              Neural network predicts next bytes             │
 │              from the corpus patterns so far.               │
 │                                                             │
 │   Smarter mutations. Called ONLY when havoc stalls.         │
 │   If coverage resumes → drop back to Stage 1.               │
 └──────────────────────────┬──────────────────────────────────┘
                            │
            coverage plateau detected AGAIN
        (AI mutations also stopped finding new paths)
                            │
                            ▼
 ┌─────────────────────────────────────────────────────────────┐
 │              STAGE 3: SYMBOLIC EXECUTION                    │
 │          Constraint solving for hard branches.              │
 │            The `if (x == 0xDEADBEEF)` killer.               │
 │                                                             │
 │    Slow. Precise. Only activated for the last 5-10%.        │
 │     Overkill before ~90% coverage. Worth it after.          │
 └─────────────────────────────────────────────────────────────┘
```

**The rules are simple:**
1. **Start cheap.** Havoc mutations are nearly free — Achlys run them at max speed.
2. **Escalate on plateau.** If coverage hasn't grown in ~10 minutes, we bring in the AI.
3. **De-escalate when possible.** If the AI finds new paths, feed them back to havoc and drop down. Stage 1 is always faster.
4. **Symbolic is the last resort.** Only for the nightmare branches that neither random nor AI can crack (magic bytes, checksums, multi-condition guards). We don't use it before ~90-95% coverage — it's overkill.

This means Achlys spends **most of its time** in the fast lane (havoc), occasionally dips into AI-assisted mode, and only fires up the symbolic engine when everything else has been exhausted. The goal: come to grips with **any** binary, and not in 12 hours.

---

## Workspace Structure

```
                        ┌───────────────┐
                        │  achlys-cli   │ ← entry point
                        └───────┬───────┘
                                │
              ┌─────────────────┼──────────────────┐
              │                 │                  │
      ┌───────▼───────┐  ┌──────▼──────┐  ┌────────▼────────┐
      │  achlys-core  │  │achlys-cortex│  │  achlys-bridge  │
      │  (engine)     │  │  (AI brain) │  │  (target I/O)   │
      └───────────────┘  └─────────────┘  └─────────────────┘
```

| Crate | Path | Role |
|-------|------|------|
| **achlys-core** | `src/core/` | The fuzzing engine. Wraps LibAFL primitives (state, executor, scheduler, stages). Owns the escalation logic: monitors coverage growth, decides when to call cortex, when to drop back to havoc. Will expose a `FuzzerBuilder` so wiring things up isn't 100 lines of boilerplate every time. |
| **achlys-cortex** | `src/cortex/` | The AI brain. Loads ONNX models via [`ort`](https://github.com/pykeio/ort). Receives byte sequences from the corpus, predicts promising next-byte mutations, returns them to core. Later: also hosts the symbolic execution integration. Not wired up yet — skeleton + `ort` dependency in place. |
| **achlys-bridge** | `src/bridge/` | The target interface. Abstracts away *how* Achlys talks to whatever it's fuzzing. Today: in-process FFI for the cJSON test. Tomorrow: out-of-process execution (fork+exec), shared-memory transport, QEMU user-mode for closed-source binaries, network sockets for services. Adding a new target type = extending the bridge, not touching the engine. |
| **achlys-cli** | `src/cli/` | Command-line interface. `achlys fuzz <target>` and it figures out the rest. Skeleton for now. |

---

## How the Escalation Maps to the Code

### Stage 0 — Seed Corpus (today: ✅ supported)

Before any mutation happens, the user can (and should, when possible) provide **valid samples**
of the target's input format. A JSON file for a JSON parser. A PNG for an image decoder. A PCAP
for a network protocol parser.

**Why it matters:**
Most parsers reject random bytes immediately. Without seeds, the fuzzer can spend hours
generating garbage that never gets past the first `if` statement. A single valid sample
lets havoc start from *inside* the parser's acceptance zone instead of banging on the
front door.

**When you don't have seeds:**
This is exactly where Stage 2 (AI) earns its keep. Unknown format, no docs, no samples?
The AI learns the input structure statistically from coverage feedback alone.
But if you *do* have seeds — use them. It's free speed.

**Where it lives:** `achlys-core` (corpus initialization before the fuzz loop starts).

### Stage 1 — Havoc (today: ✅ working)

This is what the example fuzzers already do. `HavocScheduledMutator` with `havoc_mutations()` from LibAFL. Random bit flips, byte insertions, arithmetic, splicing — the full AFL++ mutation set. Extremely fast because there's zero inference overhead.

**Where it lives:** `achlys-core` (the `StdMutationalStage` + `HavocScheduledMutator` setup).

**Plateau detection:** Core tracks coverage map growth over time. If `MaxMapFeedback` hasn't reported a new edge in N seconds (configurable, ~10 min default), core declares a plateau and escalates.

### Stage 2 — AI Hybrid (`achlys-cortex`)

**What it actually does:** Implicit grammar inference. The model observes which byte
patterns in the corpus led to new coverage, and predicts mutations that are likely to
pass the target's input validation — without ever looking at the binary's code.

**When it matters:**
- Target with **known format** (JSON, PNG, XML...)? You can skip the AI entirely.
  Just drop valid samples in the seed corpus and havoc will handle the rest.
  The AI adds nothing here that good seeds don't already solve.
- Target with **unknown/custom/proprietary format**, no samples, no docs?
  This is where the AI earns its keep. It learns the input structure statistically,
  from the coverage feedback alone, and generates mutations that respect enough of
  the format to get past the parser's front door.

**What it does NOT do:**
- It doesn't reverse engineer the binary.
- It doesn't explain the crash.
- It doesn't write exploits.
- A human reverser + AFL++ with hand-crafted seeds will match or beat it on
  well-known targets. The point is: Achlys doesn't need the human.

**The honest tradeoff:**
Achlys trades *inference compute time* for *human preparation time*.
If you have a reverser and a week, you don't need the AI.
If you have a binary and a few hours, you do.

### Stage 3 — Symbolic Execution (future)

The nuclear option. For branches like `if (input[4..8] == 0xDEADBEEF)` that neither random bits nor a neural network will ever guess. Symbolic execution treats the program as a set of mathematical constraints and solves for inputs that reach specific branches.

**When to activate:** Only after ~90-95% coverage. Before that, havoc + AI will find paths faster. Symbolic execution is expensive (minutes per path vs microseconds for havoc) and should only target the specific hard branches that are blocking progress.

**Integration approach (TBD):**
- Likely via an external symbolic engine (e.g., [haybale](https://github.com/PLSysSec/haybale) for LLVM bitcode, or hooking into [KLEE](https://klee.github.io/) / [Manticore](https://github.com/trailofbits/manticore) / [angr](https://angr.io/))
- Core identifies "stuck" branches from the coverage map (edges that are neighbors of covered edges but never hit)
- Sends those constraints to the symbolic engine
- Receives concrete inputs that satisfy the constraints
- Feeds them back into the corpus → havoc takes over again

**Where it lives:** `achlys-cortex` (alongside the AI, since both are "smart" strategies).

---

## Target-Agnostic Design

Achlys doesn't care what it's fuzzing. The `achlys-bridge` crate abstracts the target behind a trait:

```
    ┌─────────────┐
    │ achlys-core │  "here are bytes, run them"
    └──────┬──────┘
           │
           ▼
    ┌─────────────────────────────────┐
    │          achlys-bridge          │
    │                                 │
    │  ┌───────────┐ ┌────────────┐   │
    │  │ InProcess │ │  ForkExec  │   │   ← today: InProcess (cJSON test)
    │  │   (FFI)   │ │  (spawn)   │   │   ← next: fork+exec any binary
    │  ├───────────┤ ├────────────┤   │
    │  │   QEMU    │ │  Network   │   │   ← later: closed-source, services
    │  │(user-mode)│ │ (TCP/UDP)  │   │
    │  └───────────┘ └────────────┘   │
    └─────────────────────────────────┘
```

The engine just sends bytes and reads coverage. It never knows (or cares) whether the target is a C library loaded in-process, a binary spawned via fork+exec, a QEMU-instrumented closed-source blob, or a service listening on a socket.

---

## The Example Fuzzers (Test Bench)

Three example fuzzers live in `examples/fuzzers/`. They wire up LibAFL by hand to test the cJSON target. They exist to validate the plumbing before it gets abstracted into `achlys-core`.

| Example | Target | Mode | Feedback |
|---------|--------|------|----------|
| `simple_fuzzer` | Inline Rust (simulated) | Whitebox | `MaxMapFeedback` on hand-written `SIGNALS` map |
| `cjson_blackbox` | cJSON (via FFI) | Blackbox | `ConstFeedback(true)` — blind, keeps everything |
| `cjson_graybox` | cJSON (via FFI + SanCov) | Graybox | `MaxMapFeedback` on `EDGES_MAP` from SanCov callbacks |

### Build system for test targets

`build.rs` compiles cJSON twice into two static libraries:

```
build.rs
  ├── cc::Build → libcjson_blackbox.a  (gcc, no instrumentation)
  └── cc::Build → libcjson_graybox.a   (clang + -fsanitize-coverage=trace-pc-guard)
                   └── includes sancov_callbacks.c (coverage bridge)
```

This dual build is specific to the cJSON test setup. When Achlys targets arbitrary binaries, it won't need to compile the target.

### The SanCov coverage bridge

`sancov_callbacks.c` implements `__sanitizer_cov_trace_pc_guard_init` and `__sanitizer_cov_trace_pc_guard`. When Clang instruments a target, it calls these at every edge. They write into a global `EDGES_MAP` array that the Rust side reads via FFI. This is what makes the graybox example work.

For closed-source binaries where recompilation isn't possible, other instrumentation strategies (QEMU user-mode, DynamoRIO, hardware tracing via Intel PT) will be explored in later phases.

---

## Data Flow: One Fuzzing Iteration

```
1. Scheduler picks an input from the corpus
2. Mutator transforms it:
   - Stage 1: havoc mutations (random, fast)
   - Stage 2: AI mutations (predicted bytes, when stuck)
   - Stage 3: symbolic solutions (constraint-solved, when really stuck)
3. Bridge feeds the bytes to the target (however it's connected)
4. Observer reads coverage (edge map, or nothing in blackbox mode)
5. Feedback evaluates: "did this input find something new?"
6. If interesting → corpus    If crash → ./crashes/
7. Escalation check: is coverage still growing?
   - Yes → stay in current stage (or de-escalate)
   - No  → escalate to next stage
8. Loop
```

---

## Dependencies

All shared versions in root `Cargo.toml` under `[workspace.dependencies]`:

| Dependency | Version | Used for |
|-----------|---------|----------|
| libafl | 0.15.4 | Fuzzing framework |
| libafl_bolts | 0.15.4 | LibAFL utilities |
| ort | 2.0.0-rc.11 | ONNX Runtime — powers the AI brain |
| clap | 4.5 | CLI argument parsing |
| cc | 1.2 | Compiling test targets at build time |
| serde | 1.0 | Serialization |

---

## Roadmap

### Phase 1 — MVP ✅ (done)
- Workspace with four crates
- Three example fuzzers (simple, cjson blackbox, cjson graybox)
- Dual build system + SanCov coverage bridge
- Proof that LibAFL can fuzz a real C library and find paths

### Phase 2 — Engine Abstraction
- Extract boilerplate into `achlys-core` (`FuzzerBuilder` pattern)
- Target trait in `achlys-bridge` (in-process + fork-exec backends)
- Plateau detection (coverage stall timer)
- CLI wired up: `achlys fuzz <binary>`
- Seed corpus support

### Phase 3 — AI Hybrid (Cortex)
- Train LSTM/GRU on corpus byte patterns → export ONNX
- Load in `achlys-cortex` via `ort`
- Plateau triggers AI mutation injection
- De-escalation: AI finds new edges → drop back to havoc
- Benchmark: AI hybrid vs pure havoc on same targets

### Phase 4 — Symbolic Execution
- Integrate symbolic engine for hard branches
- Core identifies stuck edges from coverage map
- Symbolic solver produces concrete inputs → fed back to corpus
- Only activates at high coverage (~90%+)
- Benchmark: three-stage vs two-stage vs pure havoc

### Phase 5 — Universal Target Support
- QEMU user-mode backend (fuzz any binary without source)
- Network target backend (TCP/UDP services)
- Distributed fuzzing (multi-node campaigns)
- Target format auto-detection
- Grammar inference from corpus patterns

---

## Directory Layout

```
Achlys/
├── Cargo.toml                    # workspace root
├── build.rs                      # compiles test targets
├── examples/
│   ├── fuzzers/
│   │   ├── simple_fuzzer.rs      # test: inline simulated target
│   │   ├── cjson_blackbox_fuzzer.rs  # test: blind fuzzing cJSON
│   │   └── cjson_graybox_fuzzer.rs   # test: coverage-guided cJSON
│   └── targets/
│       └── cJSON/
│           ├── cJSON.c           # test target (vendored)
│           ├── cJSON.h
│           └── sancov_callbacks.c
├── src/
│   ├── lib.rs
│   ├── core/                     # achlys-core   (engine + escalation)
│   ├── cortex/                   # achlys-cortex (AI + future symbolic)
│   ├── bridge/                   # achlys-bridge (target abstraction)
│   └── cli/                      # achlys-cli    (command line)
└── docs/
    └── ARCHITECTURE.md           # you are here
```
