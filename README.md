# Achlys

<div>

**A 4-stage adaptive fuzzer that hunts Zero-Days in any binary. Written in Rust, powered by LibAFL and AI.**

*"The death-mist of Achlys settled upon his sight."*

</div>

---

## The Vision

Achlys was born from a simple observation: **traditional fuzzers** (AFL++, Honggfuzz) are *fast but blind*, while **LLMs** and **symbolic engines** (KLEE, angr) are *precise but slow*. Everyone picks a side. Achlys doesn't — it **escalates**.

In a **Red Teaming** or **Blackbox Audit** scenario, brute force is no longer enough. Complex targets (PDF, XML, custom protocols) enforce strict structures that reject **99% of random mutations**.

Achlys bridges this gap with a **4-stage escalation model**: seed corpus for instant bootstrap, havoc mutations for raw speed, AI-guided mutations when brute-force hits a wall, and symbolic execution for the nightmare branches nothing else can crack. Each stage is smarter and slower than the last — and only activates when the cheaper one stops making progress.

---

## Why Achlys?
| Feature | Classic Fuzzers (AFL++) | Symbolic (KLEE/angr) | Achlys |
|---------|------------------------|----------------------|--------|
| **Speed** | 🟢 at least 20k+ exec/s | 🔴 Minutes per path | 🟢 Fast by default, slow only when needed |
| **Hard branches** | 🔴 Blind guessing | 🟢 Constraint solving | 🟢 AI first, symbolic as last resort |
| **Setup required** | 🟡 Needs seed corpus, otherwise very dumb | 🔴 Needs source / IR | 🟢 Point at a binary and go |
| **Adaptiveness** | 🔴 Same strategy forever | 🔴 Same strategy forever | 🟢 Escalates on plateau, de-escalates when unstuck |

---

### The 4-Stage Engine

```
  Seeds ──▶ Havoc ──▶ AI Hybrid ──▶ Symbolic
  (free)    (fast)    (smart)       (precise)
               ◄──────────┘
                de-escalate when 
                coverage resumes
```

1. **Stage 0 — Seeds**: Drop valid samples in the corpus. Instant bootstrap. Optional but powerful.
2. **Stage 1 — Havoc** (`achlys-core`): Random mutations at max speed. Covers 60-70% of edges. Pure LibAFL.
3. **Stage 2 — AI** (`achlys-cortex`): Neural network (LSTM/GRU via ONNX) predicts byte patterns that pass the parser. Only called when havoc plateaus. **This is what lets Achlys fuzz unknown formats without hand-crafted seeds.**
4. **Stage 3 — Symbolic** (`achlys-cortex`): Constraint solving for magic bytes, checksums, multi-condition guards. The `if (x == 0xDEADBEEF)` killer. Only when AI's stuck at ~90%+ coverage.

### The Workspace

| Crate | Role |
|-------|------|
| **achlys-core** | Fuzzing engine + escalation logic. Monitors coverage, decides when to escalate/de-escalate. |
| **achlys-cortex** | AI brain (ONNX inference) + future symbolic integration. The "think" side. |
| **achlys-bridge** | Target abstraction. In-process FFI, fork+exec, QEMU, network — the engine doesn't care how. |
| **achlys-cli** | `achlys fuzz <binary>` and it figures out the rest. |

---

## The "Search & Destroy" Workflow

Achlys doesn't just look for bugs, **it tries to force them**.

### Initialization

Point Achlys at a binary. Optionally provide seed files and/or an ONNX model.
No seeds? No problem — the AI will figure out the format. It just takes longer.

### The Escalation Loop

1. **Seeds loaded** → Corpus bootstrapped with valid inputs (if provided).
2. **Havoc ("Berserk Mode")** → Random mutations at thousands of execs/sec. *Maximum speed.*
3. **Plateau?** → No new coverage for N minutes → **AI kicks in.** Predicts structural mutations from corpus patterns. Hybrid mode: AI + havoc together.
4. **Coverage resumes?** → AI found new paths → **drop back to pure havoc.** Always prefer the fast lane.
5. **Still stuck at ~90%+?** → **Symbolic execution.** Solves the hard constraints (magic bytes, checksums) that nothing else can crack.
6. **Crash (SIGSEGV)?** → Input saved to `crashes/`. Ready for GDB and exploit development.

**Result**: A crashing input file, found without hand-crafting seeds or reversing the binary first.

---

## Installation & Build

### Prerequisites

- Rust (Nightly toolchain recommended)
- Clang / LLVM (for target instrumentation)
- Python 3.10+ (for your own model training)
```bash
# 1. Clone the repo
git clone https://github.com/dadaam/achlys.git
cd achlys

# 2. Build the Fuzzer and Harness
# (The build.rs script will compile the target lib automatically)
cargo build --release

# 3. Train a model (Optional, pre-trained models provided)
cd cortex/training
python train.py --dataset ./json_samples --output ../models/brain.onnx
```

---

## Usage
```bash
# Run Achlys on a target
./target/release/achlys \
    --target ./targets/vulnerable_parser \
    --corpus ./corpus/seeds \
    --model ./models/json_brain.onnx
```

---

## Roadmap

- [x] **Phase 1 (MVP)**: Functional fuzzer on cJSON with random mutations (Pure LibAFL)
- [ ] **Phase 2 (Engine)**: `FuzzerBuilder` abstraction, seed corpus support, plateau detection, CLI
- [ ] **Phase 3 (AI Hybrid)**: ONNX integration via `ort`, AI-guided mutations on plateau, de-escalation
- [ ] **Phase 4 (Symbolic)**: Constraint solving for hard branches at 90%+ coverage
- [ ] **Phase 5 (Universal)**: QEMU backend, network targets, distributed fuzzingns)

---

## Disclaimer

**Achlys is an offensive security research tool.**

It is designed for code auditing, CTFs (Capture The Flag), and vulnerability research within legal boundaries. The author is not responsible for any misuse of this tool on unauthorized systems.

---

<div align="center">

Made with 🦀 and ☕ by [Dadaam](https://github.com/Dadaam)

</div>
