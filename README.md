# Achlys

<div>

**A Hybrid Fuzzer (Rust + AI) designed for Pwn and Zero-Day vulnerability research.**

*"The death-mist of Achlys settled upon his sight."*

</div>

---

## 📜 The Vision

Achlys was born from a simple observation: **traditional fuzzers** (AFL++, Honggfuzz) are *fast but blind*, while modern **LLMs** are *smart but slow*.

In a **Red Teaming** or **Blackbox Audit** scenario, brute force is no longer enough. Complex targets (PDF, XML, custom protocols) enforce strict structures that reject **99% of random mutations**.

Achlys bridges this gap. It is a **hybrid engine** that leverages the speed of **LibAFL** for surface exploration, and delegates strategy to a neural network (LSTM/GRU) when brute-force hits a plateau.

---

## ⚡ Why Achlys?

| Feature | Classic Fuzzers (AFL++) | Achlys |
|---------|------------------------|----------|
| **Strategy** | Random Bit-flipping (Dumb) | AI-Guided Heatmaps (Smart) |
| **Context** | Blind to file structure | Implicit Grammar Understanding |
| **Architecture** | Monolithic C/C++ | Modular Rust (Core vs Cortex) |
| **Usage** | CI/CD (Defensive) | Pwn / Exploitation (Offensive) |

---

## 🏗 Technical Architecture

The project is divided into **three major components** within a Rust Workspace.

### 1. The Core (Engine)

- **Language**: Rust (based on LibAFL 0.11)
- **Role**: Bombard the target
- **Performance**: Targets **10k+ executions/second**
- **Tech**: Uses *"In-Process"* instrumentation for maximum speed. Manages the *"Feedback Loop"* (Coverage Map) to detect if a mutation has uncovered a new code path.

### 2. The Cortex (Brain)

- **Language**: Rust (via `ort` - ONNX Runtime) & Python (Training)
- **Role**: Intervenes only when the Core is *"Stuck"*
- **Logic**: 
  1. Receives the current input as a byte vector
  2. Uses a pre-trained model (LSTM) to predict the most probable next bytes and critical variations
  3. Returns a *"Heatmap"* of intelligent mutations to the Core

### 3. The Bridge (Harness)

- **Role**: The critical contact point
- **Function**: Transforms raw Fuzzer data into a target-compatible input (e.g., CString for a C lib). This is where execution happens.

---

## 🔄 The "Search & Destroy" Workflow

Achlys doesn't just look for bugs, **it tries to force them**.

### Initialization Phase

The user provides a target (e.g., `libjson.so`) and a seed corpus (valid files). Achlys selects the appropriate ONNX model (e.g., `models/json_structure.onnx`).

### The Fuzzing Loop

1. **"Berserk" Mode**: The Core mutates bits randomly. *Maximum speed*.
2. **Wall Detection**: If no new path (Coverage) is found for N seconds, the Core calls the Cortex.
3. **AI Injection**: The Cortex analyzes the input and suggests a structural modification (e.g., closing a missing bracket, inserting an Integer Overflow in a "Length" field).
4. **Resume**: The Core takes these "smart" inputs and resumes mutating around them.

### The Crash (Segfault)

As soon as the target crashes (Signal 11/SIGSEGV), Achlys saves the guilty input to the `crashes/` folder.

**Result**: A binary file ready to be analyzed in GDB to develop the final exploit (ROP Chain, Shellcode).

---

## 🛠 Installation & Build

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

## 🚀 Usage
```bash
# Run Achlys on a target
./target/release/achlys \
    --target ./targets/vulnerable_parser \
    --corpus ./corpus/seeds \
    --model ./models/json_brain.onnx
```

---

## 🧠 Roadmap

- [ ] **Phase 1 (MVP)**: Functional fuzzer on cJSON with random mutations (Pure LibAFL)
- [ ] **Phase 2 (Hybrid)**: Integration of `ort` (ONNX) and creation of the "Stuck Detection" mechanism
- [ ] **Phase 3 (Training)**: Creation of Python scripts to train models on PDF and XML
- [ ] **Phase 4 (Optimization)**: Implementation of implicit Grammar Discovery (AI guesses tokens)

---

## ⚠️ Disclaimer

*Achlys is an offensive security research tool.**

It is designed for code auditing, CTFs (Capture The Flag), and vulnerability research within legal boundaries. The author is not responsible for any misuse of this tool on unauthorized systems.

---

<div align="center">

Made with 🦀 and ☕ by [Dadaam](https://github.com/Dadaam)

</div>
