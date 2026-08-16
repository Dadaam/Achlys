# Achlys Master Plan

Status: authoritative design document  
Audience: future implementation and review agents  
Last architecture review: 2026-08-16  
Scope: research vision, target architecture, build order, evaluation protocol, and acceptance gates

## 1. Purpose of this document

This document is the source of truth for the next version of Achlys. It exists to prevent the project from growing through disconnected features, optimistic documentation, or implementation work that cannot be evaluated.

If this document conflicts with the current README or `docs/ARCHITECTURE.md`, this document wins until the older documents are rewritten. The current codebase is a useful prototype, not the architecture described here.

Future agents must follow these rules:

1. Work on one approved tranche at a time.
2. Do not begin the next tranche until the current tranche satisfies its exit gate.
3. Preserve reproducible raw evidence for every performance claim.
4. Keep baseline behavior separate from experimental behavior.
5. Do not describe an unimplemented component as working.
6. Do not add AI, symbolic execution, network targets, distributed execution, or UI work merely because they appear in the long-term design.
7. Prefer deleting or disabling a strategy that fails its evaluation gate over protecting the original vision.
8. Treat a negative experimental result as a valid research result.

The project succeeds only if it produces defensible evidence that Achlys is competitive with strong baselines under equal resources. A large feature list is not success.

## 2. Executive vision

Achlys should become a cooperative, heterogeneous fuzzing system built around one central idea:

> Allocate execution, analysis, and generation resources to the strategy with the highest expected marginal value for the current campaign, while allowing workers to hand difficult, well-described problems to workers with more appropriate capabilities.

Achlys is not primarily an AI fuzzer. It is not a linear pipeline that moves the whole campaign from havoc to AI to symbolic execution. It is not a wrapper that launches several existing fuzzers and synchronizes their queue directories.

Achlys is a control system for fuzzing:

- Fast workers explore cheaply.
- Specialized workers solve specific obstacles.
- Every accepted discovery retains provenance.
- Workers request typed assistance when they observe a problem suited to another capability.
- The orchestrator assigns bounded work, measures cost and reward, preserves exploration diversity, and reallocates resources.
- Expensive techniques must continuously justify their resource consumption.

The intended long-term result is a system that is:

- competitive with AFL++ on general source-available parser targets;
- better on a defensible subset of structured or hard-branch targets;
- measurably more efficient than a static heterogeneous worker allocation;
- reproducible enough for independent academic or engineering review;
- architected so that ML can be added as a measured capability instead of a branding requirement.

## 3. What “better than AFL++” means

“Better” must never be used without a metric, workload, resource budget, and statistical protocol.

Achlys is unlikely to universally beat AFL++ in raw executions per second. AFL++ has mature forkserver, persistent mode, shared-memory coverage, comparison solving, power schedules, binary-only modes, and years of performance engineering. Adding orchestration, concolic solving, or ML creates additional cost.

Achlys should target four different forms of superiority.

### 3.1 Performance parity

On targets where specialized help is unnecessary, Achlys must remain close to a strong LibAFL havoc baseline and reasonably competitive with AFL++.

Initial gate:

- no more than 5% orchestration overhead relative to the same LibAFL worker loop without orchestration;
- no central lock or message on the per-execution hot path;
- no unbounded corpus or event growth;
- persistent or in-process execution where the target permits it.

### 3.2 Search efficiency

At equal CPU time, Achlys should discover more canonical coverage or reach important edges earlier on targets where heterogeneous strategies are useful.

Relevant metrics:

- canonical edge coverage over time;
- time to target edge;
- time to first verified bug;
- number of verified known bugs reached;
- coverage gain per CPU-second;
- coverage gain per joule when practical.

### 3.3 Hard-obstacle efficiency

Achlys should excel when a normal mutation worker encounters an obstacle that another capability can solve more efficiently, such as:

- magic-value comparisons;
- transformed comparisons;
- checksums;
- structured input validity barriers;
- stateful message sequencing;
- constraints suitable for concolic solving.

The key metric is not that a specialist found an input. The key metric is that the complete assistance cycle reached the obstacle faster or more reliably than strong baselines under an equal total budget.

### 3.4 Operational efficiency

Achlys may also be better by reducing human preparation time while maintaining useful results. This must be measured separately from runtime performance.

Examples:

- automated harness validation;
- automatic dictionary extraction;
- target variant construction;
- campaign configuration generation;
- crash reproduction and deduplication.

Do not mix setup-time savings with fuzzing throughput claims.

## 4. Research hypotheses

Every major subsystem exists to test a hypothesis.

### H0: substrate correctness

A LibAFL-based Achlys worker can match the behavior and remain within 5% of the throughput of an equivalent minimal LibAFL baseline.

If H0 fails, no orchestration or ML work may proceed.

### H1: heterogeneous portfolio value

A static heterogeneous pool using havoc and comparison-aware workers produces better coverage or time-to-target results than the same number of homogeneous havoc workers on an obstacle-bearing benchmark set.

### H2: targeted assistance value

Typed requests that transfer a specific seed, trace, and obstacle to a suitable worker outperform blind global corpus synchronization under an equal budget.

### H3: adaptive allocation value

A cost-aware dynamic allocator outperforms the best tested static allocation across a diverse target set, not merely the average static allocation.

### H4: concolic worker value

A budgeted concolic worker improves time-to-target or known-bug discovery on constraint-heavy targets without materially degrading aggregate performance.

### H5: ML value

An ML capability provides positive marginal value after accounting for CPU, GPU, inference latency, training cost, and communication overhead, and it beats a substantially cheaper non-ML alternative designed for the same task.

H5 is deliberately last. ML is optional. Achlys remains successful if H0 through H4 hold and H5 is rejected.

## 5. Non-goals for the first credible release

The first credible release will not promise:

- arbitrary closed-source binaries;
- every operating system;
- network services;
- distributed multi-host fuzzing;
- autonomous exploit generation;
- automatic zero-day discovery;
- a universal learned grammar;
- a total coverage percentage;
- custom symbolic execution from scratch;
- higher raw throughput than AFL++ on every target.

The initial target class is source-available C and C++ libraries or command-line parsers that can expose a stable fuzz harness. Linux x86-64 is the reference execution platform. macOS may remain a development platform, but release benchmarks must run in a controlled Linux environment.

## 6. Architectural principles

### 6.1 LibAFL is the execution substrate

Use LibAFL for the worker hot loop, observers, feedback, corpus integration, executors, event transport, restart behavior, and existing concolic support.

Do not rewrite these systems unless a profile and a minimal reproducer demonstrate that a specific LibAFL component blocks an accepted requirement. A replacement must be benchmarked against the original component before adoption.

### 6.2 Separate control plane from data plane

The data plane performs target executions and local mutations. It must be fast, local, and minimally coordinated.

The control plane processes discoveries, maintains campaign knowledge, assigns bounded tasks, and changes resource allocation at coarse intervals.

No orchestrator decision, database transaction, network request, model call, or global mutex may occur once per target execution.

### 6.3 Share discoveries, not executions

Workers execute thousands or millions of inputs locally. They emit messages only for:

- locally interesting candidates;
- new comparison or constraint observations;
- assistance requests;
- task progress and completion;
- crashes, timeouts, or infrastructure failures;
- periodic aggregate metrics.

### 6.4 Keep one canonical measurement authority

Coverage maps from fast, CmpLog, sanitizer, and concolic target builds may not have compatible edge identifiers. A worker-local novelty result is therefore provisional.

A dedicated coverage authority must replay candidate inputs against a canonical coverage build and decide whether they add global canonical coverage. Published coverage metrics must come only from this build.

### 6.5 Preserve provenance

Every retained input must record:

- its content hash;
- parent input or parents;
- producing worker and strategy;
- mutation operator or generator version;
- campaign and target build identities;
- local observation;
- canonical coverage delta;
- comparison or concolic metadata when available;
- generation and execution cost;
- timestamp and deterministic RNG lineage where practical.

Without provenance, the allocator cannot learn and experiments cannot explain their results.

### 6.6 Use bounded work everywhere

Every specialist assignment must have:

- an owner;
- a lease;
- an execution or time budget;
- a priority;
- a termination reason;
- a maximum retry count;
- a deduplication key.

No solver, model, worker, or target process may run indefinitely without an explicit campaign policy.

### 6.7 Maintain exploration diversity

The most recent successful seed must not attract every worker. Achlys must reserve resources for independent exploration and may maintain partially isolated worker islands.

### 6.8 Evidence before interface polish

TUI, remote dashboards, distributed control, and elaborate configuration systems are lower priority than correctness, corpus integrity, execution speed, benchmark automation, and event evidence.

## 7. Target architecture

```text
                         CONTROL PLANE

    +----------------------------------------------------------+
    |                    Achlys Orchestrator                    |
    |                                                          |
    |  candidate intake     challenge queue     policy engine  |
    |  canonical novelty    leases and budgets  slot allocator |
    |  corpus authority     provenance          circuit breaks |
    +----------------------------+-----------------------------+
                                 |
                     typed events and assignments
                                 |
    +----------------------------v-----------------------------+
    |                 LibAFL LLMP Broker Layer                 |
    |       local shared memory, optional remote TCP later      |
    +----------+-----------------+------------------+-----------+
               |                 |                  |

                          DATA PLANE

      +--------v-------+ +-------v--------+ +-------v---------+
      | Havoc Workers  | | CmpLog Workers | | Concolic Worker |
      | local corpus   | | compare traces | | bounded solving |
      | local feedback | | targeted tasks | | targeted tasks  |
      +--------+-------+ +-------+--------+ +-------+---------+
               |                 |                  |
               +-----------------+------------------+
                                 |
                          candidate inputs
                                 |
                    +------------v-------------+
                    | Canonical Coverage Oracle |
                    | stable measurement build  |
                    +------------+--------------+
                                 |
                      authoritative discoveries
                                 |
                    +------------v-------------+
                    | Content-addressed Corpus  |
                    | metadata and event log    |
                    +---------------------------+
```

## 8. Target build model

One logical target may have several build variants. They must share a `TargetIdentity` while retaining distinct `BuildIdentity` values.

### 8.1 Required variants

#### Fast build

Purpose: maximum-throughput local fuzzing.

- in-process or persistent when possible;
- lightweight edge coverage;
- no heavy sanitizer in the main throughput path unless the experiment explicitly tests it;
- stable harness contract.

#### Canonical coverage build

Purpose: authoritative measurement and corpus admission.

- stable compiler and instrumentation configuration;
- deterministic edge map as far as the target permits;
- separate from worker-specific instrumentation;
- never silently changed during an experiment.

#### Sanitizer replay build

Purpose: bug verification and classification.

- ASan and UBSan initially;
- complete stderr capture;
- explicit exit policy;
- reproducible environment;
- slower execution is acceptable because only selected inputs are replayed.

#### CmpLog build

Purpose: comparison-aware assistance.

- instrumented for comparison operands;
- compatible harness behavior;
- build identity recorded with every trace.

#### Concolic build

Purpose: bounded constraint tracing and solving.

- initially use LibAFL and SymCC facilities;
- separate worker pool;
- explicit solver and runtime versions.

### 8.2 Target manifest

Every campaign must consume a versioned target manifest rather than infer important behavior from CLI flags.

Illustrative shape:

```toml
schema_version = 1
target_id = "libpng-read-png"
harness = "LLVMFuzzerTestOneInput"
input_mode = "inprocess"
max_input_len = 1048576
timeout_ms = 1000

[build.fast]
artifact = "artifacts/libpng-fast.a"
instrumentation = "sancov-edge"

[build.canonical]
artifact = "artifacts/libpng-coverage.a"
instrumentation = "llvm-cov"

[build.sanitizer]
artifact = "artifacts/libpng-asan.a"
sanitizers = ["address", "undefined"]

[build.cmplog]
artifact = "artifacts/libpng-cmplog.a"

[build.concolic]
artifact = "artifacts/libpng-symcc.a"
```

The manifest must include hashes of source revision, compiler, flags, harness, and artifacts in the final implementation.

## 9. Worker model

A worker is a process with a declared capability set, a local corpus cache, a local observer, and a bounded assignment loop.

Workers are not autonomous agents. They do not negotiate in natural language. They emit observations and requests defined by a versioned protocol.

### 9.1 Common worker lifecycle

1. Register capability, build identity, resource class, and protocol version.
2. Receive campaign configuration and an initial corpus snapshot.
3. Receive a `WorkLease` with a budget and objective.
4. Execute locally without control-plane interaction on each iteration.
5. Emit provisional discoveries and structured telemetry.
6. Accept corpus deltas or targeted assignments at safe synchronization points.
7. Return a completion event when the lease expires or the objective is met.
8. Remain in role, reconfigure, or terminate according to the slot allocator.

### 9.2 Havoc worker

Responsibilities:

- high-throughput general exploration;
- local coverage-guided corpus management;
- production of seeds for specialist workers;
- exploitation of specialist-produced seeds;
- multiple power schedules or controlled islands when evaluated.

The havoc worker is the default and must always retain a minimum campaign allocation.

### 9.3 Comparison worker

Responsibilities:

- consume seeds associated with comparison obstacles;
- collect comparison operands and transformations;
- generate targeted substitutions;
- return solved candidates and evidence;
- reject unsuitable challenges quickly.

Do not send the entire corpus to every comparison worker. Send high-value seeds or allow a worker to claim a challenge from a bounded queue.

### 9.4 Concolic worker

Responsibilities:

- trace one selected seed or a small lineage;
- solve selected branches under explicit time and query budgets;
- record constraints attempted and reasons for failure;
- return concrete candidate inputs;
- cache repeated unsatisfiable or unsupported work.

The concolic worker must never become the implicit fallback for every plateau.

### 9.5 Structure-aware worker

This worker is distinct from ML. It may use:

- dictionaries;
- grammar definitions;
- protobuf or AST mutators;
- format-specific repair;
- checksums and length-field fixups;
- inferred token boundaries.

It provides the cheap baseline that any learned structural model must beat.

### 9.6 ML worker or service

ML is split into three possible capabilities.

#### Offline semantic extraction

An LLM may inspect public source, harnesses, specifications, and seed examples before a campaign to propose:

- dictionaries;
- grammars;
- harness candidates;
- state-machine hypotheses;
- field annotations.

Every output must be stored as a versioned artifact and validated before use. No live LLM dependency is required during fuzzing.

#### Online policy model

A lightweight model may help predict:

- which strategy should receive a challenge;
- which seed is promising for which worker;
- how much budget a task should receive;
- whether a solver attempt is likely to pay off.

This is likely a more defensible use of ML than raw next-byte generation.

#### Online generation model

A neural generator is allowed only as an experimental strategy. It must:

- use categorical byte or token distributions rather than MSE byte regression;
- model and preserve length explicitly;
- support sampling and diversity;
- operate in batches outside the execution hot path;
- preserve or intentionally repair structural regions;
- report generation and inference cost;
- compete against n-gram, dictionary, grammar, and structure-aware baselines.

If it does not produce positive marginal campaign value, disable it.

## 10. Slots, roles, and migration

Do not model every process as a universal worker that instantly changes identity. Different capabilities need different builds, runtimes, caches, and hardware.

Model resources as slots:

- general CPU slot;
- CmpLog CPU slot;
- sanitizer replay slot;
- concolic solver slot;
- optional GPU generation slot.

A slot advertises compatible roles. The orchestrator may reassign or restart a slot at coarse intervals.

Migration policy must include:

- minimum role residence time;
- migration cost;
- hysteresis;
- warm-up state;
- maximum simultaneous migrations;
- mandatory exploration floor;
- target-specific capability compatibility.

For early versions, prefer stable specialist pools and dynamic task assignment. Dynamic process-role migration should be added only after task routing is proven.

## 11. Protocol and event model

Create a small pure-Rust `achlys-protocol` crate with no LibAFL or ONNX dependency. All messages must carry:

- `schema_version`;
- `campaign_id`;
- monotonically increasing sender sequence number;
- `worker_id`;
- `timestamp_monotonic` where applicable;
- payload-specific deduplication key.

### 11.1 Core identifiers

```rust
struct CampaignId(Uuid);
struct WorkerId(Uuid);
struct TargetId(String);
struct BuildId([u8; 32]);
struct InputId([u8; 32]);
struct ChallengeId(Uuid);
struct LeaseId(Uuid);
```

`InputId` should be the content hash of the raw input. Metadata must not alter identity.

### 11.2 Candidate discovery

```rust
struct CandidateDiscovered {
    input_id: InputId,
    parent_ids: Vec<InputId>,
    producing_strategy: StrategyId,
    producer_build: BuildId,
    local_coverage_digest: CoverageDigest,
    local_delta_count: u32,
    execution_ns: u64,
    generation_ns: u64,
    provenance: MutationProvenance,
    attachments: Vec<AttachmentRef>,
}
```

The orchestrator responds with an admission result after canonical replay.

### 11.3 Assistance request

```rust
enum AssistanceReason {
    HardComparison,
    ChecksumSuspected,
    StructuredValidityBarrier,
    StateTransitionBarrier,
    ConcolicCandidate,
    LowYieldLineage,
}

struct AssistanceRequest {
    challenge_id: ChallengeId,
    seed: InputId,
    reason: AssistanceReason,
    requested_capabilities: Vec<Capability>,
    evidence: Vec<AttachmentRef>,
    suggested_budget: WorkBudget,
    priority_hint: u16,
}
```

A request is a hypothesis, not proof that the requested worker is appropriate.

### 11.4 Work lease

```rust
struct WorkLease {
    lease_id: LeaseId,
    challenge_id: Option<ChallengeId>,
    objective: WorkObjective,
    seeds: Vec<InputId>,
    budget: WorkBudget,
    expires_at: CampaignTime,
    attempt: u16,
}
```

### 11.5 Result and termination

```rust
enum WorkTermination {
    ObjectiveSatisfied,
    BudgetExhausted,
    Unsupported,
    NoProgress,
    InfrastructureFailure,
    Cancelled,
}

struct WorkResult {
    lease_id: LeaseId,
    produced_inputs: Vec<InputId>,
    provisional_coverage: CoverageDigest,
    cpu_ns: u64,
    executions: u64,
    termination: WorkTermination,
    evidence: Vec<AttachmentRef>,
}
```

## 12. Communication implementation

Use LibAFL LLMP for local multi-process transport. It already provides a broker and low-overhead shared-memory messaging, with TCP broker connections available later.

Do not build an HTTP control API for the worker hot path.

Initial communication rules:

- batch telemetry;
- send candidate input bytes only when locally interesting or explicitly requested;
- use content hashes for deduplication;
- let workers retain local corpus caches;
- let the orchestrator remain the single authority for canonical corpus admission;
- make message handling idempotent;
- tolerate duplicate and out-of-order status messages;
- bound every queue;
- persist important events before acknowledging them when required for recovery.

Remote multi-host operation is a later transport concern. Protocol semantics must not depend on all workers sharing a filesystem.

## 13. Corpus and knowledge architecture

### 13.1 Content-addressed object store

Store raw inputs by hash:

```text
campaigns/<campaign-id>/
  manifest.json
  corpus/objects/ab/cd/<full-hash>
  corpus/metadata/<full-hash>.json
  crashes/objects/
  attachments/
  events/events.jsonl
  metrics/
  reports/
```

For early development, a filesystem object store plus a single-writer metadata database is sufficient. Do not introduce a distributed database.

### 13.2 Authoritative and local corpora

The orchestrator owns the authoritative canonical corpus. Each worker maintains a local optimized view.

Local corpora may temporarily contain candidates rejected by the canonical authority if they remain useful under worker-local instrumentation. Such entries must be marked local and must not appear in published canonical coverage totals.

### 13.3 Admission pipeline

1. Worker reports local novelty.
2. Orchestrator deduplicates by `InputId` and pending replay key.
3. Canonical coverage worker replays the input.
4. Input is accepted if it adds canonical coverage or satisfies another explicit admission objective.
5. Metadata and provenance are committed.
6. A corpus delta is broadcast selectively.
7. Crash-like behavior is queued for sanitizer replay.

### 13.4 Corpus minimization

Online admission should remain cheap. Periodic minimization may run outside the hot path and produce a new corpus snapshot. Never mutate or delete the only copy of provenance when minimizing.

## 14. Coverage, frontier, and challenge modeling

A global edge bitmap is not a complete model of unexplored branches.

Achlys should maintain several layers of knowledge:

- canonical covered edges;
- hit-count or rarity summaries;
- per-input canonical deltas;
- observed comparisons and operands;
- optional CFG adjacency from static analysis;
- concolic constraints associated with a concrete trace;
- lineage success and failure history;
- challenge attempts and outcomes.

### 14.1 Frontier definition

An exploration frontier is a set of seeds associated with evidence that nearby behavior may remain reachable. Evidence can include:

- rare edges;
- newly observed comparisons;
- partial comparison progress;
- novel state transitions;
- static CFG adjacency;
- a concolic branch predicate;
- repeated parser acceptance with stalled deeper coverage.

Do not manufacture a global “percentage covered” unless a valid denominator is independently defined.

### 14.2 Challenge deduplication

A challenge deduplication key should combine the stable elements available for that challenge type, such as:

```text
target build + branch site + comparison shape + seed lineage class
```

Repeated failed requests must not create an infinite work loop.

## 15. Orchestrator design

The orchestrator is a single logical authority in the first release. It can use multiple internal threads, but correctness must not depend on distributed consensus.

### 15.1 Responsibilities

- worker registration and health;
- campaign clock and budgets;
- canonical corpus admission;
- challenge creation and deduplication;
- task leasing;
- per-strategy cost and reward tracking;
- static and dynamic resource allocation;
- exploration floors and island policy;
- circuit breakers;
- experiment event logging;
- reproducible shutdown and resume.

### 15.2 Scheduling has three timescales

#### Fast timescale: local worker scheduling

Microseconds to milliseconds. LibAFL chooses seeds, mutation energy, and local stages without orchestrator involvement.

#### Medium timescale: challenge assignment

Seconds. The orchestrator assigns specific seeds or obstacles to compatible workers using leases.

#### Slow timescale: resource allocation

Tens of seconds to minutes. The orchestrator changes the number of slots devoted to each role.

Do not collapse all three decisions into one model.

### 15.3 Initial policy sequence

Implement policies in this order:

1. fixed homogeneous allocation;
2. fixed heterogeneous allocation;
3. rule-based challenge routing;
4. weighted round-robin task scheduling;
5. decayed reward allocation;
6. non-contextual bandit;
7. contextual bandit only if features and evidence justify it.

Every policy must implement the same interface and be selectable from the campaign manifest.

### 15.4 Reward model

Start with a simple observable reward:

```text
reward =
    canonical_new_edges_weighted_by_rarity
    + challenge_completion_bonus
    + verified_bug_bonus
    - normalized_cpu_cost
    - normalized_special_resource_cost
```

Do not tune a large reward formula before basic policies are benchmarked.

Important concerns:

- reward is non-stationary as the campaign progresses;
- delayed discoveries complicate attribution;
- imported seeds can create shared credit;
- coverage map collisions can distort reward;
- symbolic workers have long latency;
- cheap superficial edges must not always dominate difficult progress.

Use sliding windows or exponential decay. Retain raw components so reward can be recomputed offline.

### 15.5 Safety policy

The allocator must enforce:

- a minimum havoc allocation;
- a maximum specialist allocation;
- per-strategy budget ceilings;
- minimum residence periods;
- solver query limits;
- GPU cost limits;
- maximum concurrent tasks per challenge;
- automatic quarantine for crashing or unhealthy workers;
- fallback to a proven static policy.

## 16. Crash and timeout pipeline

Crash discovery and crash verification are separate.

### 16.1 Discovery

Workers report:

- signal;
- exit status;
- timeout;
- sanitizer marker if available;
- truncated stderr digest;
- input and build identity.

Execution infrastructure errors must never be converted into a normal target result.

### 16.2 Verification

A sanitizer replay worker must:

- replay the exact input;
- capture stdout and stderr;
- apply a strict timeout and process-group termination;
- record environment and artifact hashes;
- classify reproducibility;
- extract a normalized stack signature;
- distinguish target failure from harness or infrastructure failure.

### 16.3 Deduplication and minimization

Only verified, reproducible crashes enter the verified crash corpus. Minimized inputs retain links to original inputs and complete lineage.

Bug counts in reports must use verified ground truth or documented deduplication. Raw crash file count is never a valid performance metric.

## 17. Observability and experiment evidence

Every campaign must produce enough evidence to answer:

- which worker produced each accepted input;
- which strategy consumed each resource budget;
- why a role allocation changed;
- which challenge was requested, claimed, solved, abandoned, or retried;
- how canonical coverage evolved;
- what overhead the orchestrator introduced;
- whether the campaign experienced infrastructure failure.

### 17.1 Append-only event log

Persist a versioned append-only event stream. Events should be replayable into summary state. Periodic snapshots may accelerate restart, but the raw event stream remains authoritative for research analysis.

### 17.2 Metrics

At minimum record:

- executions and executions per second per worker;
- worker CPU time;
- candidate and canonical admission counts;
- canonical edges over time;
- corpus size and bytes;
- queue depths;
- broker traffic;
- candidate replay latency;
- challenge outcomes and costs;
- migrations and role residence;
- crash discovery and verification;
- model training and inference cost;
- solver queries and solver time;
- infrastructure errors.

### 17.3 Determinism

Record all RNG seeds and versions. Full deterministic reproduction may not be possible for concurrent campaigns, but each individual target input and crash must be reproducible.

## 18. Security and isolation

Achlys executes untrusted and often deliberately malformed targets.

The execution layer must eventually enforce:

- process-group termination;
- memory and CPU limits;
- file descriptor limits;
- isolated working directories;
- network disabled by default;
- explicit filesystem allowlists;
- bounded output capture;
- cleanup of temporary inputs;
- no shell interpolation for target arguments;
- no credential inheritance;
- optional container or namespace isolation for campaign workers.

AI services must not receive proprietary source, seeds, crashes, or target metadata unless the campaign explicitly permits it.

## 19. Proposed repository structure

Do not immediately split every module into a crate. Use this as the intended dependency direction.

```text
Achlys/
  crates/
    achlys-protocol/       pure message and identifier types
    achlys-bridge/         target builds, executors, harness contracts
    achlys-worker/         LibAFL worker runtime and local loops
    achlys-strategies/     havoc, cmplog, structure, concolic adapters
    achlys-orchestrator/   corpus authority, tasks, policies, allocation
    achlys-eval/           experiment manifests, runners, reports
    achlys-cli/            user-facing campaign commands
    achlys-ml/             optional experimental ML capabilities
  benchmarks/
    micro/
    manifests/
    expected/
  docs/
    MASTER_PLAN.md
    decisions/
    protocols/
  scripts/
    ci/
    experiments/
  campaigns/              ignored runtime data
```

Dependency direction:

```text
protocol <- bridge <- worker <- strategies
    ^           ^        ^          ^
    +-----------+--------+----------+
                orchestrator
                     ^
                    cli

eval depends on public campaign interfaces, not private worker internals.
ml implements strategy and policy interfaces; core crates do not depend on ml.
```

The current crates can migrate incrementally. Do not perform a repository-wide rename before Tranche 1 correctness is achieved.

## 20. Benchmark strategy

Benchmark infrastructure is a product feature, not cleanup work.

### 20.1 Benchmark layers

#### Microbenchmarks

Purpose: deterministic correctness and mechanism tests.

Include synthetic targets for:

- direct magic comparison;
- transformed comparison;
- checksum;
- nested parser validity;
- rare branch;
- stateful sequence;
- timeout and child-process cleanup;
- reproducible crash;
- non-crashing nonzero exit;
- coverage map stability.

Microbenchmarks prove that a mechanism works, not that the fuzzer is generally superior.

#### Development benchmark set

Use a small diverse subset of real parser targets for frequent experiments. Prefer targets already supported by FuzzBench or OSS-Fuzz.

#### Release benchmark set

Use a broader FuzzBench-compatible set and a known-bug suite such as MAGMA where feasible. Lock revisions and publish manifests.

### 20.2 Baselines

At minimum compare:

- AFL++ default;
- AFL++ with recommended comparison-aware configuration when relevant;
- minimal LibAFL havoc using the same harness;
- Achlys homogeneous havoc;
- Achlys static heterogeneous allocation;
- Achlys dynamic allocation;
- every experimental strategy ablation.

Comparisons must use equal physical cores, wall time, CPU affinity policy, memory limits, seeds, and target revisions. GPU use must be reported and either charged as a separate resource or presented as a separate experiment.

### 20.3 Trial ladder

#### Pull-request smoke

- deterministic unit and integration tests;
- 3 to 10 minute mechanism runs;
- no performance claims.

#### Development experiment

- at least 5 trials;
- typically 1 hour;
- small benchmark set;
- used to reject broken ideas, not publish broad claims.

#### Candidate experiment

- at least 10 trials;
- 6 to 12 hours where resources permit;
- broader targets;
- used for architectural decisions.

#### Release experiment

- target 20 trials of 24 hours;
- diverse real-world benchmarks;
- canonical measurement;
- statistical analysis and raw artifact publication.

FuzzBench reports use medians, confidence intervals, effect sizes, and significance tests. Achlys should reuse compatible analysis rather than invent favorable summaries.

### 20.4 Required reports

Every accepted experiment must preserve:

- campaign and target manifests;
- source and artifact hashes;
- raw metrics;
- event logs;
- corpora or corpus hashes;
- crashes and verification results;
- stdout and stderr logs;
- environment details;
- analysis code;
- plots and tables;
- failure and exclusion reasons.

## 21. Development quality gates

Every merge must satisfy, where applicable:

- `cargo fmt --check`;
- Clippy with warnings denied;
- unit tests;
- protocol compatibility tests;
- integration tests;
- no unbounded queues introduced;
- no silent infrastructure error conversion;
- no undocumented unsafe block;
- deterministic test seed;
- benchmark smoke when the hot path changes;
- clean campaign shutdown;
- repository builds from a clean clone.

Performance-sensitive changes require before-and-after evidence. A micro-optimization without a profile is not a priority.

## 22. Build tranches

### Tranche 0: truth reset and reproducible repository

Goal: make the current project honest, buildable, and suitable for incremental work.

Tasks:

1. Repair or replace the broken cJSON gitlink and restore clean-clone builds.
2. Make `cargo build`, `cargo test --workspace --all-targets`, formatting, and Clippy pass in CI.
3. Correct package and installation instructions.
4. Remove or clearly mark unsupported claims in README and the old architecture document.
5. Disable the false graybox `--source` route until child coverage is actually transported.
6. Make target launch and I/O errors explicit infrastructure failures.
7. Replace unbounded blackbox `ConstFeedback(true)` behavior.
8. Disable autonomous training until the training corpus is genuinely connected.
9. Pin Rust and important tool versions.
10. Add a small target and campaign smoke test that runs from a clean checkout.

Exit gate:

- clean clone builds and tests on Linux;
- CI green;
- no documented feature is known to be false;
- a five-minute smoke campaign produces bounded, inspectable artifacts;
- current limitations are explicit.

### Tranche 1: trustworthy single-worker baseline

Goal: implement a high-quality source-available graybox fuzzer baseline.

Tasks:

1. Define the target manifest and build identities.
2. Implement real in-process or persistent execution.
3. Implement stable shared-memory edge coverage.
4. Use a bounded persistent corpus.
5. Implement proper crash, timeout, and infrastructure result types.
6. Add sanitizer replay and crash deduplication.
7. Produce canonical campaign artifacts and metrics.
8. Add microbenchmarks for execution correctness.
9. Compare throughput and coverage with minimal LibAFL and AFL++ baselines.

Exit gate:

- H0 accepted or the regression explained and approved;
- worker hot path has no global coordination;
- crashes and timeouts reproduce;
- corpus remains bounded by novelty policy;
- canonical coverage can be replayed independently;
- results are reproducible from a manifest.

### Tranche 2: homogeneous multi-worker substrate

Goal: scale the proven worker across cores without changing strategy.

Tasks:

1. Add LLMP broker and launcher integration.
2. Define `achlys-protocol` identifiers and versioning.
3. Run multiple havoc workers with local corpora.
4. Implement authoritative candidate admission and corpus deltas.
5. Add content-addressed storage and provenance.
6. Add bounded queues, idempotency, restart, and late worker join.
7. Measure scaling from 1 to 2, 4, 8, and available higher core counts.

Exit gate:

- near-linear useful scaling until target or host saturation;
- no corpus corruption or duplicate explosion;
- worker crash and restart do not lose accepted corpus entries;
- coordinator overhead is measured and within the H0 budget;
- global results can be reconstructed from event logs.

### Tranche 3: static heterogeneous portfolio

Goal: prove that specialist diversity can add value before building adaptive allocation.

Tasks:

1. Add CmpLog build and worker capability.
2. Add structure-aware baseline capability.
3. Implement a fixed role allocation manifest.
4. Synchronize canonical discoveries across roles.
5. Compare homogeneous havoc against several static allocations.
6. Record per-role cost and accepted discoveries.

Exit gate:

- H1 evaluated on micro and real targets;
- at least one defensible target class shows positive heterogeneous value;
- no aggregate regression is hidden by cherry-picked targets;
- the best static allocation is identified for the next tranche.

If no heterogeneous allocation provides value, stop and investigate before orchestration work.

### Tranche 4: challenge protocol and targeted assistance

Goal: make cross-strategy cooperation more useful than blind seed sharing.

Tasks:

1. Define comparison and structural challenge evidence.
2. Implement `AssistanceRequest`, challenge deduplication, and leases.
3. Route selected seeds to compatible specialists.
4. Return solved candidates with full provenance.
5. Implement budget exhaustion and failure caching.
6. Compare targeted assistance with blind periodic corpus synchronization.

Exit gate:

- H2 evaluated;
- complete request-to-result evidence exists;
- duplicate specialist work is bounded;
- challenge completion improves time-to-target on the obstacle suite;
- no worker can monopolize the campaign through request spam.

### Tranche 5: adaptive orchestration

Goal: dynamically allocate tasks and resources according to measured marginal value.

Tasks:

1. Implement common policy interface.
2. Add weighted round-robin and decayed reward baselines.
3. Add a non-contextual bandit policy.
4. Enforce exploration floor and role hysteresis.
5. Implement policy replay against recorded event streams where possible.
6. Compare dynamic policies against the best static allocation, not only an average allocation.
7. Run ablations for reward components.

Exit gate:

- H3 evaluated on a diverse benchmark set;
- dynamic allocation beats or meaningfully complements the best static policy;
- gains survive multiple trials and are not caused by unequal resources;
- policy decisions are explainable from recorded state;
- a static fallback remains available.

### Tranche 6: concolic assistance

Goal: add a bounded high-cost solver for obstacles unsuited to comparison mutation.

Tasks:

1. Integrate LibAFL concolic tracing and SymCC runtime.
2. Define concolic challenge eligibility.
3. Select branches rather than solve every observed predicate.
4. Add query, memory, and wall-time budgets.
5. Cache unsupported, unsatisfiable, and repeated constraints.
6. Feed solutions back through canonical admission.
7. Compare against AFL++ CmpLog and static concolic schedules.

Exit gate:

- H4 evaluated;
- solver work is bounded and observable;
- concolic candidates are reproducible;
- aggregate benefit justifies resource use on the declared target class.

### Tranche 7: ML experiments

Goal: evaluate specific ML capabilities without making the core depend on their success.

Tasks, in preferred order:

1. Offline dictionary and grammar extraction.
2. Lightweight strategy or task-value prediction.
3. Seed-to-worker matching.
4. Only then, learned candidate generation.
5. Compare every ML method to a cheap task-specific baseline.
6. Track training, inference, model serving, GPU, and failure costs.
7. Store model, dataset, split, and version artifacts.

Exit gate:

- H5 accepted for a precisely defined target class, or rejected and the ML capability disabled;
- no claim uses raw model output as evidence of fuzzing impact;
- equal-resource and wall-clock comparisons are both reported;
- data leakage and train/test contamination are excluded.

### Tranche 8: release-grade evaluation and distribution

Goal: prepare an alpha that is credible on a CV, in a paper artifact, and to external reviewers.

Tasks:

1. Integrate with FuzzBench conventions.
2. Run release-scale trials.
3. Publish raw results and analysis.
4. Freeze supported target classes and limitations.
5. Add stable CLI and campaign documentation.
6. Add multi-host transport only if local architecture is proven.
7. Add TUI or dashboard only after metrics semantics stabilize.

Exit gate:

- clean installation and tutorial;
- independently reproducible results;
- honest comparison against strong AFL++ configurations;
- supported claims backed by release experiment artifacts;
- unsupported claims removed.

## 23. Immediate pull-request sequence

Future agents should prefer small reviewable changes in this order:

1. `build: restore clean-clone workspace and CI`
2. `docs: align public claims with implemented behavior`
3. `core: introduce explicit execution and infrastructure outcomes`
4. `bridge: add real in-process persistent target contract`
5. `corpus: replace unbounded blackbox corpus behavior`
6. `eval: add deterministic micro-target suite`
7. `campaign: add manifest and artifact identities`
8. `coverage: add canonical replay authority`
9. `crash: add sanitizer verification pipeline`
10. `worker: establish measured single-worker baseline`
11. `protocol: add versioned IDs and discovery events`
12. `multi: add LLMP homogeneous workers`

Do not combine repository restructuring, execution redesign, ML changes, and scheduler changes in one pull request.

## 24. Anti-patterns and forbidden shortcuts

### 24.1 No fake graybox

Compiling a child process with instrumentation is not graybox fuzzing unless the fuzzer receives and uses its coverage.

### 24.2 No “interesting=true” corpus

Do not retain every blackbox execution. A corpus admission policy must have a bounded behavioral objective.

### 24.3 No silent target errors

Missing binaries, failed writes, spawn errors, observer failures, and broken instrumentation are infrastructure failures, not successful executions.

### 24.4 No invented percentages

Do not claim that havoc covers 70% or symbolic starts at 90% without a valid, target-specific denominator and evidence.

### 24.5 No AI on the hot path by default

No remote LLM request or heavyweight model call per execution. Batch and isolate expensive generation.

### 24.6 No benchmark by anecdote

Finding one synthetic crash proves mechanism correctness, not superiority.

### 24.7 No unfair baseline

Do not compare six Achlys cores plus a GPU against one default AFL++ process. Match resources and use strong documented configurations.

### 24.8 No phase completion by code existence

A feature is complete when its acceptance evidence exists, not when a type, CLI flag, or enum variant exists.

### 24.9 No distributed system before local correctness

Remote brokers, databases, and dashboards are prohibited until homogeneous local multi-worker execution passes Tranche 2.

### 24.10 No novelty claim based only on orchestration

Ensemble and collaborative fuzzing already exist. Achlys novelty must be demonstrated through its specific challenge protocol, provenance, cross-capability assistance, canonical measurement, and cost-aware allocation.

## 25. Review checklist for each completed tranche

When the user requests a tranche review, the reviewing agent must answer:

### Correctness

- Does the implementation do what the tranche says?
- Are errors explicit?
- Are queues, corpora, outputs, and processes bounded?
- Does it survive restart and malformed target behavior?

### Architecture

- Is the hot path isolated from the control plane?
- Are dependencies pointing in the intended direction?
- Is provenance retained?
- Can the experimental component be disabled?

### Performance

- What is the measured overhead?
- Is the comparison equal-resource?
- Are regressions separated from infrastructure incidents?
- Are results stable across trials?

### Research validity

- Which hypothesis was tested?
- What baseline was used?
- What evidence could falsify the claim?
- Were negative and excluded results retained?

### Handoff

- Exact commands used.
- Exact artifact paths.
- Git commit and dirty state.
- Known limitations.
- Decision: accept tranche, revise tranche, or reject approach.

## 26. Decision log required from future agents

Every material architectural decision should receive a short record under `docs/decisions/` containing:

- context;
- decision;
- alternatives considered;
- expected consequence;
- benchmark or evidence required;
- date and responsible change;
- later superseding decision if any.

Examples:

- canonical coverage instrumentation choice;
- corpus metadata store choice;
- default worker epoch length;
- initial reward policy;
- concolic eligibility rule;
- whether a given ML capability survives evaluation.

## 27. Success ladder

Achlys should claim only the highest level it has actually demonstrated.

### Level 0: buildable prototype

The repository builds, tests, and runs a bounded campaign.

### Level 1: credible fuzzer

Single-worker behavior is reproducible, crashes are verified, and performance is competitive with its LibAFL baseline.

### Level 2: credible cooperative fuzzer

Multiple heterogeneous workers exchange accepted seeds and targeted assistance under equal-resource experiments.

### Level 3: adaptive research result

Dynamic allocation beats the best tested static allocation across a meaningful benchmark set.

### Level 4: competitive alpha

Achlys is statistically competitive with strong AFL++ configurations overall and superior on a declared target class.

### Level 5: publishable claim

Release-scale independent experiments, ablations, raw artifacts, and external reproduction support the claim.

Do not use Level 4 or Level 5 language while the project remains at Level 0 or Level 1.

## 28. Recommended public positioning

Until release evidence exists:

> Achlys is an experimental cooperative fuzzing system built on LibAFL. It investigates whether typed cross-strategy assistance and cost-aware worker allocation can improve coverage and hard-branch discovery under equal resource budgets.

If the adaptive experiments succeed:

> Achlys is a cooperative hybrid fuzzer that routes difficult inputs between specialized workers and dynamically reallocates compute according to measured marginal progress.

Avoid “hunts zero-days in any binary.” It is unverifiable, undersells the actual research question, and invites comparison on unsupported target classes.

## 29. Why this plan has research potential

The individual ingredients have prior art:

- AFL++ already supports parallel heterogeneous campaigns and queue synchronization.
- EnFuzz demonstrated value from diverse fuzzer ensembles and seed synchronization.
- CollabFuzz studied centrally informed collaborative scheduling.
- autofz demonstrated runtime composition and dynamic resource allocation among existing fuzzers.
- multi-armed-bandit schedulers have been applied to seeds, mutation operators, objectives, and fuzzer allocation.
- LibAFL already provides LLMP and concolic building blocks.
- ML-guided fuzzing has both promising niche results and strong negative reevaluations.

Achlys therefore needs a sharper contribution than “an ensemble with AI.” Its strongest possible contribution is the integration and evaluation of:

1. typed, evidence-carrying assistance requests;
2. branch or obstacle-oriented challenge ownership;
3. full input and resource provenance;
4. canonical measurement across heterogeneous instrumentation;
5. two-level adaptation of task routing and resource slots;
6. explicit marginal value accounting for expensive capabilities;
7. a system that can reject its own ML strategy when it is not useful.

This is ambitious but falsifiable. That is the correct standard.

## 30. Novel research bets

The architecture above can produce a strong cooperative fuzzer, but cooperation and dynamic allocation are not novel by themselves. EnFuzz synchronizes seeds among diverse fuzzers. CollabFuzz adds centrally informed scheduling. autofz reallocates resources among fuzzers at runtime. Multiple fuzzers already use bandits for seed, mutation, objective, or fuzzer selection.

Achlys must therefore push cooperation below the level of “which fuzzer gets how many cores?” and above the level of “copy this seed into every queue.”

The intended research identity is:

> Achlys organizes temporary teams around concrete exploration frontiers. Workers exchange typed challenge capsules and reusable knowledge artifacts, not only seeds. The orchestrator learns from both successful and failed assistance, controls when discoveries diffuse between worker islands, and can synthesize validated low-cost mutation skills from runtime evidence.

The ideas below are research bets, not established claims. “Novelty confidence” means that the initial review did not find an exact equivalent combining the same mechanism and scope. It is not a substitute for a systematic literature review or patent review before publication.

### 30.1 Ranked portfolio

| Bet | Expected value | Engineering risk | Novelty confidence | Earliest tranche |
|---|---:|---:|---:|---:|
| Frontier Capsules | Very high | Medium | Medium-high | 4 |
| Knowledge Artifacts | Very high | Medium-high | High | 4 |
| Failure Memory | High | Low-medium | Medium-high | 4 |
| Frontier Teams | High | Medium-high | Medium-high | 5 |
| Adaptive Diffusion | High | Medium | Medium | 5 |
| Constraint Contracts | High | High | High | 6 |
| Active Probing Worker | Medium-high | High | Medium | 6 |
| Scout Tournaments | Medium-high | Medium | Medium | 5 |
| Sandboxed Mutation Skill Synthesis | Very high if successful | Very high | Medium-high | 7 |
| Cross-campaign Capability Prior | Medium-high | High | Medium | 7 or later |
| Shadow Policy Laboratory | Medium | High | Medium-high | 5 or later |

The first three should influence protocol design even before they are fully implemented. The ML-related bets must not delay the non-ML system.

### 30.2 Bet A: Frontier Capsules

### Problem

Traditional collaborative fuzzing mostly shares successful testcases. A raw testcase says little about why it matters, what obstacle it reached, which attempts already failed, or which specialist should work on it.

### Idea

Represent a promising exploration frontier as a portable, evidence-carrying `FrontierCapsule`.

```rust
struct FrontierCapsule {
    capsule_id: CapsuleId,
    target: TargetId,
    seed: InputId,
    lineage_summary: LineageSummary,
    frontier_evidence: Vec<FrontierEvidence>,
    canonical_delta: CoverageDigest,
    local_traces: Vec<AttachmentRef>,
    artifacts: Vec<KnowledgeArtifactRef>,
    failed_attempts: Vec<AttemptSummary>,
    open_questions: Vec<ChallengeHypothesis>,
    priority: FrontierPriority,
    budget_spent: ResourceCost,
}
```

Possible evidence:

- comparison site and operands;
- input byte ranges correlated with the comparison;
- rare edge or dominator reached;
- parser acceptance depth;
- state transition;
- observed checksum-like behavior;
- concolic predicate;
- structural region annotations;
- multiple near-miss inputs.

The capsule moves between workers and accumulates knowledge. It is not duplicated as an unstructured seed in every queue.

### Why it may matter

- It makes assistance targeted and explainable.
- It prevents specialists from rediscovering context.
- It permits failure caching.
- It makes complex multi-worker paths auditable.
- It creates a natural unit for budgeting, leasing, and frontier-level scheduling.

### Research question

Does scheduling and transferring capsules outperform seed-only synchronization under equal resources?

### Required baseline

- ordinary global seed synchronization;
- seed plus minimal metadata;
- full Frontier Capsule.

### Stop condition

Reject or simplify the capsule model if serialization, replay, and scheduling cost exceeds its measured assistance benefit or if most fields remain unused.

### 30.3 Bet B: Knowledge Artifacts instead of seed-only collaboration

### Problem

When a specialist solves one obstacle, conventional collaboration usually shares only the resulting input. The reasoning or reusable mechanism that produced the input is lost.

### Idea

Workers may emit reusable, scoped `KnowledgeArtifact` objects.

```rust
enum KnowledgeArtifact {
    TokenSet(TokenSetArtifact),
    ComparisonRecipe(ComparisonRecipeArtifact),
    ByteInfluenceMap(ByteInfluenceArtifact),
    ProtectedRegions(ProtectedRegionsArtifact),
    GrammarFragment(GrammarFragmentArtifact),
    LengthFieldRelation(FieldRelationArtifact),
    ChecksumRepair(RepairArtifact),
    ConstraintContract(ConstraintContractArtifact),
    StateSequence(StateSequenceArtifact),
    MutationSkill(MutationSkillArtifact),
    NegativeCapability(NegativeCapabilityArtifact),
}
```

Examples:

- CmpLog discovers a constant and publishes a token plus the positions where it was effective.
- A concolic worker publishes a constraint over bytes 12 through 15 rather than only one satisfying input.
- A structure worker publishes that bytes 4 through 7 encode payload length in little endian.
- A checksum worker publishes a bounded repair function.
- A stateful worker publishes a message prefix that reaches a protocol state.
- A failed solver publishes that a predicate uses an unsupported floating-point operation.

Artifacts must carry:

- provenance;
- target and build scope;
- confidence;
- validation evidence;
- applicability predicate;
- expiration or invalidation condition;
- production and validation cost;
- versioned representation.

### Artifact promotion pipeline

```text
Untrusted candidate
        |
        v
Local validation on held-out seeds
        |
        v
Campaign-scoped artifact
        |
        v
A/B evidence from independent workers
        |
        v
Promoted reusable artifact
```

No worker may inject executable native code directly into another worker. Executable artifacts must use a bounded DSL or separately reviewed plugin mechanism.

### Why it may matter

One expensive solve can improve thousands of later havoc mutations. This changes specialist work from producing isolated testcases to teaching the whole campaign.

### Research question

Does sharing reusable artifacts provide greater downstream canonical coverage per specialist CPU-second than sharing only specialist-generated seeds?

### Strongest potential differentiator

This is one of the best candidates for Achlys's signature contribution. Existing ensemble systems commonly synchronize seeds or allocate fuzzers. Achlys should attempt to synchronize learned operational knowledge with explicit scope and validation.

### 30.4 Bet C: Failure Memory

### Problem

Fuzzing systems celebrate discoveries but often discard structured information about expensive failures. Another worker later repeats the same unsupported solve, ineffective mutation family, or invalid structural transformation.

### Idea

Treat failed work as campaign knowledge.

```rust
struct FailedAttemptRecord {
    challenge_key: ChallengeKey,
    capability: Capability,
    strategy_version: StrategyVersion,
    budget: WorkBudget,
    termination: WorkTermination,
    failure_class: FailureClass,
    evidence_digest: EvidenceDigest,
    retry_after: Option<CampaignTime>,
}
```

Failure classes include:

- unsupported operation;
- unsatisfiable under current model;
- solver timeout;
- model produced invalid candidates;
- repair invalidated protected bytes;
- no marginal coverage after a statistically meaningful sample;
- infrastructure failure, which must not count as strategy failure.

### Uses

- suppress duplicate requests;
- reduce predicted success for a capability and challenge class;
- choose a different worker;
- increase a budget only when new evidence changes the problem;
- distinguish “not yet solved” from “same failed attempt repeated.”

### Why it may be novel

The important part is not negative caching alone. It is feeding typed negative outcomes into capability calibration and future routing decisions.

### Risk

Overgeneralized failure memory can suppress a later valid strategy. Records therefore require narrow scope, versioning, decay, and invalidation when new artifacts arrive.

### 30.5 Bet D: Frontier Teams

### Problem

Global role allocation asks how many cores should run havoc, CmpLog, or concolic execution. It does not ask which mixture should attack each frontier.

### Idea

The orchestrator forms temporary micro-teams around high-value Frontier Capsules.

Example:

```text
Frontier A: structured header plus hard comparison
  2 havoc exploit workers
  1 comparison worker
  1 structure repair worker
  budget: 90 seconds

Frontier B: rare edge with no comparison evidence
  1 rare-edge havoc worker
  1 active probing worker
  budget: 45 seconds

Independent exploration islands
  remaining workers
```

The team exists only for a lease window. Its workers retain their implementations but receive a common capsule, objective, and artifact view.

### Scheduling hierarchy

1. Allocate total budget between independent exploration and frontier teams.
2. Select which frontiers deserve teams.
3. Select a capability composition for each team.
4. Allocate tasks within each team.
5. Dissolve, resize, or renew teams based on marginal progress.

### Novelty target

autofz dynamically composes fuzzers at runtime. Achlys should differentiate itself through frontier-scoped, evidence-driven team formation rather than campaign-wide fuzzer trends alone.

### Evaluation

Compare:

- global dynamic role allocation;
- frontier teams without typed artifacts;
- frontier teams with capsules and artifacts.

### 30.6 Bet E: Adaptive Diffusion and deliberate information embargo

### Problem

Immediate global synchronization creates a thundering herd. Every worker sees the same successful seed, converges on the same region, and loses independent exploration diversity.

Never synchronizing wastes discoveries. Fixed periodic synchronization ignores the value and maturity of each seed.

### Idea

Treat propagation as a scheduled action.

Every accepted input receives a diffusion policy:

- global immediately;
- specialist-only;
- selected islands;
- delayed global release;
- capsule team only;
- quarantine pending canonical or sanitizer replay.

The orchestrator learns or heuristically selects when and where to release a discovery.

Possible signals:

- edge rarity;
- lineage saturation;
- number of islands already covering the region;
- challenge type;
- seed structural quality;
- expected complementarity of recipient workers;
- recent global convergence.

### Island entropy

Maintain a diversity signal between worker corpora or coverage distributions. Do not optimize it blindly, but use it to detect collapse into identical exploration.

### Research question

Can adaptive seed and artifact diffusion preserve useful exploration diversity while still exploiting specialist breakthroughs?

### Required baseline

- immediate global broadcast;
- fixed interval sync;
- fixed island model;
- adaptive diffusion.

### 30.7 Bet F: Constraint Contracts and cooperative repair

### Problem

One specialist's solution can destroy another specialist's achievement.

Examples:

- concolic solving satisfies a branch but breaks a checksum;
- grammar repair restores validity but changes the bytes satisfying a comparison;
- havoc mutates a newly solved magic field immediately;
- length repair changes an offset used by another constraint.

### Idea

Workers exchange explicit `ConstraintContract` artifacts that describe what must be preserved and what may change.

```rust
struct ConstraintContract {
    protected_regions: Vec<ByteRegion>,
    symbolic_relations: Vec<FieldRelation>,
    repair_obligations: Vec<RepairObligation>,
    validity_checks: Vec<ValidationPredicate>,
    scope: ApplicabilityPredicate,
}
```

A pipeline can then compose workers:

```text
concolic candidate
    -> preserve solved branch bytes
    -> structure worker repairs lengths
    -> checksum worker repairs checksum
    -> canonical replay verifies branch and coverage
    -> havoc worker mutates only permitted regions for an initial lease
```

### Why it may matter

Hybrid fuzzers often treat generated inputs as atomic outputs. Constraint contracts allow specialists to compose transformations instead of repeatedly invalidating one another.

### Main difficulty

Byte regions are not always independent. Repairs can shift offsets or change derived values. The first version must support only explicit fixed-offset and simple field-relation contracts. Do not begin with a universal constraint language.

### 30.8 Bet G: Active Probing Worker

### Problem

Routing is difficult when Achlys does not know which input bytes influence a frontier predicate or whether a barrier is structural, arithmetic, or stateful.

### Idea

Create a worker whose objective is information gain rather than immediate coverage.

It performs controlled perturbations around one seed to estimate:

- byte-to-edge influence;
- byte-to-comparison influence;
- protected structural regions;
- likely field boundaries;
- monotonic distance relationships;
- whether a comparison is directly controllable.

It emits `ByteInfluenceMap`, `FieldBoundary`, and `ChallengeClassification` artifacts.

This is related to taint-guided fuzzing and systems such as Angora and Matryoshka. Achlys's research angle must therefore be the use of bounded active experiments to create portable artifacts for heterogeneous routing, not a claim to invent input-byte influence.

### Value test

The worker is valuable only if the cost of probing is recovered through better downstream routing or mutation efficiency.

### Cheap baseline

Compare against:

- direct dynamic taint where available;
- comparison logging alone;
- random mutation sensitivity;
- no influence artifact.

### 30.9 Bet H: Scout Tournaments before full allocation

### Problem

The allocator may lack enough evidence to decide whether a challenge deserves havoc, comparison solving, structure-aware mutation, or concolic work.

### Idea

Run a small bounded tournament:

1. Give the same capsule to several compatible strategies.
2. Allocate a tiny scout budget to each.
3. Measure partial progress, validity, comparison distance, and cost.
4. Allocate the main budget to the most promising strategy or combination.

This is not a permanent duplicate campaign. It is an information-gathering phase for uncertain high-value challenges.

### Partial progress signals

- canonical edge delta;
- comparison operand distance;
- parser depth;
- number of newly valid structures;
- constraint simplification;
- state transition proximity;
- candidate diversity.

### Risk

Scout tournaments waste compute if used too frequently. Restrict them to high-value challenges with high routing uncertainty.

### 30.10 Bet I: Sandboxed Mutation Skill Synthesis

### Problem

Direct LLM input generation is expensive and slow. Generic next-byte models struggle to produce both valid and bug-revealing inputs. Human-written structure-aware mutators are effective but expensive to create.

Recent systems already use LLMs to synthesize input generators or mutators, including G2FUZZ and Mut4All. Achlys must not claim this general idea as new.

### Achlys-specific direction

Use runtime Frontier Capsules, comparison evidence, accepted corpus examples, and failed attempts to synthesize small reusable mutation skills in a bounded DSL.

The LLM is called rarely. It does not emit fuzz inputs directly and does not emit unrestricted native code. It emits a candidate transformation such as:

```text
skill png_chunk_length_repair {
    when bytes[1..4] == "PNG";
    read_u32_be length at chunk.offset;
    set_u32_be length = chunk.payload.size;
    preserve region challenge.magic_bytes;
}
```

The skill is then:

1. parsed and type-checked;
2. sandboxed;
3. tested against held-out corpus inputs;
4. checked for runtime and output bounds;
5. A/B tested against a control worker;
6. promoted only if it produces measurable value;
7. versioned and attributable to its evidence and model.

### Mutation skill DSL requirements

- total or forcibly bounded execution;
- no filesystem, process, or network access;
- bounded input and output size;
- deterministic mode for reproduction;
- structured random primitives supplied by the worker;
- byte, integer, checksum, token, and region operations;
- explicit preconditions and postconditions;
- preserved-region support;
- easy interpretation and logging;
- compilation to a low-overhead representation.

WASM may be considered later, but a small purpose-built DSL is safer and easier to analyze initially.

### Research question

Can sparse, challenge-conditioned synthesis of validated mutation programs outperform both direct LLM generation and fixed structure-aware mutators in marginal coverage per total compute and monetary cost?

### Stop condition

Reject the feature if synthesized skills mostly reproduce available dictionary, grammar, or repair operators, or if their validation cost exceeds their campaign value.

### 30.11 Bet J: Cross-campaign Capability Prior

### Problem

Every new campaign initially has little evidence for allocating workers. A fully cold-start bandit wastes early campaign time.

### Idea

Learn a prior over strategy usefulness from previous campaigns using target and early-run fingerprints.

Possible features:

- seed entropy and length distribution;
- early coverage growth shape;
- comparison density and types;
- parser validity rate;
- target execution speed;
- branch rarity profile;
- observed statefulness;
- proportion of structured tokens;
- source or binary metadata that is safe to use.

The prior only initializes the online allocator. Current-campaign evidence must be able to override it quickly.

### Research risk

- benchmark leakage;
- overfitting to target families;
- unstable instrumentation features;
- incorrect confidence on novel targets.

Evaluation requires leave-one-project-out or leave-one-family-out splits. Randomly splitting campaigns from the same target is not acceptable.

### 30.12 Bet K: Shadow Policy Laboratory

### Problem

Testing every allocator policy through full multi-day campaigns is expensive. Online changes also make it difficult to understand whether a policy decision was good.

### Idea

Run shadow policies that observe campaign state and log what they would have assigned without controlling workers.

Propensity and decision-context logging may later support cautious off-policy analysis. Exact counterfactual replay is impossible because a different assignment changes future discoveries. The system must never present shadow results as equivalent to real trials.

Useful outputs:

- policy disagreement rate;
- resource allocation divergence;
- challenges one policy would starve;
- estimated immediate reward on tasks that happened to match;
- candidate policies worth a real experiment.

### Value

This can reduce the number of obviously bad policies promoted to expensive experiments and makes allocator development more inspectable.

### 30.13 The flagship composition

The most coherent long-term Achlys contribution is not any single bet. It is the following loop:

```text
1. Independent workers explore locally.
2. A worker identifies a frontier and creates a Frontier Capsule.
3. The orchestrator consults positive and negative capability memory.
4. If routing confidence is low, small scout workers compete.
5. A temporary Frontier Team receives the capsule.
6. Specialists return candidates and reusable Knowledge Artifacts.
7. Constraint Contracts preserve discoveries across repair steps.
8. Canonical replay validates global progress.
9. Adaptive Diffusion decides which islands receive the seed and artifacts.
10. The allocator updates capability value from full cost and outcome evidence.
11. If existing capabilities repeatedly fail, a sandboxed mutation skill may be synthesized and experimentally promoted.
```

This pushes the original worker vision in a defensible direction. Workers do not merely “talk.” They collaborate through an accumulating technical object, and the output of expensive work can change the behavior of cheap workers.

### 30.14 Protocol changes required by the novel bets

The earlier protocol should eventually add:

```rust
struct KnowledgeArtifactEnvelope {
    artifact_id: ArtifactId,
    kind: ArtifactKind,
    producer: WorkerId,
    producer_version: StrategyVersion,
    scope: ArtifactScope,
    confidence: Confidence,
    validation: ValidationSummary,
    cost: ResourceCost,
    payload: AttachmentRef,
}

struct CapsuleUpdate {
    capsule_id: CapsuleId,
    base_revision: u64,
    added_artifacts: Vec<ArtifactId>,
    added_attempts: Vec<AttemptSummary>,
    new_hypotheses: Vec<ChallengeHypothesis>,
    observed_progress: ProgressVector,
}
```

Capsule updates require optimistic revision checks or single-writer orchestration. Do not create distributed shared mutable capsule state.

### 30.15 Additional hypotheses

### H6: capsule value

Frontier Capsules improve specialist success or reduce redundant work compared with seed-only transfer.

### H7: knowledge transfer value

Reusable Knowledge Artifacts produce downstream discoveries that would not be obtained, or would be obtained later, from sharing specialist-generated seeds alone.

### H8: failure memory value

Typed negative outcomes reduce repeated expensive work without suppressing later valid solutions.

### H9: diffusion value

Adaptive propagation improves aggregate coverage by balancing exploitation and island diversity better than immediate broadcast or fixed interval synchronization.

### H10: compositional assistance value

Constraint Contracts let multiple specialists compose successful transformations more reliably than independent atomic candidate generation.

### H11: synthesized skill value

Challenge-conditioned mutation skills provide positive marginal value over fixed cheap baselines after including model, validation, and execution costs.

### 30.16 Novelty gates

Before calling any bet novel in public:

1. Conduct a systematic related-work search using the exact mechanism, not only the product vocabulary.
2. Read the full papers and artifacts for EnFuzz, CollabFuzz, autofz, Angora, Matryoshka, Redqueen, SymCC, current LibAFL, G2FUZZ, Mut4All, and relevant recent systems.
3. Write a mechanism-by-mechanism comparison table.
4. Identify the smallest claim not already demonstrated.
5. Implement an ablation that isolates that claim.
6. Avoid combining several known techniques and calling the combination novel without evidence of an emergent advantage.

The target paper claim should look like this:

> Under equal resources, typed frontier capsules plus reusable knowledge artifacts reduce redundant specialist work and improve time-to-hard-branch compared with seed-only collaborative fuzzing.

It should not look like this:

> Achlys is the first multi-agent AI fuzzer.

## 31. References and implementation anchors

Primary and official references to consult before implementing the relevant tranche:

- [LibAFL message passing and LLMP](https://aflplus.plus/libafl-book/message_passing/message_passing.html)
- [LibAFL spawning and multi-client configuration](https://aflplus.plus/libafl-book/message_passing/spawn_instances.html)
- [LibAFL concolic tracing and hybrid fuzzing](https://aflplus.plus/libafl-book/advanced_features/concolic/concolic.html)
- [AFL++ features](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/features.md)
- [AFL++ parallel and heterogeneous campaign guidance](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md)
- [EnFuzz: Ensemble Fuzzing with Seed Synchronization among Diverse Fuzzers](https://www.usenix.org/conference/usenixsecurity19/presentation/chen-yuanliang)
- [CollabFuzz: A Framework for Collaborative Fuzzing](https://research.vu.nl/en/publications/collabfuzz-a-framework-for-collaborative-fuzzing/)
- [autofz: Automated Fuzzer Composition at Runtime](https://arxiv.org/abs/2302.12879)
- [T-Scheduler: multi-armed-bandit seed scheduling](https://arxiv.org/abs/2312.04749)
- [SymCC: compilation-based symbolic execution](https://www.usenix.org/system/files/sec20-poeplau.pdf)
- [Revisiting Neural Program Smoothing for Fuzzing](https://arxiv.org/abs/2309.16618)
- [Learn&Fuzz](https://arxiv.org/abs/1701.07232)
- [ChatAFL: LLM-guided protocol fuzzing](https://www.ndss-symposium.org/ndss-paper/large-language-model-guided-protocol-fuzzing/)
- [G2FUZZ: LLM-synthesized input generators](https://www.usenix.org/system/files/conference/usenixsecurity25/sec25cycle1-prepub-1291-zhang-kunpeng.pdf)
- [Mut4All: LLM-synthesized mutators](https://arxiv.org/abs/2507.19275)
- [Matryoshka: fuzzing deeply nested branches](https://web.cs.ucdavis.edu/~hchen/paper/chen2019matryoshka.pdf)
- [FuzzBench methodology](https://google.github.io/fuzzbench/)
- [FuzzBench reports and statistical analysis](https://google.github.io/fuzzbench/reference/report/)

These references provide context, not permission to copy their claims. Achlys results must come from Achlys experiments.

## 32. Final directive

Build the fastest trustworthy baseline first. Then prove cooperation. Then prove adaptation. Then add expensive intelligence one capability at a time.

The project must be designed so that havoc can run alone, specialists can fail safely, the allocator can fall back to a static policy, and ML can be removed without damaging the system.

If Achlys eventually beats AFL++ on a meaningful target class, it will not be because it contains more buzzwords. It will be because it spends each unit of compute on the right problem, transfers evidence cleanly between complementary techniques, and can prove the result.
