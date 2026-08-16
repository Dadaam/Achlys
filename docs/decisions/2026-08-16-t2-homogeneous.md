# Decision: open T2 homogeneous multi-worker implementation

- Date: 2026-08-16
- Decision: **open Tranche 2 implementation**. Do **not** accept T2. Do **not** start T3 (CmpLog / heterogeneous), T4 (leases / assistance), adaptive allocation, or ML.
- Ground truth: `docs/MASTER_PLAN.md` §22 Tranche 2, §6, §9, §11–13, §15.2, §24.8.

This supersedes the “do not start T2” sentence in
[`2026-08-16-t1-baseline-accepted.md`](2026-08-16-t1-baseline-accepted.md)
for **implementation work only**. The T1 scientific caveats stand: AFL++
smoke figures stay unpublished, and T2 is not closed until the Linux
multi-trial ladder defined below is executed.

## Context

T1 is accepted as baseline infrastructure. The user has no Linux host
today and will have one in the coming days. Homogeneous multi-worker
code can be written and smoke-tested on macOS aarch64. Scaling evidence
cannot.

T2 goal (Master Plan): scale the proven havoc worker across cores
**without changing strategy**.

## Tasks (Master Plan §22 T2)

1. LLMP broker and launcher integration.
2. `achlys-protocol` worker identifiers and versioning.
3. Multiple havoc workers with local corpora.
4. Authoritative candidate admission and corpus deltas.
5. Content-addressed storage and provenance (already T1; T2 must attach
   `worker_id` + sender sequence).
6. Bounded queues, idempotency, restart, and late worker join.
7. Measure scaling from 1 to 2, 4, 8, and available higher core counts.

## What T2 is not

- Not CmpLog, structure-aware, concolic, or mixed roles (T3).
- Not `AssistanceRequest`, `WorkLease`, or challenge routing (T4).
- Not adaptive slot allocation (T5).
- Not a public AFL++ comparison.
- Not a T2 accept. Exit-gate language (“near-linear scaling”) is
  forbidden until the Linux ladder runs.

## Architecture

```text
launcher (parent)
  ├─ compile one canonical dump (shared BuildId)
  ├─ CampaignStore (single writer of events.jsonl)
  ├─ spawn admit process  ── DumpOracle ── CorpusAuthority
  │         ▲ spool/inbox                  │
  │         │                              ▼
  │         │                      spool/deltas/<seq>.json
  └─ LibAFL Launcher
        ├─ LLMP broker (data plane: local-novelty NewTestcase)
        └─ N havoc workers (same fast build, local corpus)
              ├─ persist InMemoryOnDiskCorpus under workers/<slot>/
              └─ at sync points only: export new local files to spool
```

Control plane vs data plane:

- Worker hot loop is the T1 substrate (`InProcessExecutor`, SanCov or
  synthetic micro map, havoc, `QueueScheduler`). No orchestrator call,
  no dump, no JSON, no mutex per execution.
- LibAFL LLMP shares **local** novelty between workers. That is the
  data plane.
- `CorpusAuthority` is the only writer of canonical admission. It
  replays through the existing `DumpOracle` (fresh process, hashed
  dump binary). Published edges come only from that replay.
- Local corpora may keep inputs the authority later rejects. Those
  must not appear in published canonical totals.

## Protocol contract

`achlys-protocol` stays free of LibAFL / ONNX.

New identifiers: `WorkerId` (16-byte hex, same serde as `CampaignId`),
`StrategyId::Havoc` only.

Every worker-originated event carries:

- `schema_version`
- `campaign_id`
- `sender_seq` (monotonic per `worker_id`)
- `worker_id`
- `timestamp_monotonic_ns`
- payload `dedup_key` (`"{worker_id:hex}:{sender_seq}"` for worker
  events; `"input:{input_id:hex}"` for `CandidateDiscovered`)

New `CampaignEvent` variants: `WorkerRegistered`, `WorkerLeft`,
`WorkerRestarted`, `CandidateDiscovered`, `CorpusDelta`.

`schema_version` remains 1. New variants are additive. Old T1 JSONL
must still parse.

No leases. No assistance reasons. No bandit types.

## Admission contract

`CorpusAuthority` in `achlys-core`:

- `submit` is idempotent on `InputId`. First insert persists bytes
  via `CampaignStore::put_input` and enqueues replay. Duplicates
  return `Duplicate` and do not grow the queue.
- Pending replay queue is bounded (`DEFAULT_PENDING_BOUND = 4096`).
  Overflow persists to `spool/overflow/<hex>` and increments
  `queue_full`; it must not unbounded-grow RAM.
- `drain(oracle, max)` replays at most `max` pending inputs.
  Admit iff `DumpOracle` reports new canonical edges.
  Writes `CanonicalAdmitted` / `CanonicalRejected` and, for each
  non-empty batch of admits, one `CorpusDelta`.
- `reconstruct(store)` rebuilds admitted/rejected/pending/worker
  sets from `events.jsonl` plus leftover spool. A killed authority
  must not lose an already-admitted object.
- Single writer for `events.jsonl`. Workers never append there.

## Launcher / worker contract

Example `achlys_t2` (not the product CLI):

```text
achlys_t2 --manifest PATH --out DIR --workers N
          [--seed N] [--iters N | --seconds N]
          [--cores LIST] [--broker-port P] [--corpus DIR]
          [--label NAME] [--canonical-bin PATH] [--join] [--role launcher|admit]
```

- Default role `launcher` creates a fresh `--out` (reuse forbidden
  unless `--join` on an existing campaign).
- `--join` is **offline continuation** of a stopped campaign. It does
  not attach to a live broker. A restarted slot emits `WorkerLeft`
  (end of the previous run) then `WorkerRestarted` and continues
  `sender_seq` from `last_seq + 1`. It is refused if `target_id`,
  stored manifest flags, `fast_build`, or the on-disk canonical
  dump hash do not match the campaign record.
- `run_substrate` (H0) is unchanged: still `SimpleEventManager` +
  `NopMonitor`. T2 uses a new `run_homogeneous_worker` that takes an
  injected LibAFL `EventManager`.
- Same `WorkerTarget` registry as T1. Unknown `target_id` is fatal.
- One shared canonical dump compiled by the launcher, hashed, recorded
  on `CampaignRecord`. All admission uses that binary/`BuildId`.
- Workers 1..N get `WorkerId::from_slot(i)` and RNG seed
  `seed.wrapping_add(i as u64)` so they do not clone one another.

## Restart and late join

- Accepted objects live in `CampaignStore`. Worker death may lose
  local-only candidates; it must not lose admitted objects.
- A restarted worker with the same `WorkerId` emits `WorkerRestarted`
  and continues `sender_seq` from reconstruct (last seq + 1).
- A new `WorkerId` in an offline continuation is registered as a
  first-time worker and loads the admitted snapshot. Live late join
  onto a running broker is not implemented.
- Reconstructing the event log must recover: registered workers,
  last seq per worker, admitted set, rejected set, last delta seq.

## Scaling ladder (defined now, executed on Linux)

Script: `scripts/experiments/t2_scale.sh`.

| Field | Rule |
|---|---|
| Platform | Linux x86-64 for any scaling sentence. macOS is smoke. |
| Target | `benchmarks/manifests/cjson-parse.toml` |
| Shared dump | compiled once per trial, all worker counts reuse it |
| Workers | 1, 2, 4, 8 (skip counts above `nproc`) |
| Wall | `T2_SECONDS` (default 30 smoke / 300 ladder) |
| Cores | pin 1:1 worker→core when the host allows |
| Trials | `T2_TRIALS` (default 1 smoke / 5 ladder) |
| Seeds | trial index |
| Metrics | wall, sum execs, exec/s, canonical edges, admitted, rejected, unique objects, duplicate submits |

The script writes a TSV and `T2_SCALE` lines. It must **not** print
`T2_PASS` / “near-linear” / a public claim. Completeness of the
ladder is `T2_LADDER=DEFINED` on macOS and `T2_LADDER=RAN` only
after Linux trials exist under `docs/evidence/t2/`.

## Smoke (this host)

`T2_FUNCTIONAL=1 ./scripts/experiments/t2_smoke.sh`

Must fail the campaign unless:

- 2 workers register
- `events.jsonl` reconstructs the same admitted set as
  `reports/canonical.json`
- duplicate bytes from two workers produce one object
- killing the in-memory authority and reconstructing keeps admitted
  objects
- a late-join load sees those objects
- H0 functional pair still matches 150 hashes
- T1 semantic smoke still passes

## Evidence required before any T2 accept

- Linux 1/2/4/8 (or host max) multi-trial TSV
- Coordinator overhead vs single-worker H0 substrate, same host
- No corpus corruption, no duplicate object explosion
- Restart test on Linux
- Event-log reconstruction of the published totals

Until that bundle exists, README stays Level 0 and T2 stays
“implemented, not accepted.”

## Alternatives considered

- Putting canonical replay inside `run_substrate`. Rejected: breaks
  H0 and puts the control plane on the hot path.
- Treating LibAFL `NewTestcase` counts as canonical coverage.
  Rejected: worker maps are not the measurement authority (T1).
- Opening T3 because “we have workers.” Forbidden.
- Closing T2 on macOS 2-worker smoke. Forbidden (§24.8).

## Expected consequence

A 2-worker campaign can share local novelty over LLMP, persist a
content-addressed corpus with worker provenance, admit through one
canonical dump, survive authority restart, and reconstruct its
totals from JSONL. Scaling remains unclaimed.

## Implementation status (not an accept)

`--join` is documented as offline continuation. Live late join is
not implemented. The first T2 close was refused (scale log inside
`--out`, mixed-target join, fake restart, unacked spool, hardcoded
`queue_full=0`, `--workers` vs `--cores`). Those contracts are now
enforced. This is still **not** a T2 accept.
