# Decision: T1 baseline infrastructure accepted

- Date: 2026-08-16
- Decision: **accept Tranche 1 as baseline infrastructure**. Merge `tranche-1-baseline` into `main`.
- Do **not** start Tranche 2 (LLMP, multi-worker, adaptive allocation) or ML.
- Do **not** treat AFL++ smoke figures as a comparison result.

Ground truth: `docs/MASTER_PLAN.md` §22 Tranche 1.

## What is accepted

A single-worker graybox campaign can now be driven from a target manifest, persist a content-addressed corpus, replay coverage on a separately compiled canonical dump, and verify crash candidates off the hot path.

H0 remains the throughput development gate
([`2026-08-16-h0-substrate.md`](2026-08-16-h0-substrate.md)). T1 does not replace that number and does not add a public AFL++ claim.

## What this is not

- Not Level 1 in the Master Plan success ladder. Linux x86-64 multi-trial evidence is still missing.
- Not a release experiment.
- Not permission to publish exec/s or coverage/time-to-target against AFL++.
- Not a license to open Tranche 2.

Any short `t1_compare.sh` run (including the 3 s local smoke that shared one canonical artifact across LibAFL, Achlys, and AFL++) is a **pipeline smoke artifact only**. Those edge counts and timings must not appear in README, papers, or public claims.

## Accepted properties

- The manifest selects the harness, or the campaign errors.
- Campaign roots refuse reuse.
- Canonical and sanitizer artifacts are compiled, hashed, and recorded.
- Compare lanes that run must replay against **one** shared dump binary and `BuildId`.
- Crash counters distinguish candidates, clean replays, and reproduced crashes.
- Semantic T1 smoke and H0 functional pair are green on Linux CI.

## Still closed

Tranche 2 stays closed until a Linux multi-trial ladder is **defined and executed**: equal cores and wall time, shared canonical dump, multiple trials, coverage and time-to-target — not exec/s anecdotes.

## Evidence

- Branch `tranche-1-baseline` through `03a2a09`, plus this accept record, merged to `main`.
- Linux CI green on the shared-oracle commit: run `31964013720`.
- Functional smoke: [`docs/evidence/t1/`](../evidence/t1/).
- Implementation notes and remediations: [`2026-08-16-t1-baseline.md`](2026-08-16-t1-baseline.md).

## Later superseding decision

None.
