# T2 Linux evidence — 2026-08-17

Not a T2 accept. Not a public scaling claim. Not an AFL++ comparison.

Host: `achlys-t2-linux` (51.15.217.99), 8 physical cores, 1 thread/core,
AMD EPYC 9555P slice, rustc 1.97.1. See `MANIFEST.txt`.

Two archives are kept separate:

| Bundle | SHA | Protocol |
|---|---|---|
| `baseline-fcb725c/` | `fcb725c` | `T2_LADDER=1`, 5 × 300 s, workers 1/2/4/8 |
| `ab-7b2a40c/` | `7b2a40c` | A/B, 3 × 120 s, 7 variants, 21/21 `rc=0` |

Raw host trees stay on the machine (`/root/achlys-t2-linux-fcb725c`,
`/root/achlys-t2-ab-7b2a40c`). Campaign objects are not committed.
Baseline tarball SHA-256:
`fe08142433a215de25265303899a503ab1814ae9c141ad92d079b3ef6ac49ccc`.

## Conclusion (this snapshot)

The initial scaling defect came mainly from a filesystem
synchronization that ran after every LibAFL cycle. Batching at 256
restores 3.97× at 4 workers and 5.85× at 8 workers. Reserving one
core for the control plane does not improve throughput.

## Baseline `fcb725c` (5 × 300 s)

`queue_full=0` on all 20 cells. Median exec/s from
`baseline-fcb725c/results.tsv`:

| Workers | Median exec/s | Median speedup vs 1w |
|---|---|---|
| 1 | 49 396 | 1.00× |
| 2 | 97 440 | 1.97× |
| 4 | 185 936 | 3.76× |
| 8 | 249 247 | 5.05× |

Edges stay 171–173. This is the pre-fix ladder.

## A/B `7b2a40c` (3 × 120 s)

Variant key: A=1w/256, B=4w/256, C=8w/256, D=7w/256/cores 0-6,
E=8w/sync=1 incremental, F=8w/256 rescan, G=8w/sync=1 rescan.

Median exec/s from `ab-7b2a40c/cells.tsv`:

| Variant | Median exec/s | vs A |
|---|---|---|
| A 1w optimized | 763 618 | 1.00× |
| B 4w optimized | 3 027 858 | 3.97× |
| C 8w optimized | 4 465 579 | 5.85× |
| D 7w optimized | 4 104 869 | 5.38× |
| E sync=1 incremental | 337 247 | 0.44× |
| F 256 + rescan | 4 322 780 | 5.66× |
| G old behaviour | 246 228 | 0.32× |

C vs G is about 18×. C vs D is +9 % for the eighth worker. Batching
is the main gain; path indexing adds a few percent once batched.
Coverage remains 171–173. `queue_full=0` everywhere.

`paths_listed` at 8w/256 is still 11–12 million in 120 s. Contents
are no longer re-read. The remaining directory walk is recorded as
bounded debt in
[`docs/decisions/2026-08-17-t2-sync-scan-debt.md`](../../../decisions/2026-08-17-t2-sync-scan-debt.md).

## Still required before any T2 accept

- Independent H0/LibAFL ceiling (1/4/8 processes, no spool).
- Hardened `7b2a40c` contracts (sync_every, join, stamp on replace,
  bounded p95).
- Final `T2_LADDER=1` on the hardened commit.
- Human review. This file does not close the tranche.
