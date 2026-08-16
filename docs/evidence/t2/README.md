# T2 evidence bundles

This directory is for **future** T2 evidence. It is empty of measured results.

T2 homogeneous multi-worker implementation is **open**
([`docs/decisions/2026-08-16-t2-homogeneous.md`](../../decisions/2026-08-16-t2-homogeneous.md)).
T2 is **not accepted**. Do not put a scaling sentence, a `T2_PASS` token, or
an AFL++ comparison here.

When a Linux x86-64 host runs `T2_LADDER=1 ./scripts/experiments/t2_scale.sh`,
a dated bundle here should contain only what that run actually wrote:

- `results.tsv` — one row per trial × worker count (raw parse of `T2_RESULT`)
- `summary.txt` — `T2_LADDER=RAN` on that Linux run; still not a public claim
- `MANIFEST.txt` — commit, rustc, `uname`, protocol knobs
- copies of `canonical.json` / reconstruct notes if a restart cell is recorded

Campaign trees stay in `campaigns/` (gitignored). Do not commit heartbeat logs.

macOS runs of `t2_smoke.sh` or the default `t2_scale.sh` path are smoke.
They stay `T2_LADDER=DEFINED`. They do not close the tranche.

There are no numbers in this file because none have been accepted.
