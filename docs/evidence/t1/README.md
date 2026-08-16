# T1 evidence bundles

Small, versioned artifacts only. Campaign trees stay in `campaigns/` (gitignored).

A T1 smoke bundle should contain:

- `summary.txt` — `T1_RESULT` line and what ran
- `canonical.json` — independent replay report
- `metrics.json` — worker snapshot
- `MANIFEST.txt` — commit, rustc, OS, protocol knobs

This is mechanism evidence, not an AFL++ or superiority claim.
