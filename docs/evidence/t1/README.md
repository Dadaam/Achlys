# T1 evidence bundles

Small, versioned artifacts only. Campaign trees stay in `campaigns/` (gitignored).

A T1 smoke bundle should contain:

- `summary.txt` — `T1_RESULT` line and what ran
- `canonical.json` — independent replay report
- `metrics.json` — worker snapshot
- `MANIFEST.txt` — commit, rustc, OS, protocol knobs

JSON files here are exact program exports (`digest` is a hex string).
`summary.txt` is generated and records the SHA-256 of `canonical.json`.

This is mechanism evidence, not an AFL++ or superiority claim.
