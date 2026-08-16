# H0 evidence bundles

Small, versioned artifacts only. Campaign logs stay in `campaigns/` (gitignored).

Each dated directory should contain:

- `results.tsv` — one row per timed pair
- `summary.txt` — mean, median, range, descriptive t interval
- `MANIFEST.txt` — commit, `Cargo.lock` hash, rustc, OS, protocol knobs
- `functional.hashes.txt` — sorted SHA-256 of corpus *contents* from the fixed-iter pair (optional if recorded in the manifest)

Do not commit heartbeat logs.