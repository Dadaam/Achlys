#!/usr/bin/env bash
# Clean-checkout smoke: workspace tests, H0 functional pair, T1 semantic smoke,
# T2 homogeneous functional smoke. Mechanism check only — not a superiority
# or scaling claim. T2 is implemented (or landing), not accepted.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

cargo test --workspace --all-targets
H0_FUNCTIONAL=1 H0_OUT="${H0_OUT:-campaigns/h0-smoke}" ./scripts/experiments/h0_throughput.sh
T1_FUNCTIONAL=1 T1_OUT="${T1_OUT:-campaigns/t1-smoke}" ./scripts/experiments/t1_smoke.sh
T2_FUNCTIONAL=1 T2_OUT="${T2_OUT:-campaigns/t2-smoke}" ./scripts/experiments/t2_smoke.sh
