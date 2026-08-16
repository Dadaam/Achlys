#!/usr/bin/env bash
# Clean-checkout smoke: workspace tests plus a bounded H0 functional pair.
# Mechanism / substrate check only — not a superiority claim.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

cargo test --workspace --all-targets
H0_FUNCTIONAL=1 H0_OUT="${H0_OUT:-campaigns/h0-smoke}" ./scripts/experiments/h0_throughput.sh
T1_FUNCTIONAL=1 T1_OUT="${T1_OUT:-campaigns/t1-smoke}" ./scripts/experiments/t1_smoke.sh
