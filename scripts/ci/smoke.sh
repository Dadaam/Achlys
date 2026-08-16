#!/usr/bin/env bash
# Workspace smoke from a clean checkout: build + unit tests.
#
# A full 5-minute campaign smoke is deferred until the worker can time-bound
# campaigns (Master Plan T0.10 / T1). This script does not run a live fuzz loop.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

cargo build --workspace --all-targets
cargo test --workspace --all-targets
