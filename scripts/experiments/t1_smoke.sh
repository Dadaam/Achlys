#!/usr/bin/env bash
# Tranche 1 mechanism smoke: manifest campaign + independent oracle artifacts.
# Not a performance or AFL++ claim.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

if [[ "${T1_UNIT:-0}" == "1" ]]; then
  cargo test -p achlys-protocol --all-targets
  cargo test --workspace --all-targets
fi

if [[ "${T1_FUNCTIONAL:-0}" == "1" ]]; then
  out="${T1_OUT:-campaigns/t1-smoke}"
  rm -rf "$out"
  mkdir -p "$out/seeds"
  printf '%s\n' '{"a":1}' >"$out/seeds/seed.json"

  cargo build --release --example achlys_t1 --example achlys_oracle
  ./target/release/examples/achlys_t1 \
    --manifest benchmarks/manifests/cjson-parse.toml \
    --label t1-smoke \
    --seed 4242 \
    --iters 50 \
    --corpus "$out/seeds" \
    --out "$out"

  if [[ ! -f "$out/artifacts/reports/canonical.json" ]]; then
    echo "T1_ORACLE=FAIL reason=missing-canonical-report" >&2
    exit 1
  fi
  if [[ ! -f "$out/artifacts/events/events.jsonl" ]]; then
    echo "T1_EVENTS=FAIL reason=missing-events" >&2
    exit 1
  fi
  echo "T1_FUNCTIONAL=OK"
fi
