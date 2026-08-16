#!/usr/bin/env bash
# Tranche 1 mechanism smoke: protocol + (once wired) oracle / sanitizer / store.
# Not a performance or AFL++ claim.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

cargo test -p achlys-protocol --all-targets
cargo test --workspace --all-targets

if [[ "${T1_FUNCTIONAL:-0}" == "1" ]]; then
  out="${T1_OUT:-campaigns/t1-smoke}"
  rm -rf "$out"
  mkdir -p "$out/seeds"
  printf '%s\n' '{"a":1}' >"$out/seeds/seed.json"

  cargo build --release --example achlys_h0
  ./target/release/examples/achlys_h0 \
    --seed 4242 \
    --iters 50 \
    --corpus "$out/seeds" \
    --out "$out/worker" \
    --max-input-len 64 \
    --target cjson

  if [[ -x ./target/release/examples/achlys_oracle ]]; then
    cargo build --release --example achlys_oracle
    ./target/release/examples/achlys_oracle \
      --corpus "$out/worker/corpus" \
      --out "$out/reports/canonical.json" \
      --target cjson
  else
    echo "T1_ORACLE=SKIP reason=example-not-built-yet"
  fi
fi
