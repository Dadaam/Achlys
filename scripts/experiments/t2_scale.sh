#!/usr/bin/env bash
# T2 homogeneous scaling ladder definition. Not a T2 accept.
#
# Defaults are Darwin / local smoke (short). The Linux ladder profile is:
#   T2_SECONDS=300  T2_TRIALS=5  T2_WORKERS="1 2 4 8"  (skip counts > nproc)
# That profile is applied only when T2_LADDER=1 on Linux. macOS never
# becomes T2_LADDER=RAN, even if the 1- and 2-worker smoke cells run.
#
# achlys_t2 has no shared-dump flag today. Each cell compiles its own
# canonical dump. A future flag should pin one dump per trial so worker
# counts are comparable. Do not invent numbers to paper over that.
#
# Never prints a T2 accept / pass token. Do not publish these rows.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

# Smoke defaults. Linux ladder (when T2_LADDER=1 on Linux) uses 300 / 5 / 1 2 4 8.
SECONDS_BUDGET="${T2_SECONDS:-5}"
TRIALS="${T2_TRIALS:-1}"
WORKERS="${T2_WORKERS:-1 2}"
OUT_ROOT="${T2_OUT:-campaigns/t2-scale}"
LADDER_STATE="DEFINED"

uname_s="$(uname -s)"
if [[ "${T2_LADDER:-0}" == "1" && "$uname_s" == "Linux" ]]; then
  SECONDS_BUDGET=300
  TRIALS=5
  WORKERS="1 2 4 8"
  LADDER_STATE="RAN"
fi

host_nproc=""
if command -v nproc >/dev/null 2>&1; then
  host_nproc="$(nproc)"
elif [[ "$uname_s" == "Darwin" ]]; then
  host_nproc="$(sysctl -n hw.ncpu 2>/dev/null || true)"
fi
if [[ -z "$host_nproc" ]]; then
  host_nproc=1
fi

filtered=""
for w in $WORKERS; do
  if [[ "$w" -le "$host_nproc" ]]; then
    filtered+=" $w"
  else
    echo "T2_SCALE skip workers=$w (nproc=$host_nproc)"
  fi
done
filtered="${filtered# }"
if [[ -z "$filtered" ]]; then
  echo "T2_SCALE=FAIL reason=no-worker-counts-le-nproc nproc=$host_nproc" >&2
  exit 1
fi
WORKERS="$filtered"

SEED_DIR="${OUT_ROOT}/seeds"
mkdir -p "$SEED_DIR"
printf '%s\n' '{"a":1}' >"${SEED_DIR}/seed.json"

tsv="${OUT_ROOT}/results.tsv"
mkdir -p "$OUT_ROOT"
printf '%s\n' $'trial\tworkers\tseed\twall_s\texecs\texec_per_sec\tedges\tadmitted\trejected\tobjects\tqueue_full' >"$tsv"

write_summary() {
  {
    echo "T2 homogeneous ladder / smoke"
    echo "this is a ladder definition / smoke"
    echo "do not publish"
    echo "T2_LADDER=${LADDER_STATE}"
    echo "uname=${uname_s}"
    echo "nproc=${host_nproc}"
    echo "seconds=${SECONDS_BUDGET}"
    echo "trials=${TRIALS}"
    echo "workers=${WORKERS}"
    echo "out=${OUT_ROOT}"
    echo "target=benchmarks/manifests/cjson-parse.toml"
    echo "dump=each cell compiles its own dump; achlys_t2 has no shared-dump flag; a future flag should pin one dump per trial"
    echo "note=not a T2 accept; not a scaling claim; not an AFL++ comparison"
    echo "tsv=${tsv}"
  } >"${OUT_ROOT}/summary.txt"
}

# If T2_LADDER=1 was requested on a non-Linux host, keep DEFINED and the
# smoke defaults already in SECONDS_BUDGET / TRIALS / WORKERS.
if [[ "${T2_LADDER:-0}" == "1" && "$uname_s" != "Linux" ]]; then
  LADDER_STATE="DEFINED"
fi

set +e
cargo build --release --example achlys_t2 --example achlys_oracle
build_rc=$?
set -e
if [[ "$build_rc" -ne 0 ]]; then
  LADDER_STATE="DEFINED"
  write_summary
  echo "T2_ARTIFACT=FAIL reason=cargo-build-example-achlys_t2" >&2
  exit 1
fi

t2_bin="./target/release/examples/achlys_t2"
if [[ ! -x "$t2_bin" ]]; then
  LADDER_STATE="DEFINED"
  write_summary
  echo "T2_ARTIFACT=FAIL missing=$t2_bin" >&2
  exit 1
fi

cell_fail=0

for trial in $(seq 1 "$TRIALS"); do
  seed="$trial"
  for workers in $WORKERS; do
    cell="${OUT_ROOT}/w${workers}_t${trial}"
    rm -rf "$cell"
    mkdir -p "$cell"
    log="${cell}/stdout.log"
    start_s="$(date +%s)"
    set +e
    port="$((17300 + trial * 20 + workers))"
    "$t2_bin" \
      --manifest benchmarks/manifests/cjson-parse.toml \
      --label "t2-scale-w${workers}-t${trial}" \
      --seed "$seed" \
      --seconds "$SECONDS_BUDGET" \
      --workers "$workers" \
      --broker-port "$port" \
      --corpus "$SEED_DIR" \
      --out "$cell" >"$log" 2>&1
    rc=$?
    set -e
    end_s="$(date +%s)"
    measured_wall="$((end_s - start_s))"

    parsed="$(python3 - "$log" "$cell" "$measured_wall" <<'PY'
import os, sys

log_p, cell, measured_wall = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(log_p, encoding="utf-8", errors="replace").read()
lines = [ln for ln in text.splitlines() if "T2_RESULT" in ln]
kv = {}
if lines:
    payload = lines[-1].split("T2_RESULT", 1)[1].strip()
    kv = dict(part.split("=", 1) for part in payload.split() if "=" in part)

def get(*keys):
    for k in keys:
        if k in kv and kv[k] not in ("", None):
            return kv[k]
    return ""

wall = get("wall_s", "elapsed_s")
if wall == "":
    wall = measured_wall
execs = get("execs", "executions")
eps = get("exec_per_sec", "execs_per_sec")
if eps == "" and execs != "" and wall not in ("", "0"):
    try:
        eps = f"{float(execs) / float(wall):.6f}"
    except ValueError:
        eps = ""
edges = get("edges", "canonical_edges")
admitted = get("admitted")
rejected = get("rejected")
queue_full = get("queue_full")
objects = get("objects")
if objects == "":
    obj_root = os.path.join(cell, "artifacts", "corpus", "objects")
    hashes = []
    if os.path.isdir(obj_root):
        for _dirpath, _dirs, names in os.walk(obj_root):
            for name in names:
                if name.startswith(".") or name.endswith(".metadata"):
                    continue
                hashes.append(name)
    objects = str(len(set(hashes)))
status = "OK" if lines else "MISSING"
# One record: status then the TSV fields. Empty cells stay empty; never invent.
print("\t".join([status, wall, execs, eps, edges, admitted, rejected, objects, queue_full]))
PY
)"
    status="$(printf '%s' "$parsed" | cut -f1)"
    wall_s="$(printf '%s' "$parsed" | cut -f2)"
    execs="$(printf '%s' "$parsed" | cut -f3)"
    exec_per_sec="$(printf '%s' "$parsed" | cut -f4)"
    edges="$(printf '%s' "$parsed" | cut -f5)"
    admitted="$(printf '%s' "$parsed" | cut -f6)"
    rejected="$(printf '%s' "$parsed" | cut -f7)"
    objects="$(printf '%s' "$parsed" | cut -f8)"
    queue_full="$(printf '%s' "$parsed" | cut -f9)"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$trial" "$workers" "$seed" "$wall_s" "$execs" "$exec_per_sec" \
      "$edges" "$admitted" "$rejected" "$objects" "$queue_full" >>"$tsv"

    echo "T2_SCALE trial=${trial} workers=${workers} seed=${seed} wall_s=${wall_s} execs=${execs} exec_per_sec=${exec_per_sec} edges=${edges} admitted=${admitted} rejected=${rejected} objects=${objects} queue_full=${queue_full} rc=${rc} parse=${status}"

    if [[ "$rc" -ne 0 || "$status" != "OK" ]]; then
      echo "T2_SCALE cell failed trial=${trial} workers=${workers} rc=${rc} parse=${status}" >&2
      cell_fail=1
    fi
  done
done

if [[ "$cell_fail" -ne 0 ]]; then
  # Incomplete run is still a definition, never a published ladder.
  LADDER_STATE="DEFINED"
fi

write_summary
echo "wrote ${OUT_ROOT}/summary.txt"
echo "wrote ${tsv}"
echo "T2_LADDER=${LADDER_STATE}"

if [[ "$cell_fail" -ne 0 ]]; then
  exit 1
fi
