#!/usr/bin/env bash
# T1 equal-resource compare infrastructure (Master Plan §20.2 / §22 task 9).
#
# Runs a short timed pair of libafl_baseline and achlys_h0, and AFL++ when
# afl-fuzz is on PATH. This is smoke / recording infrastructure, not a
# 5-trial performance gate and not a superiority claim (§24.6 / §24.7).
#
# Usage:
#   ./scripts/experiments/t1_compare.sh
#   T1_SECONDS=10 T1_SEED=1 T1_OUT=campaigns/t1-compare ./scripts/experiments/t1_compare.sh
#   T1_SKIP_LIBAFL=1 ./scripts/experiments/t1_compare.sh
#   T1_RECORD_ONLY=1 ./scripts/experiments/t1_compare.sh
#
# Env:
#   T1_SECONDS      wall seconds per requested side (default 10)
#   T1_SEED         RNG seed for the LibAFL/Achlys pair (default 1)
#   T1_OUT          output directory (default campaigns/t1-compare)
#   T1_RECORD_ONLY  if 1, always exit 0 after writing artifacts
#   T1_SKIP_LIBAFL  if 1, skip the LibAFL/Achlys build and timed pair
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

SECONDS_BUDGET="${T1_SECONDS:-10}"
SEED="${T1_SEED:-1}"
OUT_ROOT="${T1_OUT:-campaigns/t1-compare}"
RECORD_ONLY="${T1_RECORD_ONLY:-0}"
SKIP_LIBAFL="${T1_SKIP_LIBAFL:-0}"
SEED_DIR="${OUT_ROOT}/seeds"
CJSON_DIR="${root}/examples/targets/cJSON"
HARNESS_SRC="${CJSON_DIR}/harness_afl.c"

libafl_status="skip"
achlys_status="skip"
aflpp_status="skip"
aflpp_reason=""
libafl_reason=""
achlys_reason=""

git_rev() {
  git rev-parse HEAD 2>/dev/null || echo unknown
}

git_dirty() {
  git status --porcelain 2>/dev/null | awk 'NF && $1 != "??" { n++ } END { print n+0 }'
}

rustc_line() {
  if command -v rustc >/dev/null 2>&1; then
    rustc --version
  else
    echo "rustc=missing"
  fi
}

write_manifest() {
  {
    echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "git=$(git_rev)"
    echo "git_dirty=$(git_dirty)"
    echo "rustc=$(rustc_line)"
    echo "uname=$(uname -a)"
    echo "seconds=${SECONDS_BUDGET}"
    echo "seed=${SEED}"
    echo "out=${OUT_ROOT}"
    echo "skip_libafl=${SKIP_LIBAFL}"
    echo "libafl=${libafl_status}"
    echo "achlys=${achlys_status}"
    echo "aflpp=${aflpp_status}"
    if [[ -n "${aflpp_reason}" ]]; then
      echo "aflpp_reason=${aflpp_reason}"
    fi
    echo "profile=release"
    echo "examples=libafl_baseline,achlys_h0"
    echo "harness=examples/targets/cJSON/harness_afl.c"
    echo "note=equal-resource smoke; not a superiority claim; not a 5-trial gate"
  } > "${OUT_ROOT}/MANIFEST.txt"
}

write_summary() {
  {
    echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "seconds=${SECONDS_BUDGET}"
    echo "seed=${SEED}"
    echo "out=${OUT_ROOT}"
    echo "libafl=${libafl_status}"
    if [[ -n "${libafl_reason}" ]]; then
      echo "libafl_reason=${libafl_reason}"
    fi
    echo "achlys=${achlys_status}"
    if [[ -n "${achlys_reason}" ]]; then
      echo "achlys_reason=${achlys_reason}"
    fi
    echo "aflpp=${aflpp_status}"
    if [[ -n "${aflpp_reason}" ]]; then
      echo "aflpp_reason=${aflpp_reason}"
    fi
    echo "record_only=${RECORD_ONLY}"
    echo "note=what ran / what was skipped; raw logs under ${OUT_ROOT}; no winner"
  } > "${OUT_ROOT}/summary.txt"
}

fail_or_record() {
  local msg="$1"
  echo "${msg}" >&2
  write_manifest
  write_summary
  echo "wrote ${OUT_ROOT}/summary.txt"
  echo "wrote ${OUT_ROOT}/MANIFEST.txt"
  if [[ "${RECORD_ONLY}" == "1" ]]; then
    echo "T1_RECORD_ONLY=1; continuing" >&2
    exit 0
  fi
  exit 1
}

run_one() {
  local bin="$1"
  local out_dir="$2"
  mkdir -p "${out_dir}"
  local log="${out_dir}/stdout.log"
  "${bin}" \
    --seed "${SEED}" \
    --corpus "${SEED_DIR}" \
    --out "${out_dir}" \
    --seconds "${SECONDS_BUDGET}" \
    --target cjson \
    > "${log}"
}

mkdir -p "${SEED_DIR}"
printf '%s\n' '{"a":1}' > "${SEED_DIR}/seed.json"

echo "T1 compare: seconds=${SECONDS_BUDGET} seed=${SEED} out=${OUT_ROOT}"
echo "equal-resource smoke; not a superiority claim; not a 5-trial gate"

if [[ "${SKIP_LIBAFL}" == "1" ]]; then
  libafl_status="skip"
  achlys_status="skip"
  libafl_reason="T1_SKIP_LIBAFL"
  achlys_reason="T1_SKIP_LIBAFL"
  echo "T1_LIBAFL=SKIP reason=T1_SKIP_LIBAFL"
  echo "T1_ACHLYS=SKIP reason=T1_SKIP_LIBAFL"
else
  if ! cargo build --release --example libafl_baseline --example achlys_h0; then
    libafl_status="fail"
    achlys_status="fail"
    libafl_reason="build-failed"
    achlys_reason="build-failed"
    echo "T1_LIBAFL=FAIL reason=build-failed"
    echo "T1_ACHLYS=FAIL reason=build-failed"
    fail_or_record "cargo build of libafl_baseline/achlys_h0 failed"
  fi

  BASE_BIN="${root}/target/release/examples/libafl_baseline"
  ACHLYS_BIN="${root}/target/release/examples/achlys_h0"

  rm -rf "${OUT_ROOT}/libafl" "${OUT_ROOT}/achlys"

  if run_one "${BASE_BIN}" "${OUT_ROOT}/libafl"; then
    libafl_status="ok"
    echo "T1_LIBAFL=OK"
  else
    libafl_status="fail"
    libafl_reason="run-failed"
    echo "T1_LIBAFL=FAIL reason=run-failed"
  fi

  if run_one "${ACHLYS_BIN}" "${OUT_ROOT}/achlys"; then
    achlys_status="ok"
    echo "T1_ACHLYS=OK"
  else
    achlys_status="fail"
    achlys_reason="run-failed"
    echo "T1_ACHLYS=FAIL reason=run-failed"
  fi
fi

# AFL++ is optional. Missing afl-fuzz is a clean skip, not a failure.
if ! command -v afl-fuzz >/dev/null 2>&1; then
  aflpp_status="skip"
  aflpp_reason="afl-fuzz-not-found"
  echo "T1_AFLPP=SKIP reason=afl-fuzz-not-found"
else
  AFL_DIR="${OUT_ROOT}/aflpp"
  rm -rf "${AFL_DIR}"
  mkdir -p "${AFL_DIR}"

  if ! command -v afl-clang-fast >/dev/null 2>&1; then
    aflpp_status="skip"
    aflpp_reason="afl-clang-fast-not-found"
    echo "T1_AFLPP=SKIP reason=afl-clang-fast-not-found"
  else
    HARNESS_BIN="${AFL_DIR}/harness"
    BUILD_LOG="${AFL_DIR}/build.log"
    built=0

    if afl-clang-fast -O0 -g -fsanitize=fuzzer \
      -I "${CJSON_DIR}" \
      "${HARNESS_SRC}" "${CJSON_DIR}/cJSON.c" \
      -o "${HARNESS_BIN}" > "${BUILD_LOG}" 2>&1; then
      built=1
      echo "aflpp_harness=libfuzzer" > "${AFL_DIR}/harness.mode"
    else
      cat > "${AFL_DIR}/stdin_driver.c" <<'EOF'
#include <stdint.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(void) {
    uint8_t buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    return LLVMFuzzerTestOneInput(buf, n);
}
EOF
      if afl-clang-fast -O0 -g \
        -I "${CJSON_DIR}" \
        "${HARNESS_SRC}" "${CJSON_DIR}/cJSON.c" "${AFL_DIR}/stdin_driver.c" \
        -o "${HARNESS_BIN}" >> "${BUILD_LOG}" 2>&1; then
        built=1
        echo "aflpp_harness=stdin" > "${AFL_DIR}/harness.mode"
      fi
    fi

    if [[ "${built}" != "1" ]]; then
      aflpp_status="fail"
      aflpp_reason="afl-clang-fast-build-failed"
      echo "T1_AFLPP=FAIL reason=afl-clang-fast-build-failed"
    else
      export AFL_SKIP_CPUFREQ=1
      export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
      export AFL_NO_AFFINITY=1
      export AFL_NO_UI=1

      AFL_OUT="${AFL_DIR}/out"
      AFL_LOG="${AFL_DIR}/stdout.log"
      # -V is seconds in AFL++. Same seed corpus and wall budget as the pair.
      if afl-fuzz \
        -i "${SEED_DIR}" \
        -o "${AFL_OUT}" \
        -V "${SECONDS_BUDGET}" \
        -- "${HARNESS_BIN}" \
        > "${AFL_LOG}" 2>&1; then
        aflpp_status="ok"
        echo "T1_AFLPP=OK"
      else
        aflpp_status="fail"
        aflpp_reason="afl-fuzz-run-failed"
        echo "T1_AFLPP=FAIL reason=afl-fuzz-run-failed"
      fi
    fi
  fi
fi

write_manifest
write_summary
echo "wrote ${OUT_ROOT}/summary.txt"
echo "wrote ${OUT_ROOT}/MANIFEST.txt"

if [[ "${RECORD_ONLY}" == "1" ]]; then
  echo "T1_RECORD_ONLY=1; exit 0"
  exit 0
fi

if [[ "${libafl_status}" == "fail" || "${achlys_status}" == "fail" || "${aflpp_status}" == "fail" ]]; then
  exit 1
fi
exit 0
