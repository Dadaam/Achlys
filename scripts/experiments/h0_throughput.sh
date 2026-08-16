#!/usr/bin/env bash
# H0 throughput ladder: Achlys substrate vs minimal LibAFL baseline.
# Exit 0 even if the 5% gate fails — the orchestrator audits raw numbers.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

SECONDS_BUDGET="${H0_SECONDS:-30}"
TRIALS="${H0_TRIALS:-5}"
MAX_INPUT_LEN="${H0_MAX_INPUT_LEN:-64}"
OUT_ROOT="${H0_OUT:-campaigns/h0}"
SEED_DIR="${OUT_ROOT}/seeds"

cargo build --release --example libafl_baseline --example achlys_h0

mkdir -p "${SEED_DIR}"
printf '%s\n' '{"a":1}' > "${SEED_DIR}/seed.json"

BASE_BIN="${root}/target/release/examples/libafl_baseline"
ACHLYS_BIN="${root}/target/release/examples/achlys_h0"

TSV="${OUT_ROOT}/results.tsv"
mkdir -p "${OUT_ROOT}"
printf 'trial\tseed\tbaseline_execs\tbaseline_eps\tachlys_execs\tachlys_eps\toverhead\n' > "${TSV}"

parse_h0() {
  local log="$1"
  grep -E '^H0_RESULT ' "${log}" | tail -n 1
}

field() {
  local line="$1"
  local key="$2"
  echo "${line}" | sed -n "s/.*${key}=\\([^ ]*\\).*/\\1/p"
}

echo "H0: ${TRIALS} trials × ${SECONDS_BUDGET}s  max_input_len=${MAX_INPUT_LEN}"
echo

sum_base=0
sum_achlys=0
n=0

for i in $(seq 1 "${TRIALS}"); do
  seed="${i}"
  base_dir="${OUT_ROOT}/baseline/trial_${i}"
  achlys_dir="${OUT_ROOT}/achlys/trial_${i}"
  rm -rf "${base_dir}" "${achlys_dir}"
  mkdir -p "${base_dir}" "${achlys_dir}"

  base_log="${base_dir}/stdout.log"
  achlys_log="${achlys_dir}/stdout.log"

  "${BASE_BIN}" \
    --seed "${seed}" \
    --seconds "${SECONDS_BUDGET}" \
    --corpus "${SEED_DIR}" \
    --out "${base_dir}" \
    --max-input-len "${MAX_INPUT_LEN}" \
    --target cjson \
    > "${base_log}"

  "${ACHLYS_BIN}" \
    --seed "${seed}" \
    --seconds "${SECONDS_BUDGET}" \
    --corpus "${SEED_DIR}" \
    --out "${achlys_dir}" \
    --max-input-len "${MAX_INPUT_LEN}" \
    --target cjson \
    > "${achlys_log}"

  base_line="$(parse_h0 "${base_log}")"
  achlys_line="$(parse_h0 "${achlys_log}")"
  if [[ -z "${base_line}" || -z "${achlys_line}" ]]; then
    echo "missing H0_RESULT (trial ${i})" >&2
    echo "  baseline: ${base_line:-<empty>}" >&2
    echo "  achlys:   ${achlys_line:-<empty>}" >&2
    exit 1
  fi

  b_execs="$(field "${base_line}" execs)"
  b_eps="$(field "${base_line}" exec_per_sec)"
  a_execs="$(field "${achlys_line}" execs)"
  a_eps="$(field "${achlys_line}" exec_per_sec)"

  overhead="$(awk -v b="${b_eps}" -v a="${a_eps}" 'BEGIN {
    if (b+0 == 0) { print "nan"; exit }
    printf "%.6f", (b - a) / b
  }')"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${i}" "${seed}" "${b_execs}" "${b_eps}" "${a_execs}" "${a_eps}" "${overhead}" >> "${TSV}"

  sum_base="$(awk -v s="${sum_base}" -v x="${b_eps}" 'BEGIN { printf "%.8f", s + x }')"
  sum_achlys="$(awk -v s="${sum_achlys}" -v x="${a_eps}" 'BEGIN { printf "%.8f", s + x }')"
  n=$((n + 1))

  printf 'trial %s  seed=%s  baseline=%s exec/s  achlys=%s exec/s  overhead=%s\n' \
    "${i}" "${seed}" "${b_eps}" "${a_eps}" "${overhead}"
done

means="$(awk -v sb="${sum_base}" -v sa="${sum_achlys}" -v n="${n}" 'BEGIN {
  mb = sb / n
  ma = sa / n
  if (mb == 0) { oh = "nan"; pass = 0 }
  else {
    oh = (mb - ma) / mb
    pass = (oh <= 0.05) ? 1 : 0
  }
  printf "%.2f %.2f %.6f %d", mb, ma, oh, pass
}')"
mean_base="$(echo "${means}" | awk '{print $1}')"
mean_achlys="$(echo "${means}" | awk '{print $2}')"
mean_oh="$(echo "${means}" | awk '{print $3}')"
pass="$(echo "${means}" | awk '{print $4}')"

echo
echo "mean baseline exec/s: ${mean_base}"
echo "mean achlys   exec/s: ${mean_achlys}"
echo "mean overhead:        ${mean_oh}  ((baseline - achlys) / baseline)"
echo
if [[ "${pass}" == "1" ]]; then
  echo "H0_PASS  overhead ${mean_oh} <= 0.05"
else
  echo "H0_FAIL  overhead ${mean_oh} > 0.05"
fi

{
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "rustc=$(rustc --version)"
  rustc -vV | sed 's/^/rustc_vv./'
  echo "seconds=${SECONDS_BUDGET}"
  echo "trials=${TRIALS}"
  echo "max_input_len=${MAX_INPUT_LEN}"
  echo "target=cjson"
  echo "profile=release"
  echo "examples=libafl_baseline,achlys_h0"
} > "${OUT_ROOT}/MANIFEST.txt"

echo
echo "wrote ${TSV}"
echo "wrote ${OUT_ROOT}/MANIFEST.txt"
exit 0
