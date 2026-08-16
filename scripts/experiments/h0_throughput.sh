#!/usr/bin/env bash
# H0 substrate gate: Achlys run_substrate vs a minimal LibAFL baseline.
#
# Default: functional hash-equivalence, then a timed ladder. Non-zero exit
# on H0_FAIL or corpus divergence.
# H0_RECORD_ONLY=1 keeps exit 0 (descriptive runs).
# H0_FUNCTIONAL=1 skips the timed ladder (CI / smoke).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

SECONDS_BUDGET="${H0_SECONDS:-30}"
TRIALS="${H0_TRIALS:-5}"
MAX_INPUT_LEN="${H0_MAX_INPUT_LEN:-64}"
OUT_ROOT="${H0_OUT:-campaigns/h0}"
SEED_DIR="${OUT_ROOT}/seeds"
WARMUP_SECONDS="${H0_WARMUP_SECONDS:-3}"
ORDER_MODE="${H0_ORDER:-abba}"
ORDER_SEED="${H0_ORDER_SEED:-${RANDOM}}"
FUNC_SEED="${H0_FUNC_SEED:-4242}"
FUNC_ITERS="${H0_FUNC_ITERS:-1000}"
RECORD_ONLY="${H0_RECORD_ONLY:-0}"
FUNCTIONAL_ONLY="${H0_FUNCTIONAL:-0}"
TARGET="${H0_TARGET:-cjson}"
GATE="${H0_GATE:-0.05}"

cargo build --release --example libafl_baseline --example achlys_h0

mkdir -p "${SEED_DIR}"
printf '%s\n' '{"a":1}' > "${SEED_DIR}/seed.json"

BASE_BIN="${root}/target/release/examples/libafl_baseline"
ACHLYS_BIN="${root}/target/release/examples/achlys_h0"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

corpus_hash_list() {
  local dir="$1"
  if [[ ! -d "${dir}" ]]; then
    return 0
  fi
  # Content hashes only; LibAFL file names are not the identity.
  # Corpus IDs are single-path tokens; no -print0 needed.
  find "${dir}" -type f ! -name '.*' \
    | sort \
    | while IFS= read -r f; do
        sha256_file "${f}"
      done \
    | sort
}

parse_h0() {
  grep -E '^H0_RESULT ' "$1" | tail -n 1
}

field() {
  echo "$1" | sed -n "s/.*${2}=\\([^ ]*\\).*/\\1/p"
}

run_one() {
  local bin="$1"
  local out_dir="$2"
  local seed="$3"
  shift 3
  mkdir -p "${out_dir}"
  local log="${out_dir}/stdout.log"
  "${bin}" \
    --seed "${seed}" \
    --corpus "${SEED_DIR}" \
    --out "${out_dir}" \
    --max-input-len "${MAX_INPUT_LEN}" \
    --target "${TARGET}" \
    "$@" > "${log}"
}

fail_or_record() {
  local msg="$1"
  echo "${msg}" >&2
  if [[ "${RECORD_ONLY}" == "1" ]]; then
    echo "H0_RECORD_ONLY=1; continuing" >&2
    return 0
  fi
  exit 1
}

echo "H0 functional: seed=${FUNC_SEED} iters=${FUNC_ITERS} target=${TARGET}"

func_base="${OUT_ROOT}/functional/baseline"
func_achlys="${OUT_ROOT}/functional/achlys"
rm -rf "${func_base}" "${func_achlys}"

run_one "${BASE_BIN}" "${func_base}" "${FUNC_SEED}" --iters "${FUNC_ITERS}"
run_one "${ACHLYS_BIN}" "${func_achlys}" "${FUNC_SEED}" --iters "${FUNC_ITERS}"

base_func_line="$(parse_h0 "${func_base}/stdout.log")"
achlys_func_line="$(parse_h0 "${func_achlys}/stdout.log")"
if [[ -z "${base_func_line}" || -z "${achlys_func_line}" ]]; then
  fail_or_record "missing H0_RESULT on functional pair"
fi

corpus_hash_list "${func_base}/corpus" > "${func_base}/corpus.hashes"
corpus_hash_list "${func_achlys}/corpus" > "${func_achlys}/corpus.hashes"

if ! cmp -s "${func_base}/corpus.hashes" "${func_achlys}/corpus.hashes"; then
  echo "functional corpus hashes differ" >&2
  echo "  baseline $(wc -l < "${func_base}/corpus.hashes") files" >&2
  echo "  achlys   $(wc -l < "${func_achlys}/corpus.hashes") files" >&2
  diff -u "${func_base}/corpus.hashes" "${func_achlys}/corpus.hashes" >&2 || true
  fail_or_record "H0_FAIL functional divergence"
fi

func_count="$(wc -l < "${func_base}/corpus.hashes" | tr -d ' ')"
echo "H0_FUNCTIONAL_PASS  ${func_count} corpus hashes identical (seed=${FUNC_SEED}, iters=${FUNC_ITERS})"

if [[ "${FUNCTIONAL_ONLY}" == "1" ]]; then
  {
    echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "git=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "git_dirty=$(git status --porcelain | awk 'NF && $1 != "??" { n++ } END { print n+0 }')"
    echo "cargo_lock=$(sha256_file Cargo.lock)"
    echo "rustc=$(rustc --version)"
    rustc -vV | sed 's/^/rustc_vv./'
    echo "uname=$(uname -a)"
    echo "mode=functional"
    echo "func_seed=${FUNC_SEED}"
    echo "func_iters=${FUNC_ITERS}"
    echo "func_corpus_files=${func_count}"
    echo "target=${TARGET}"
    echo "profile=release"
    echo "monitor=NopMonitor"
  } > "${OUT_ROOT}/MANIFEST.txt"
  echo "wrote ${OUT_ROOT}/MANIFEST.txt"
  exit 0
fi

# Timed ladder -----------------------------------------------------------------

TSV="${OUT_ROOT}/results.tsv"
mkdir -p "${OUT_ROOT}"
printf 'trial\tseed\torder\tbaseline_execs\tbaseline_eps\tachlys_execs\tachlys_eps\toverhead\n' > "${TSV}"

if [[ "${WARMUP_SECONDS}" != "0" ]]; then
  echo "warmup ${WARMUP_SECONDS}s (discarded)"
  rm -rf "${OUT_ROOT}/warmup"
  run_one "${BASE_BIN}" "${OUT_ROOT}/warmup/baseline" 0 --seconds "${WARMUP_SECONDS}" || true
  run_one "${ACHLYS_BIN}" "${OUT_ROOT}/warmup/achlys" 0 --seconds "${WARMUP_SECONDS}" || true
fi

echo "H0 timed: ${TRIALS} trials × ${SECONDS_BUDGET}s  order=${ORDER_MODE}  max_input_len=${MAX_INPUT_LEN}"
echo

# Precompute AB/BA or shuffled order. 0 = baseline first, 1 = achlys first.
orders=()
case "${ORDER_MODE}" in
  abab)
    for i in $(seq 1 "${TRIALS}"); do orders+=(0); done
    ;;
  abba)
    for i in $(seq 1 "${TRIALS}"); do
      if (( i % 2 == 1 )); then orders+=(0); else orders+=(1); fi
    done
    ;;
  random)
    # Deterministic shuffle from ORDER_SEED.
    for i in $(seq 1 "${TRIALS}"); do
      # portable-ish: awk LCG
      bit="$(awk -v s="${ORDER_SEED}" -v i="${i}" 'BEGIN {
        x = (s * 1103515245 + i * 12345) % 2147483648
        print (x % 2)
      }')"
      orders+=("${bit}")
    done
    ;;
  *)
    echo "unknown H0_ORDER=${ORDER_MODE} (abab|abba|random)" >&2
    exit 2
    ;;
esac

n=0
for i in $(seq 1 "${TRIALS}"); do
  seed="${i}"
  base_dir="${OUT_ROOT}/baseline/trial_${i}"
  achlys_dir="${OUT_ROOT}/achlys/trial_${i}"
  rm -rf "${base_dir}" "${achlys_dir}"

  first="${orders[$((i - 1))]}"
  if [[ "${first}" == "0" ]]; then
    order_label="AB"
    run_one "${BASE_BIN}" "${base_dir}" "${seed}" --seconds "${SECONDS_BUDGET}"
    run_one "${ACHLYS_BIN}" "${achlys_dir}" "${seed}" --seconds "${SECONDS_BUDGET}"
  else
    order_label="BA"
    run_one "${ACHLYS_BIN}" "${achlys_dir}" "${seed}" --seconds "${SECONDS_BUDGET}"
    run_one "${BASE_BIN}" "${base_dir}" "${seed}" --seconds "${SECONDS_BUDGET}"
  fi

  base_line="$(parse_h0 "${base_dir}/stdout.log")"
  achlys_line="$(parse_h0 "${achlys_dir}/stdout.log")"
  if [[ -z "${base_line}" || -z "${achlys_line}" ]]; then
    echo "missing H0_RESULT (trial ${i})" >&2
    fail_or_record "missing H0_RESULT"
  fi

  b_execs="$(field "${base_line}" execs)"
  b_eps="$(field "${base_line}" exec_per_sec)"
  a_execs="$(field "${achlys_line}" execs)"
  a_eps="$(field "${achlys_line}" exec_per_sec)"

  overhead="$(awk -v b="${b_eps}" -v a="${a_eps}" 'BEGIN {
    if (b+0 == 0) { print "nan"; exit }
    printf "%.6f", (b - a) / b
  }')"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${i}" "${seed}" "${order_label}" "${b_execs}" "${b_eps}" "${a_execs}" "${a_eps}" "${overhead}" >> "${TSV}"

  n=$((n + 1))
  printf 'trial %s  seed=%s  order=%s  baseline=%s exec/s  achlys=%s exec/s  overhead=%s\n' \
    "${i}" "${seed}" "${order_label}" "${b_eps}" "${a_eps}" "${overhead}"
done

# BSD awk has no asort; sort(1) the overhead column first.
stats="$(tail -n +2 "${TSV}" | cut -f8 | sort -n | awk -v gate="${GATE}" '
  {
    o[++n] = $1 + 0
    sum += o[n]
  }
  END {
    if (n == 0) { print "0 0 0 0 0 0 0 0"; exit }
    mean = sum / n
    if (n % 2) median = o[int((n+1)/2)]
    else median = (o[n/2] + o[n/2+1]) / 2
    ss = 0
    for (i = 1; i <= n; i++) {
      d = o[i] - mean
      ss += d * d
    }
    sd = (n > 1) ? sqrt(ss / (n - 1)) : 0
    split("12.706 4.303 3.182 2.776 2.571 2.447 2.365 2.306 2.262 2.228", tcrit, " ")
    tc = (n-1 >= 1 && n-1 <= 10) ? tcrit[n-1] : 1.96
    se = (n > 0) ? sd / sqrt(n) : 0
    lo = mean - tc * se
    hi = mean + tc * se
    pass = (mean <= gate + 0) ? 1 : 0
    printf "%.6f %.6f %.6f %.6f %.6f %.6f %d %d", mean, median, lo, hi, o[1], o[n], pass, n
  }
')"

mean_oh="$(echo "${stats}" | awk '{print $1}')"
median_oh="$(echo "${stats}" | awk '{print $2}')"
ci_lo="$(echo "${stats}" | awk '{print $3}')"
ci_hi="$(echo "${stats}" | awk '{print $4}')"
min_oh="$(echo "${stats}" | awk '{print $5}')"
max_oh="$(echo "${stats}" | awk '{print $6}')"
pass="$(echo "${stats}" | awk '{print $7}')"

{
  echo "mean_overhead=${mean_oh}"
  echo "median_overhead=${median_oh}"
  echo "min_overhead=${min_oh}"
  echo "max_overhead=${max_oh}"
  echo "t95_lo=${ci_lo}"
  echo "t95_hi=${ci_hi}"
  echo "gate=${GATE}"
  echo "n=${n}"
  echo "pass=${pass}"
} > "${OUT_ROOT}/summary.txt"

{
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_dirty=$(git status --porcelain | awk 'NF && $1 != "??" { n++ } END { print n+0 }')"
  echo "cargo_lock=$(sha256_file Cargo.lock)"
  echo "rustc=$(rustc --version)"
  rustc -vV | sed 's/^/rustc_vv./'
  echo "uname=$(uname -a)"
  echo "seconds=${SECONDS_BUDGET}"
  echo "trials=${TRIALS}"
  echo "warmup_seconds=${WARMUP_SECONDS}"
  echo "order=${ORDER_MODE}"
  echo "order_seed=${ORDER_SEED}"
  echo "max_input_len=${MAX_INPUT_LEN}"
  echo "func_seed=${FUNC_SEED}"
  echo "func_iters=${FUNC_ITERS}"
  echo "func_corpus_files=${func_count}"
  echo "target=${TARGET}"
  echo "profile=release"
  echo "monitor=NopMonitor"
  echo "examples=libafl_baseline,achlys_h0"
  echo "gate=${GATE}"
} > "${OUT_ROOT}/MANIFEST.txt"

echo
echo "mean overhead:   ${mean_oh}  (point estimate, (baseline-achlys)/baseline)"
echo "median overhead: ${median_oh}"
echo "range:           ${min_oh} .. ${max_oh}"
echo "t 95% interval:  ${ci_lo} .. ${ci_hi}  (descriptive; n=${n})"
echo
if [[ "${pass}" == "1" ]]; then
  echo "H0_PASS  mean overhead ${mean_oh} <= ${GATE}"
else
  echo "H0_FAIL  mean overhead ${mean_oh} > ${GATE}"
fi

echo
echo "wrote ${TSV}"
echo "wrote ${OUT_ROOT}/summary.txt"
echo "wrote ${OUT_ROOT}/MANIFEST.txt"

if [[ "${pass}" != "1" ]]; then
  fail_or_record "H0_FAIL"
fi
exit 0
