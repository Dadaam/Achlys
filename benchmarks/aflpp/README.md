# AFL++ compare harness

Linux how-to for the equal-resource T1 smoke path (Master Plan §20.2 / §24.7).
This is **infrastructure**, not a claim that Achlys is faster or more effective
than AFL++. Do not invent or quote AFL++ numbers from a machine that skipped
the run.

The runner is [`scripts/experiments/t1_compare.sh`](../../scripts/experiments/t1_compare.sh).
If `afl-fuzz` is not on `PATH`, that script prints
`T1_AFLPP=SKIP reason=afl-fuzz-not-found` and continues.

## Prerequisites (Linux)

- AFL++ providing `afl-fuzz` and `afl-clang-fast`
- clang (used by `afl-clang-fast`)
- the same seed corpus, wall time, and input-length bound as the LibAFL / Achlys pair

macOS is not the release measurement host. The compare script must skip
cleanly when AFL++ is absent.

## Build

Harness source: [`examples/targets/cJSON/harness_afl.c`](../../examples/targets/cJSON/harness_afl.c)
(`LLVMFuzzerTestOneInput`: bounded NUL-terminated copy, `cJSON_Parse`, `cJSON_Delete`).

From the repository root:

```bash
afl-clang-fast -O0 -g -fsanitize=fuzzer \
  -I examples/targets/cJSON \
  examples/targets/cJSON/harness_afl.c \
  examples/targets/cJSON/cJSON.c \
  -o harness
```

If `-fsanitize=fuzzer` is unavailable, `t1_compare.sh` compiles a stdin
driver next to the same `LLVMFuzzerTestOneInput`. Do not treat a different
wrapper as a different target.

## Run

Equal-resource smoke (LibAFL baseline, Achlys substrate, AFL++ when present):

```bash
T1_SECONDS=10 T1_SEED=1 T1_OUT=campaigns/t1-compare \
  ./scripts/experiments/t1_compare.sh
```

AFL++ only (skip the LibAFL / Achlys pair):

```bash
T1_SKIP_LIBAFL=1 ./scripts/experiments/t1_compare.sh
```

Manual AFL++ invocation with the same seeds and time budget:

```bash
mkdir -p /tmp/t1-seeds
printf '%s\n' '{"a":1}' > /tmp/t1-seeds/seed.json
AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  afl-fuzz -i /tmp/t1-seeds -o /tmp/t1-aflpp -V 10 -- ./harness
```

`-V` is seconds. Match cores, wall time, seeds, and target revision before
any later experiment. This README does not record a winner.
