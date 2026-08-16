#!/usr/bin/env bash
# Tranche 1 semantic smoke. Not a performance or AFL++ claim.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

if [[ "${T1_UNIT:-0}" == "1" ]]; then
  cargo test -p achlys-protocol --all-targets
  cargo test --workspace --all-targets
fi

if [[ "${T1_FUNCTIONAL:-0}" != "1" ]]; then
  exit 0
fi

out="${T1_OUT:-campaigns/t1-smoke}"
rm -rf "$out"
mkdir -p "$out/seeds"
printf '%s\n' '{"a":1}' >"$out/seeds/seed.json"

cargo build --release --example achlys_t1 --example achlys_oracle

set +e
./target/release/examples/achlys_t1 \
  --manifest benchmarks/manifests/micro-timeout-hang.toml \
  --label t1-wrong \
  --seed 1 \
  --iters 2 \
  --out "$out/should-fail-unsupported" \
  >"$out/unsupported.log" 2>&1
unsupported_rc=$?
set -e
if [[ "$unsupported_rc" -eq 0 ]]; then
  echo "T1_TARGET=FAIL reason=unsupported-manifest-ran" >&2
  exit 1
fi
if ! grep -q "unsupported worker target" "$out/unsupported.log"; then
  echo "T1_TARGET=FAIL reason=missing-unsupported-error" >&2
  cat "$out/unsupported.log" >&2
  exit 1
fi

t1_log="$out/t1.log"
./target/release/examples/achlys_t1 \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t1-smoke \
  --seed 4242 \
  --iters 50 \
  --corpus "$out/seeds" \
  --out "$out/run1" | tee "$t1_log"

canon="$out/run1/artifacts/reports/canonical.json"
events="$out/run1/artifacts/events/events.jsonl"
campaign="$out/run1/artifacts/campaign.json"
metrics="$out/run1/artifacts/metrics/summary.json"

for f in "$canon" "$events" "$campaign" "$metrics"; do
  if [[ ! -f "$f" ]]; then
    echo "T1_ARTIFACT=FAIL missing=$f" >&2
    exit 1
  fi
done

python3 - "$t1_log" "$canon" "$events" "$campaign" "$metrics" <<'PY'
import json, re, sys
log, canon_p, events_p, campaign_p, metrics_p = sys.argv[1:]
text = open(log).read()
m = re.search(r"T1_RESULT (\S+)", text)
if not m:
    raise SystemExit("no T1_RESULT")
# parse key=value from the result line
line = [ln for ln in text.splitlines() if ln.startswith("T1_RESULT ")][-1]
kv = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
def need(k):
    if k not in kv:
        raise SystemExit(f"missing {k} in T1_RESULT")
    return kv[k]

ingested = int(need("ingested"))
corpus = int(need("corpus"))
replayed = int(need("replayed"))
admitted = int(need("admitted"))
rejected = int(need("rejected"))
if ingested != corpus:
    raise SystemExit(f"ingested {ingested} != corpus {corpus}")
if replayed != ingested:
    raise SystemExit(f"replayed {replayed} != ingested {ingested}")
if admitted + rejected != replayed:
    raise SystemExit(f"admitted+rejected {admitted+rejected} != replayed {replayed}")
if need("target") != "cjson-parse":
    raise SystemExit(f"target {need('target')} != cjson-parse")
if int(need("reproduced")) != 0:
    raise SystemExit("unexpected reproduced crashes on this smoke")
if int(need("clean")) != 0 or int(need("crash_files")) != 0:
    raise SystemExit(
        f"unexpected crash activity: crash_files={need('crash_files')} clean={need('clean')}"
    )

canon = json.loads(open(canon_p).read())
digest = canon["digest"]
if not isinstance(digest, str) or len(digest) != 64:
    raise SystemExit(f"canonical digest is not hex64: {digest!r}")
if canon["replayed"] != replayed:
    raise SystemExit("canonical.json replayed mismatch")
if "canonical_build" not in canon:
    raise SystemExit("canonical.json missing canonical_build")

campaign = json.loads(open(campaign_p).read())
if campaign["target_id"] != "cjson-parse":
    raise SystemExit(f"campaign.json target {campaign['target_id']}")
if not campaign.get("canonical_build") or not campaign["canonical_build"].get("artifact_hash"):
    raise SystemExit("canonical artifact_hash missing")
if not campaign.get("sanitizer_build") or not campaign["sanitizer_build"].get("artifact_hash"):
    raise SystemExit("sanitizer artifact_hash missing")
if campaign["fast_build"]["target_id"] != "cjson-parse":
    raise SystemExit("fast_build target mismatch")

started = []
for line in open(events_p):
    line = line.strip()
    if not line:
        continue
    ev = json.loads(line)
    if ev.get("type") == "campaign_started":
        started.append(ev)
        if ev["target_id"] != "cjson-parse":
            raise SystemExit("jsonl target mismatch")
        if "fast_build" not in ev:
            raise SystemExit("jsonl missing fast_build")
if len(started) != 1:
    raise SystemExit(f"expected 1 CampaignStarted, got {len(started)}")

metrics = json.loads(open(metrics_p).read())
if metrics["corpus_count"] != corpus:
    raise SystemExit("metrics corpus mismatch")
print("T1_SEMANTICS=OK")
PY

set +e
./target/release/examples/achlys_t1 \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t1-smoke \
  --seed 4242 \
  --iters 2 \
  --corpus "$out/seeds" \
  --out "$out/run1" \
  >"$out/reuse.log" 2>&1
reuse_rc=$?
set -e
if [[ "$reuse_rc" -eq 0 ]]; then
  echo "T1_REUSE=FAIL reason=second-run-same-out-succeeded" >&2
  exit 1
fi
if ! grep -q "not empty" "$out/reuse.log"; then
  echo "T1_REUSE=FAIL reason=missing-not-empty-error" >&2
  cat "$out/reuse.log" >&2
  exit 1
fi

micro_log="$out/micro.log"
./target/release/examples/achlys_t1 \
  --manifest benchmarks/manifests/micro-nonzero-exit.toml \
  --label t1-micro \
  --seed 1 \
  --iters 5 \
  --out "$out/micro" | tee "$micro_log"
if ! grep -q 'target=micro-nonzero-exit' "$micro_log"; then
  echo "T1_MICRO=FAIL reason=target-not-recorded" >&2
  exit 1
fi
if ! grep -q '"target_id": "micro-nonzero-exit"' "$out/micro/artifacts/campaign.json"; then
  echo "T1_MICRO=FAIL reason=campaign-target-mismatch" >&2
  exit 1
fi

crash_log="$out/crash-clean.log"
./target/release/examples/achlys_t1 \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t1-clean-crash \
  --seed 1 \
  --iters 2 \
  --corpus "$out/seeds" \
  --extra-crash "$out/seeds/seed.json" \
  --out "$out/crash-clean" | tee "$crash_log"
python3 - "$crash_log" "$out/crash-clean/artifacts/events/events.jsonl" <<'PY'
import json, sys
log, events_p = sys.argv[1], sys.argv[2]
line = [ln for ln in open(log) if ln.startswith("T1_RESULT ")][-1]
kv = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
want = {
    "crash_files": "1",
    "unique_candidates": "1",
    "replays": "1",
    "clean": "1",
    "reproduced": "0",
    "unique_sigs": "0",
}
for k, v in want.items():
    if kv.get(k) != v:
        raise SystemExit(f"clean-crash {k}={kv.get(k)!r} want {v}")
verified = [
    json.loads(ln)
    for ln in open(events_p)
    if ln.strip() and json.loads(ln).get("type") == "crash_verified"
]
if len(verified) != 1:
    raise SystemExit(f"want 1 CrashVerified, got {len(verified)}")
ev = verified[0]
if ev.get("reproducible") is not False:
    raise SystemExit(f"reproducible={ev.get('reproducible')}")
if ev.get("class") != "Clean":
    raise SystemExit(f"class={ev.get('class')}")
print("T1_CLEAN_CRASH=OK")
PY

echo "T1_FUNCTIONAL=OK"
