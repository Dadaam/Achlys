#!/usr/bin/env bash
# Tranche 2 homogeneous functional smoke. Not a scaling, AFL++, or T2-accept claim.
# Implementation-open (docs/decisions/2026-08-16-t2-homogeneous.md). Not accepted.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

if [[ "${T2_FUNCTIONAL:-0}" != "1" ]]; then
  exit 0
fi

out="${T2_OUT:-campaigns/t2-smoke}"
rm -rf "$out"
mkdir -p "$out/seeds"
printf '%s\n' '{"a":1}' >"$out/seeds/seed.json"

cargo build --release --example achlys_t2 --example achlys_oracle

t2_bin="./target/release/examples/achlys_t2"
if [[ ! -x "$t2_bin" ]]; then
  echo "T2_ARTIFACT=FAIL missing=$t2_bin" >&2
  exit 1
fi

t2_log="$out/t2.log"
"$t2_bin" \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t2-smoke \
  --seed 4242 \
  --iters 40 \
  --workers 2 \
  --broker-port "${T2_BROKER_PORT:-17360}" \
  --corpus "$out/seeds" \
  --out "$out/run1" | tee "$t2_log"

if ! grep -q 'T2_RESULT' "$t2_log"; then
  echo "T2_RESULT=FAIL reason=missing-T2_RESULT" >&2
  exit 1
fi

canon="$out/run1/artifacts/reports/canonical.json"
events="$out/run1/artifacts/events/events.jsonl"
campaign="$out/run1/artifacts/campaign.json"

for f in "$canon" "$events" "$campaign"; do
  if [[ ! -f "$f" ]]; then
    echo "T2_ARTIFACT=FAIL missing=$f" >&2
    exit 1
  fi
done

objects="$out/run1/artifacts/corpus/objects"

python3 - "$t2_log" "$canon" "$events" "$campaign" "$objects" <<'PY'
import json, os, re, sys

log_p, canon_p, events_p, campaign_p, objects_p = sys.argv[1:]

text = open(log_p, encoding="utf-8", errors="replace").read()
claim = re.search(
    r"near[-\s]?linear|\bT2_PASS\b|\bT2_ACCEPT\b|level\s*2|better than AFL",
    text,
    re.I,
)
if claim:
    raise SystemExit(f"claim language in t2 stdout: {claim.group(0)!r}")

lines = [ln for ln in text.splitlines() if "T2_RESULT" in ln]
if not lines:
    raise SystemExit("no T2_RESULT")
line = lines[-1]
# Accept a leading "T2_RESULT " or an embedded token.
payload = line.split("T2_RESULT", 1)[1].strip()
kv = dict(part.split("=", 1) for part in payload.split() if "=" in part)

def need(k):
    if k not in kv:
        raise SystemExit(f"missing {k} in T2_RESULT")
    return kv[k]

if need("workers") != "2":
    raise SystemExit(f"T2_RESULT workers={kv.get('workers')!r} want 2")
if need("reports") != "2":
    raise SystemExit(f"T2_RESULT reports={kv.get('reports')!r} want 2")
if "queue_full" not in kv:
    raise SystemExit("missing queue_full in T2_RESULT")

canon = json.loads(open(canon_p, encoding="utf-8").read())
digest = canon.get("digest")
if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
    raise SystemExit(f"canonical digest is not hex64: {digest!r}")

def as_int(src, key):
    if key not in src or src[key] in (None, ""):
        return None
    return int(src[key])

admitted = as_int(kv, "admitted")
rejected = as_int(kv, "rejected")
replayed = as_int(kv, "replayed")
if admitted is None:
    admitted = as_int(canon, "admitted")
if rejected is None:
    rejected = as_int(canon, "rejected")
if replayed is None:
    replayed = as_int(canon, "replayed")
if None not in (admitted, rejected, replayed) and admitted + rejected != replayed:
    raise SystemExit(
        f"admitted+rejected {admitted + rejected} != replayed {replayed}"
    )
if "admitted" in canon and admitted is not None and int(canon["admitted"]) != admitted:
    raise SystemExit(
        f"canonical.json admitted {canon['admitted']} != T2_RESULT/folded {admitted}"
    )

registered = []
stored = []
admitted_ids = []
for raw in open(events_p, encoding="utf-8"):
    raw = raw.strip()
    if not raw:
        continue
    ev = json.loads(raw)
    typ = ev.get("type")
    if typ == "worker_registered":
        registered.append(ev)
    elif typ == "input_stored":
        stored.append(ev.get("input_id"))
    elif typ == "canonical_admitted":
        admitted_ids.append(ev.get("input_id"))

if len(registered) < 2:
    raise SystemExit(
        f"events.jsonl worker_registered count={len(registered)} want >= 2"
    )
worker_ids = {ev.get("worker_id") for ev in registered if ev.get("worker_id")}
if len(worker_ids) < 2:
    raise SystemExit(f"unique worker_id from worker_registered={len(worker_ids)} want >= 2")

if any(i is None for i in stored):
    raise SystemExit("InputStored missing input_id")
if len(stored) != len(set(stored)):
    raise SystemExit("InputStored input_id values are not unique")

object_files = []
object_hashes = []
if os.path.isdir(objects_p):
    for dirpath, _, names in os.walk(objects_p):
        for name in names:
            if name.startswith(".") or name.endswith(".metadata"):
                continue
            object_files.append(os.path.join(dirpath, name))
            object_hashes.append(name)

if len(object_files) != len(set(object_hashes)):
    raise SystemExit(
        f"duplicate corpus object hashes: files={len(object_files)} unique={len(set(object_hashes))}"
    )
if len(set(object_hashes)) != len(set(stored)):
    raise SystemExit(
        f"unique corpus objects {len(set(object_hashes))} != distinct InputStored {len(set(stored))}"
    )

admitted_set = {i for i in admitted_ids if i}
canon_admitted = as_int(canon, "admitted")
if canon_admitted is None:
    raise SystemExit("canonical.json missing admitted")
if len(admitted_set) != canon_admitted:
    raise SystemExit(
        f"CanonicalAdmitted set {len(admitted_set)} != canonical.json admitted {canon_admitted}"
    )

objects_n = len(set(object_hashes))
if replayed is not None and objects_n != replayed:
    raise SystemExit(f"objects {objects_n} != replayed {replayed}")

campaign = json.loads(open(campaign_p, encoding="utf-8").read())
if not campaign:
    raise SystemExit("campaign.json empty")

print("T2_SEMANTICS=OK")
print("T2_RECONSTRUCT=OK")
print("T2_OBJECTS=OK")
PY

processing="$out/run1/spool/processing"
if [[ -d "$processing" ]] && find "$processing" -type f ! -name '.DS_Store' | grep -q .; then
  echo "T2_SPOOL=FAIL reason=processing-not-empty" >&2
  find "$processing" -type f | head >&2
  exit 1
fi
echo "T2_PROCESSING=OK"

set +e
help_out="$("$t2_bin" --help 2>&1)"
set -e
if grep -q -- '--join' <<<"$help_out"; then
  join_log="$out/join.log"
  "$t2_bin" \
    --manifest benchmarks/manifests/cjson-parse.toml \
    --label t2-join \
    --seed 4242 \
    --iters 5 \
    --workers 1 \
    --join \
    --broker-port "${T2_JOIN_BROKER_PORT:-17361}" \
    --corpus "$out/seeds" \
    --out "$out/run1" | tee "$join_log"
  python3 - "$canon" "$events" "$join_log" <<'PY'
import json, sys
canon_p, events_p, join_log = sys.argv[1:]
canon = json.loads(open(canon_p, encoding="utf-8").read())
registered = 0
restarted = 0
left = 0
stored = []
admitted = set()
worker_keys = []
seq_by_worker = {}
for raw in open(events_p, encoding="utf-8"):
    raw = raw.strip()
    if not raw:
        continue
    ev = json.loads(raw)
    typ = ev.get("type")
    if typ == "worker_registered":
        registered += 1
        worker_keys.append((typ, ev.get("worker_id"), ev.get("sender_seq")))
        seq_by_worker.setdefault(ev.get("worker_id"), []).append(ev.get("sender_seq"))
    elif typ == "worker_restarted":
        restarted += 1
        worker_keys.append((typ, ev.get("worker_id"), ev.get("sender_seq")))
        seq_by_worker.setdefault(ev.get("worker_id"), []).append(ev.get("sender_seq"))
    elif typ == "worker_left":
        left += 1
        worker_keys.append((typ, ev.get("worker_id"), ev.get("sender_seq")))
        seq_by_worker.setdefault(ev.get("worker_id"), []).append(ev.get("sender_seq"))
    elif typ == "candidate_discovered":
        worker_keys.append((typ, ev.get("worker_id"), ev.get("sender_seq")))
    elif typ == "input_stored":
        stored.append(ev.get("input_id"))
    elif typ == "canonical_admitted":
        admitted.add(ev.get("input_id"))
if registered != 2:
    raise SystemExit(f"post-join worker_registered={registered} want 2 (first run only)")
if restarted < 1:
    raise SystemExit(f"post-join worker_restarted={restarted} want >= 1")
if left < 1:
    raise SystemExit(f"post-join worker_left={left} want >= 1")
if len(worker_keys) != len(set(worker_keys)):
    raise SystemExit("duplicate (type, worker_id, sender_seq) after --join")
for wid, seqs in seq_by_worker.items():
    nums = [s for s in seqs if isinstance(s, int)]
    if nums != sorted(nums):
        raise SystemExit(f"sender_seq not nondecreasing for {wid}: {nums}")
if len(stored) != len(set(stored)):
    raise SystemExit("post-join InputStored ids are not unique")
if "admitted" not in canon:
    raise SystemExit("canonical.json missing admitted after --join")
if len(admitted) != int(canon["admitted"]):
    raise SystemExit(
        f"post-join CanonicalAdmitted {len(admitted)} != canonical.json admitted {canon['admitted']}"
    )
join_text = open(join_log, encoding="utf-8", errors="replace").read()
jline = [ln for ln in join_text.splitlines() if "T2_RESULT" in ln]
if not jline:
    raise SystemExit("join missing T2_RESULT")
jkv = dict(part.split("=", 1) for part in jline[-1].split("T2_RESULT", 1)[1].split() if "=" in part)
if jkv.get("workers") != "1" or jkv.get("reports") != "1":
    raise SystemExit(f"join workers/reports {jkv}")
if int(jkv.get("objects", "-1")) != int(jkv.get("replayed", "-2")):
    raise SystemExit(f"join objects != replayed: {jkv}")
print("T2_JOIN=OK")
PY
fi

set +e
"$t2_bin" \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t2-smoke \
  --seed 4242 \
  --iters 2 \
  --workers 2 \
  --corpus "$out/seeds" \
  --out "$out/run1" \
  >"$out/reuse.log" 2>&1
reuse_rc=$?
set -e
if [[ "$reuse_rc" -eq 0 ]]; then
  echo "T2_REUSE=FAIL reason=second-launcher-same-out-succeeded" >&2
  exit 1
fi
if ! grep -Eiq 'not empty|occupied|reuse|already exists|--join' "$out/reuse.log"; then
  echo "T2_REUSE=FAIL reason=missing-occupied-root-error" >&2
  cat "$out/reuse.log" >&2
  exit 1
fi

set +e
"$t2_bin" \
  --manifest benchmarks/manifests/micro-nonzero-exit.toml \
  --label t2-crosstarget \
  --seed 1 \
  --iters 2 \
  --workers 1 \
  --join \
  --broker-port 17362 \
  --out "$out/run1" \
  >"$out/crosstarget.log" 2>&1
cross_rc=$?
set -e
if [[ "$cross_rc" -eq 0 ]]; then
  echo "T2_JOIN_TARGET=FAIL reason=cross-target-join-succeeded" >&2
  cat "$out/crosstarget.log" >&2
  exit 1
fi
if ! grep -Eiq 'target mismatch|join target' "$out/crosstarget.log"; then
  echo "T2_JOIN_TARGET=FAIL reason=missing-target-mismatch" >&2
  cat "$out/crosstarget.log" >&2
  exit 1
fi
echo "T2_JOIN_TARGET=OK"

set +e
"$t2_bin" \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t2-cores \
  --seed 1 \
  --iters 2 \
  --workers 1 \
  --cores 0-1 \
  --broker-port 17363 \
  --corpus "$out/seeds" \
  --out "$out/cores-mismatch" \
  >"$out/cores.log" 2>&1
cores_rc=$?
set -e
if [[ "$cores_rc" -eq 0 ]]; then
  echo "T2_CORES=FAIL reason=workers-ne-cores-succeeded" >&2
  cat "$out/cores.log" >&2
  exit 1
fi
if ! grep -Eiq 'must match|cores selects' "$out/cores.log"; then
  echo "T2_CORES=FAIL reason=missing-cores-mismatch" >&2
  cat "$out/cores.log" >&2
  exit 1
fi
echo "T2_CORES=OK"

tamper="$out/run1/builds/canonical/canonical"
if [[ -f "$tamper" ]]; then
  cp "$tamper" "$out/canonical.bak"
  printf 'x' >>"$tamper"
  set +e
  "$t2_bin" \
    --manifest benchmarks/manifests/cjson-parse.toml \
    --label t2-tamper \
    --seed 1 \
    --iters 2 \
    --workers 1 \
    --join \
    --broker-port 17364 \
    --out "$out/run1" \
    >"$out/tamper.log" 2>&1
  tamper_rc=$?
  set -e
  mv "$out/canonical.bak" "$tamper"
  if [[ "$tamper_rc" -eq 0 ]]; then
    echo "T2_CANONICAL_HASH=FAIL reason=tampered-dump-join-succeeded" >&2
    cat "$out/tamper.log" >&2
    exit 1
  fi
  if ! grep -Eiq 'hash|artifact_hash|canonical dump' "$out/tamper.log"; then
    echo "T2_CANONICAL_HASH=FAIL reason=missing-hash-error" >&2
    cat "$out/tamper.log" >&2
    exit 1
  fi
  echo "T2_CANONICAL_HASH=OK"
fi

echo "T2_FUNCTIONAL=OK"
