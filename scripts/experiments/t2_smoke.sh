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

worker_seqs = {}
for raw in open(events_p, encoding="utf-8"):
    raw = raw.strip()
    if not raw:
        continue
    ev = json.loads(raw)
    wid = ev.get("worker_id")
    seq = ev.get("sender_seq")
    if wid is None or seq is None:
        continue
    worker_seqs.setdefault(wid, []).append(int(seq))
for wid, seqs in worker_seqs.items():
    if len(seqs) != len(set(seqs)):
        raise SystemExit(f"reused sender_seq for worker {wid}: {seqs}")
    if seqs != sorted(seqs):
        raise SystemExit(f"sender_seq not monotonic for worker {wid}: {seqs}")

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

if find "$out/run1/spool" -name '*.taken.json' | grep -q .; then
  echo "T2_SPOOL=FAIL reason=taken-json-leftover" >&2
  find "$out/run1/spool" -name '*.taken.json' | head >&2
  exit 1
fi
for dir in workers left workers/processing left/processing; do
  p="$out/run1/spool/$dir"
  if [[ -d "$p" ]] && find "$p" -maxdepth 1 -type f -name '*.json' | grep -q .; then
    echo "T2_SPOOL=FAIL reason=control-notices-leftover dir=$dir" >&2
    find "$p" -maxdepth 1 -type f -name '*.json' | head >&2
    exit 1
  fi
done
echo "T2_CONTROL_SPOOL=OK"

crash_out="$out/crash-join"
rm -rf "$crash_out"
cp -a "$out/run1" "$crash_out"
python3 - "$crash_out" <<'PY'
import json, os, sys

root = sys.argv[1]
events_p = os.path.join(root, "artifacts/events/events.jsonl")
events = []
slot0 = None
for raw in open(events_p, encoding="utf-8"):
    raw = raw.strip()
    if not raw:
        continue
    ev = json.loads(raw)
    events.append(ev)
    if ev.get("type") == "worker_registered" and ev.get("slot") == 0:
        slot0 = ev.get("worker_id")
if not slot0:
    raise SystemExit("crash-join plant: missing slot 0 worker_registered")

seqs = []
for ev in events:
    if ev.get("type") == "candidate_discovered" and ev.get("worker_id") == slot0:
        if ev.get("producer_seq") is not None:
            seqs.append(int(ev["producer_seq"]))
if not seqs:
    raise SystemExit("crash-join plant: no producer_seq for slot 0")
journal_max = max(seqs)
cutoff = journal_max - 20 if journal_max >= 20 else journal_max
planted = max(journal_max + 30, 100)

kept = []
for ev in events:
    typ = ev.get("type")
    wid = ev.get("worker_id")
    if wid == slot0 and typ in ("worker_left", "worker_restarted"):
        continue
    if (
        wid == slot0
        and typ == "candidate_discovered"
        and ev.get("producer_seq") is not None
        and int(ev["producer_seq"]) > cutoff
    ):
        continue
    kept.append(ev)

with open(events_p, "w", encoding="utf-8") as fh:
    for ev in kept:
        fh.write(json.dumps(ev, separators=(",", ":")) + "\n")

proc = os.path.join(root, "spool/left/processing")
os.makedirs(proc, exist_ok=True)
notice = f"left-{slot0}-p{planted}-e-crash"
exit_notice = {
    "notice_id": notice,
    "worker_id": slot0,
    "slot": 0,
    "next_producer_seq": planted,
    "reason": "budget",
}
with open(os.path.join(proc, f"{notice}.json"), "w", encoding="utf-8") as fh:
    json.dump(exit_notice, fh, indent=2)
    fh.write("\n")

plant = {
    "worker_id": slot0,
    "journal_max": journal_max,
    "cutoff": cutoff,
    "planted_next": planted,
    "notice_id": notice,
}
json.dump(plant, open(os.path.join(root, "planted.json"), "w", encoding="utf-8"), indent=2)
print(f"T2_CRASH_PLANT worker={slot0} cutoff={cutoff} planted={planted}")
PY
crash_log="$out/crash-join.log"
"$t2_bin" \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t2-crash-join \
  --seed 4242 \
  --iters 8 \
  --workers 1 \
  --join \
  --broker-port "${T2_CRASH_JOIN_BROKER_PORT:-17372}" \
  --corpus "$out/seeds" \
  --out "$crash_out" | tee "$crash_log"
python3 - "$crash_out" "$crash_log" <<'PY'
import json, os, sys

root, log_p = sys.argv[1:]
plant = json.loads(open(os.path.join(root, "planted.json"), encoding="utf-8").read())
wid = plant["worker_id"]
planted = int(plant["planted_next"])
notice = plant["notice_id"]

resume = json.loads(open(os.path.join(root, "spool/resume/0.json"), encoding="utf-8").read())
if int(resume.get("next_producer_seq", -1)) < planted:
    raise SystemExit(
        f"resume next_producer_seq={resume.get('next_producer_seq')} < planted {planted}"
    )

events = []
for raw in open(os.path.join(root, "artifacts/events/events.jsonl"), encoding="utf-8"):
    raw = raw.strip()
    if not raw:
        continue
    events.append(json.loads(raw))

idx_left = None
idx_rst = None
idx_new_left = None
producers = []
for i, ev in enumerate(events):
    if ev.get("worker_id") != wid:
        continue
    typ = ev.get("type")
    if typ == "worker_left" and ev.get("notice_id") == notice:
        idx_left = i
    elif typ == "worker_left" and idx_left is not None and idx_new_left is None:
        idx_new_left = i
    if typ == "worker_restarted" and idx_rst is None:
        idx_rst = i
    if typ == "candidate_discovered" and ev.get("producer_seq") is not None:
        producers.append(int(ev["producer_seq"]))
if idx_left is None:
    raise SystemExit("recovered WorkerLeft missing from journal")
if idx_rst is None:
    raise SystemExit("WorkerRestarted missing after crash-join")
if idx_left > idx_rst:
    raise SystemExit(
        f"WorkerRestarted at {idx_rst} preceded recovered WorkerLeft at {idx_left}"
    )
if idx_new_left is not None and idx_rst > idx_new_left:
    raise SystemExit(
        f"new WorkerLeft at {idx_new_left} preceded WorkerRestarted at {idx_rst}"
    )
if len(producers) != len(set(producers)):
    raise SystemExit(f"duplicate producer_seq after crash-join: {producers}")
newer = [p for p in producers if p >= planted]
if newer and min(newer) < planted:
    raise SystemExit(f"post-join producer_seq below planted: {newer}")
print("T2_CRASH_JOIN=OK")
PY

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
        seq_by_worker.setdefault(ev.get("worker_id"), []).append(ev.get("sender_seq"))
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
    nums = [int(s) for s in seqs if s is not None]
    if len(nums) != len(set(nums)):
        raise SystemExit(f"reused sender_seq for worker {wid}: {nums}")
    if nums != sorted(nums):
        raise SystemExit(f"sender_seq not monotonic for worker {wid}: {nums}")
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
producers = {}
for raw in open(events_p, encoding="utf-8"):
    raw = raw.strip()
    if not raw:
        continue
    ev = json.loads(raw)
    if ev.get("type") != "candidate_discovered":
        continue
    wid = ev.get("worker_id")
    pseq = ev.get("producer_seq")
    if wid is None or pseq is None:
        continue
    producers.setdefault(wid, []).append(int(pseq))
for wid, xs in producers.items():
    if len(xs) != len(set(xs)):
        raise SystemExit(f"duplicate producer_seq for {wid} after one join: {xs}")
print("T2_JOIN=OK")
PY

  join2_log="$out/join2.log"
  "$t2_bin" \
    --manifest benchmarks/manifests/cjson-parse.toml \
    --label t2-join2 \
    --seed 4242 \
    --iters 5 \
    --workers 1 \
    --join \
    --broker-port "${T2_JOIN2_BROKER_PORT:-17371}" \
    --corpus "$out/seeds" \
    --out "$out/run1" | tee "$join2_log"
  python3 - "$events" <<'PY'
import json, sys
events_p = sys.argv[1]
producers = {}
for raw in open(events_p, encoding="utf-8"):
    raw = raw.strip()
    if not raw:
        continue
    ev = json.loads(raw)
    if ev.get("type") != "candidate_discovered":
        continue
    wid = ev.get("worker_id")
    pseq = ev.get("producer_seq")
    if wid is None or pseq is None:
        continue
    producers.setdefault(wid, []).append(int(pseq))
if not producers:
    raise SystemExit("no producer_seq after second join")
for wid, xs in producers.items():
    if len(xs) != len(set(xs)):
        raise SystemExit(f"duplicate producer_seq for {wid} after two joins: {xs}")
print("T2_PRODUCER_SEQ=OK")
PY
  if find "$out/run1/spool" -name '*.taken.json' | grep -q .; then
    echo "T2_SPOOL=FAIL reason=taken-json-after-join" >&2
    exit 1
  fi
  if [[ "$(find "$out/run1/spool/workers/processing" "$out/run1/spool/left/processing" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l | tr -d ' ')" != "0" ]]; then
    echo "T2_SPOOL=FAIL reason=control-processing-after-join" >&2
    exit 1
  fi
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

micro_dir="$out/micro-canonical"
rm -rf "$micro_dir"
./target/release/examples/achlys_oracle \
  --manifest benchmarks/manifests/micro-nonzero-exit.toml \
  --compile-out "$micro_dir" \
  >"$out/micro-compile.log" 2>&1
set +e
"$t2_bin" \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t2-wrong-oracle \
  --seed 1 \
  --iters 2 \
  --workers 1 \
  --broker-port 17365 \
  --corpus "$out/seeds" \
  --canonical-dir "$micro_dir" \
  --out "$out/wrong-oracle" \
  >"$out/wrong-oracle.log" 2>&1
wrong_rc=$?
set -e
if [[ "$wrong_rc" -eq 0 ]]; then
  echo "T2_CANONICAL_TARGET=FAIL reason=micro-dump-accepted-as-cjson" >&2
  cat "$out/wrong-oracle.log" >&2
  exit 1
fi
if ! grep -Eiq 'target_id|identity|canonical identity' "$out/wrong-oracle.log"; then
  echo "T2_CANONICAL_TARGET=FAIL reason=missing-target-identity-error" >&2
  cat "$out/wrong-oracle.log" >&2
  exit 1
fi
echo "T2_CANONICAL_TARGET=OK"

set +e
"$t2_bin" \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t2-naked-bin \
  --seed 1 \
  --iters 2 \
  --workers 1 \
  --broker-port 17366 \
  --corpus "$out/seeds" \
  --canonical-bin "$micro_dir/canonical" \
  --out "$out/naked-bin" \
  >"$out/naked-bin.log" 2>&1
naked_rc=$?
set -e
# sibling identity.json exists for the micro dump, so this must still fail on target_id
if [[ "$naked_rc" -eq 0 ]]; then
  echo "T2_CANONICAL_NAKED=FAIL reason=micro-identity-accepted-as-cjson" >&2
  cat "$out/naked-bin.log" >&2
  exit 1
fi
echo "T2_CANONICAL_NAKED=OK"

orphan="$out/orphan-dump"
mkdir -p "$orphan"
cp "$micro_dir/canonical" "$orphan/canonical"
set +e
"$t2_bin" \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t2-orphan \
  --seed 1 \
  --iters 2 \
  --workers 1 \
  --broker-port 17368 \
  --corpus "$out/seeds" \
  --canonical-bin "$orphan/canonical" \
  --out "$out/orphan" \
  >"$out/orphan.log" 2>&1
orphan_rc=$?
set -e
if [[ "$orphan_rc" -eq 0 ]]; then
  echo "T2_CANONICAL_ORPHAN=FAIL reason=bin-without-identity-accepted" >&2
  cat "$out/orphan.log" >&2
  exit 1
fi
if ! grep -Eiq 'identity.json missing|refusing to invent' "$out/orphan.log"; then
  echo "T2_CANONICAL_ORPHAN=FAIL reason=missing-identity-required-error" >&2
  cat "$out/orphan.log" >&2
  exit 1
fi
echo "T2_CANONICAL_ORPHAN=OK"

# Honest cJSON identity + micro binary + artifact_hash rewritten, old build_id kept.
incoherent="$out/incoherent-id"
rm -rf "$incoherent"
mkdir -p "$incoherent"
cjson_id="$out/run1/builds/canonical/identity.json"
if [[ ! -f "$cjson_id" ]]; then
  echo "T2_BUILD_ID=FAIL reason=missing-cjson-identity" >&2
  exit 1
fi
cp "$micro_dir/canonical" "$incoherent/canonical"
python3 - "$cjson_id" "$incoherent/canonical" "$incoherent/identity.json" <<'PY'
import hashlib, json, sys
src, binary, dest = sys.argv[1:]
ident = json.loads(open(src, encoding="utf-8").read())
digest = hashlib.sha256(open(binary, "rb").read()).hexdigest()
ident["artifact_hash"] = digest
# keep the original build_id so the sidecar is internally inconsistent
json.dump(ident, open(dest, "w", encoding="utf-8"), indent=2)
PY
set +e
"$t2_bin" \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t2-incoherent-id \
  --seed 1 \
  --iters 2 \
  --workers 1 \
  --broker-port 17369 \
  --corpus "$out/seeds" \
  --canonical-dir "$incoherent" \
  --out "$out/incoherent" \
  >"$out/incoherent.log" 2>&1
inc_rc=$?
set -e
if [[ "$inc_rc" -eq 0 ]]; then
  echo "T2_BUILD_ID=FAIL reason=incoherent-identity-accepted" >&2
  cat "$out/incoherent.log" >&2
  exit 1
fi
if ! grep -Eiq 'build_id|not the hash|identity.json' "$out/incoherent.log"; then
  echo "T2_BUILD_ID=FAIL reason=missing-validate-error" >&2
  cat "$out/incoherent.log" >&2
  exit 1
fi
echo "T2_BUILD_ID=OK"

qfull_out="$out/qfull"
rm -rf "$qfull_out"
set +e
"$t2_bin" \
  --manifest benchmarks/manifests/cjson-parse.toml \
  --label t2-qfull \
  --seed 7 \
  --iters 40 \
  --workers 1 \
  --pending-bound 1 \
  --broker-port 17367 \
  --corpus "$out/seeds" \
  --out "$qfull_out" \
  >"$out/qfull.log" 2>&1
qfull_rc=$?
set -e
if [[ "$qfull_rc" -ne 0 ]]; then
  echo "T2_QUEUE_FULL=FAIL reason=pending-bound-campaign-failed" >&2
  cat "$out/qfull.log" >&2
  exit 1
fi
python3 - "$qfull_out/artifacts/metrics/admission.json" "$out/qfull.log" <<'PY'
import json, sys
adm = json.loads(open(sys.argv[1], encoding="utf-8").read())
for key in ("inbox", "processing", "overflow", "pending", "control"):
    if int(adm.get(key, 1)) != 0:
        raise SystemExit(f"{key}={adm.get(key)} want 0")
if int(adm.get("queue_full", 0)) < 1:
    raise SystemExit(f"queue_full={adm.get('queue_full')} want >= 1")
text = open(sys.argv[2], encoding="utf-8", errors="replace").read()
line = [ln for ln in text.splitlines() if "T2_RESULT" in ln][-1]
kv = dict(part.split("=", 1) for part in line.split("T2_RESULT", 1)[1].split() if "=" in part)
if int(kv.get("queue_full", "0")) < 1:
    raise SystemExit(f"T2_RESULT queue_full={kv.get('queue_full')}")
if int(kv["objects"]) != int(kv["replayed"]):
    raise SystemExit("qfull objects != replayed")
seqs = {}
events_p = sys.argv[1].replace("metrics/admission.json", "events/events.jsonl")
for raw in open(events_p, encoding="utf-8"):
    raw = raw.strip()
    if not raw:
        continue
    ev = json.loads(raw)
    wid, seq = ev.get("worker_id"), ev.get("sender_seq")
    if wid is None or seq is None:
        continue
    seqs.setdefault(wid, []).append(int(seq))
for wid, xs in seqs.items():
    if xs != sorted(xs) or len(xs) != len(set(xs)):
        raise SystemExit(f"qfull sender_seq not monotonic unique for {wid}: {xs}")
print("T2_QUEUE_FULL=OK")
PY

echo "T2_FUNCTIONAL=OK"
