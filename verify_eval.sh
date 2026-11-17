#!/usr/bin/env bash
# Verifies the two evaluation changes:
#   A. --eval-exclude-attackers  (attacker receivers are left out of the metrics)
#   B. --attack-start            (attackers manipulate only from the given time on)
#
# Run from ~/VaN3Twin/ns-3-dev   ->   bash verify_eval.sh
# Regression reference: verify_runs/fixed from the old verify.sh (run with the
# previous code). If it is missing, the regression check is skipped.
set -e
OUT=verify_runs_eval
REF=verify_runs/fixed
START=30
rm -rf "$OUT"; mkdir -p "$OUT"

run() {
    local name=$1; shift
    echo ">> run '$name': $*"
    ./ns3 run "v2v-cpm-attack-80211p $*" > "$OUT/$name.stdout" 2>&1
    mkdir -p "$OUT/$name"
    mv cpm_*.csv "$OUT/$name/"
}

run legacy  --eval-exclude-attackers=false --attack-start=0
run exclude --eval-exclude-attackers=true  --attack-start=0
run start   --eval-exclude-attackers=true  --attack-start=$START

python3 - "$OUT" "$REF" "$START" <<'EOF'
import csv, sys, os, filecmp
B, REF, START = sys.argv[1], sys.argv[2], float(sys.argv[3]) * 1000
ok = True

def check(name, cond, detail=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail else ""))
    ok &= bool(cond)

def rows(run, f): return list(csv.DictReader(open(f"{B}/{run}/{f}")))
def summary(run): return {r["metric"]: r["value"] for r in rows(run, "cpm_eval_summary.csv")}

attackers = {r["station_id"] for r in rows("legacy", "cpm_attacker_offsets.csv")}

print("\n=== 1. Regression: defaults of the old code give identical results ===")
if os.path.isdir(REF):
    for f in ("cpm_eval_summary.csv", "cpm_eval_log.csv", "cpm_groundtruth_log.csv",
              "cpm_ids_log.csv", "cpm_attack_log.csv"):
        check(f"legacy == old code: {f}",
              filecmp.cmp(f"{B}/legacy/{f}", f"{REF}/{f}", shallow=False))
else:
    print(f"SKIP no reference run in {REF}")

print("\n=== 2. Attackers excluded as receivers ===")
check("IDS log unchanged (IDS still runs on all vehicles)",
      filecmp.cmp(f"{B}/legacy/cpm_ids_log.csv", f"{B}/exclude/cpm_ids_log.csv", shallow=False))
ids_l, ev_l = rows("legacy", "cpm_ids_log.csv"), rows("legacy", "cpm_eval_log.csv")
check("legacy: one IDS row per eval row", len(ids_l) == len(ev_l), f"{len(ids_l)} vs {len(ev_l)}")
# IDS log and eval log are written in the same callback, row by row -> same order
expected = [e for i, e in zip(ids_l, ev_l) if i["receiver_id"] not in attackers]
ev_x = rows("exclude", "cpm_eval_log.csv")
check("eval log == legacy eval log without attacker receivers", ev_x == expected,
      f"{len(ev_x)} rows, expected {len(expected)}, removed {len(ev_l) - len(expected)}")
s = summary("exclude")
cnt = {k: sum(1 for e in ev_x if e["result"] == k) for k in ("TP", "FP", "TN", "FN")}
check("summary matches eval log", all(int(s[k]) == cnt[k] for k in cnt), str(cnt))

print(f"\n=== 3. Attack start at {START/1000:.0f} s ===")
off = rows("start", "cpm_attacker_offsets.csv")
check("offsets file lists the start time", all(float(r["attack_start_s"]) * 1000 == START for r in off))
atk = rows("start", "cpm_attack_log.csv")
first = {}
for r in atk:
    t = float(r["timestamp_ms"]); first[r["sender_id"]] = min(first.get(r["sender_id"], t), t)
check("no manipulation before the start time", all(t >= START for t in first.values()),
      f"first manipulation: {min(first.values()):.0f} ms")
print(f"INFO attackers that started: {len(first)} of {len(attackers)} "
      f"(an attacker that leaves the map before the start never attacks)")
check("at least one attacker starts manipulating", len(first) > 0)
gt = rows("start", "cpm_groundtruth_log.csv")
bad = [r for r in gt if r["sender_id"] in attackers and r["sender_id"] in first and (
        (r["manipulated"] == "true"  and float(r["timestamp_ms"]) <  first[r["sender_id"]]) or
        (r["manipulated"] == "false" and float(r["timestamp_ms"]) >  first[r["sender_id"]]))]
check("ground truth switches exactly at each attacker's first manipulated CPM", not bad,
      f"{len(bad)} mislabelled rows")
check("benign senders are never labelled manipulated",
      not any(r["manipulated"] == "true" for r in gt if r["sender_id"] not in attackers))
ev_s = rows("start", "cpm_eval_log.csv")
check("no TP/FN before the start time",
      not any(e["result"] in ("TP", "FN") and float(e["timestamp_ms"]) < START for e in ev_s))
pre = [e for e in ev_s if float(e["timestamp_ms"]) < START]
check("attacker senders before the start count as normal",
      any(e["sender_id"] in attackers for e in pre) and
      all(e["ground_truth"] == "normal" for e in pre if e["sender_id"] in attackers))

print("\n=== Summaries (reference) ===")
for run in ("legacy", "exclude", "start"):
    s = summary(run)
    total = sum(int(s[k]) for k in ("TP", "FP", "TN", "FN"))
    print(f"{run:8s} TP {s['TP']:>5}  FP {s['FP']:>5}  TN {s['TN']:>5}  FN {s['FN']:>5}  "
          f"total {total:>5}  Precision {float(s['Precision']):.3f}  Recall {float(s['Recall']):.3f}  FPR {float(s['FPR']):.3f}")
print("\nALL CHECKS PASSED" if ok else "\nSOME CHECKS FAILED")
sys.exit(0 if ok else 1)
EOF
