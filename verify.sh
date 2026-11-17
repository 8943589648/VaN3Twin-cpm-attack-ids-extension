#!/usr/bin/env bash
# Verifies the CPM attack extension changes:
#   1. fixed mode applies exact offsets       2. log fix (complete attack/IDS logs)
#   3. fixed_random: range, per-vehicle constancy, reproducibility, seed dependence
# Usage: run from ~/VaN3Twin/ns-3-dev   ->   bash verify.sh
set -e
OUT=verify_runs
rm -rf "$OUT"; mkdir -p "$OUT"

run() {
    local name=$1; shift
    echo ">> run '$name': $*"
    ./ns3 run "v2v-cpm-attack-80211p $*" > "$OUT/$name.stdout" 2>&1
    mkdir -p "$OUT/$name"
    mv cpm_*.csv "$OUT/$name/"
}

RAND="--attack-mode=fixed_random --attack-speed-offset=150 --attack-heading-offset=180"
run fixed  --attack-mode=fixed --eval-exclude-attackers=false   # keeps 'IDS log as long as eval log' valid
run rand1a $RAND --RngRun=1
run rand1b $RAND --RngRun=1
run rand2  $RAND --RngRun=2

python3 - "$OUT" <<'EOF'
import csv, math, sys, filecmp
B = sys.argv[1]; ok = True

def check(name, cond, detail=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail else ""))
    ok &= bool(cond)

def rows(run, f):    return list(csv.DictReader(open(f"{B}/{run}/{f}")))
def headers(run, f): return sum(1 for l in open(f"{B}/{run}/{f}") if l[:1].isalpha())
def same(f):         return filecmp.cmp(f"{B}/rand1a/{f}", f"{B}/rand1b/{f}", shallow=False)
def dv(r): return (math.hypot(float(r["atk_xSpeed"]), float(r["atk_ySpeed"]))
                 - math.hypot(float(r["orig_xSpeed"]), float(r["orig_ySpeed"]))) * 0.036
def dh(r): return float(r["atk_heading_deg"]) - float(r["orig_heading_deg"])
def angle_eq(a, b, tol=0.5): return abs((a - b + 180) % 360 - 180) < tol

print("\n=== 1. fixed mode ===")
off = rows("fixed", "cpm_attacker_offsets.csv")
check("all attackers get exactly +100 km/h / +90 deg",
      all(float(r["speed_offset_kmh"]) == 100 and float(r["heading_offset_deg"]) == 90 for r in off))
atk = rows("fixed", "cpm_attack_log.csv")
check("every manipulated object is +100 km/h", all(abs(dv(r) - 100) < 0.5 for r in atk))
check("every manipulated object is +90 deg",   all(angle_eq(dh(r), 90) for r in atk))

print("\n=== 2. log fix ===")
attackers = {r["station_id"] for r in off}
senders = {r["sender_id"] for r in atk}
check("attack log contains every attacker", senders == attackers,
      f"log: {sorted(senders, key=int)}, attackers: {sorted(attackers, key=int)}")
ids, ev = rows("fixed", "cpm_ids_log.csv"), rows("fixed", "cpm_eval_log.csv")
check("IDS log as long as eval log", len(ids) == len(ev), f"{len(ids)} vs {len(ev)}")
check("exactly one header per log",
      headers("fixed", "cpm_attack_log.csv") == 1 and headers("fixed", "cpm_ids_log.csv") == 1)

print("\n=== 3. fixed_random mode ===")
o1 = rows("rand1a", "cpm_attacker_offsets.csv")
o2 = rows("rand2",  "cpm_attacker_offsets.csv")
for name, o in (("RngRun=1", o1), ("RngRun=2", o2)):
    check(f"{name}: offsets within range (0..150 km/h, -180..180 deg)",
          all(0 <= float(r["speed_offset_kmh"]) <= 150 and -180 <= float(r["heading_offset_deg"]) <= 180 for r in o))
check("attackers get different offsets", len({r["speed_offset_kmh"] for r in o1}) > 1)
drawn = {r["station_id"]: (float(r["speed_offset_kmh"]), float(r["heading_offset_deg"])) for r in o1}
ra = rows("rand1a", "cpm_attack_log.csv")
check("each attacker applies its drawn offsets in every CPM",
      all(abs(dv(r) - drawn[r["sender_id"]][0]) < 0.5 and angle_eq(dh(r), drawn[r["sender_id"]][1]) for r in ra))
check("same seed -> identical offsets",   same("cpm_attacker_offsets.csv"))
check("same seed -> identical results",   same("cpm_eval_log.csv") and same("cpm_eval_summary.csv"))
check("different seed -> different offsets",
      [r["speed_offset_kmh"] for r in o1] != [r["speed_offset_kmh"] for r in o2])

print("\n=== Summaries (reference) ===")
for run in ("fixed", "rand1a", "rand2"):
    s = {r["metric"]: r["value"] for r in rows(run, "cpm_eval_summary.csv")}
    print(f"{run:7s} TP {s['TP']:>5}  FP {s['FP']:>5}  TN {s['TN']:>5}  FN {s['FN']:>5}  Recall {float(s['Recall']):.3f}")
print("\nALL CHECKS PASSED" if ok else "\nSOME CHECKS FAILED")
sys.exit(0 if ok else 1)
EOF
