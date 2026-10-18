# VaN3Twin – CPM Attack & IDS Extension

This fork extends [VaN3Twin](https://github.com/DriveX-devs/VaN3Twin), an ETSI-compliant V2X simulation framework built on ns-3, with the ability to **simulate manipulation attacks on Collective Perception Messages (CPMs)** and to **evaluate intrusion detection systems (IDS)** against them, using per-object ground truth.

It was developed as part of the bachelor's thesis

> M. Krallinger, *Simulation and Detection of CPM Manipulation Attacks in VANETs Using Intrusion Detection Systems*, Bachelor's thesis, Salzburg University of Applied Sciences, 2026. Supervisor: FH-Prof. DI Dr. Thomas Rosenstatter.

## What this extension adds

| Component | File | Purpose |
|---|---|---|
| Attack module | `ns-3-dev/src/automotive/model/Facilities/CPMAttackModule.h` | Manipulates speed and heading of perceived objects before ASN.1 encoding; logs original and manipulated values |
| IDS module | `ns-3-dev/src/automotive/model/Facilities/CPMIDSModule.h` | Rule-based host IDS on the receiver side: speed plausibility check and heading consistency check |
| Evaluation module | `ns-3-dev/src/automotive/model/Facilities/CPMEvalModule.h` | Builds the confusion matrix during the run and computes precision, recall, FPR and accuracy |
| Attack hook | `ns-3-dev/src/automotive/model/Facilities/cpBasicService.cc` | `setAttackModule()` – the only change to upstream VaN3Twin code |
| Simulation scenario | `ns-3-dev/src/automotive/examples/v2v-cpm-attack-80211p.cc` | Main simulation (IEEE 802.11p, SUMO via TraCI) |
| SUMO scenario | `ns-3-dev/src/automotive/examples/sumo_files_v2v_CPM_attack/` | Priority-regulated crossroads, 20 vehicles, 1 km × 1 km |

All other code is upstream VaN3Twin.

## Build

Install VaN3Twin and its dependencies (including SUMO) as described in the [upstream repository](https://github.com/DriveX-devs/VaN3Twin). Then:

```bash
cd ns-3-dev
./ns3 build
```

> **Note:** If you change one of the header-only modules (`CPM*Module.h`) and the change does not seem to take effect, copy the header into `build/include/ns3/` and rebuild.

## Run

Run from inside `ns-3-dev/`, because the SUMO paths are relative to it:

```bash
./ns3 run "v2v-cpm-attack-80211p"
```

Example with random per-vehicle offsets and a fixed seed:

```bash
./ns3 run "v2v-cpm-attack-80211p --attack-mode=fixed_random --attack-speed-offset=150 --attack-heading-offset=180 --RngRun=1"
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `--attack-mode` | `fixed` | `fixed`: every attacker applies exactly the configured offsets. `fixed_random`: each attacker draws its own offsets once at start-up and keeps them for the whole run; the offset parameters act as maximum values |
| `--attack-speed-offset` | `100` | Speed offset [km/h]. In `fixed_random` mode: speed offset ~ U(0, value) |
| `--attack-heading-offset` | `90` | Heading offset [°]. In `fixed_random` mode: heading offset ~ U(−value, +value) |
| `--attacker-percentage` | `20` | Share of attacker vehicles [%]. The first N vehicles by station ID become attackers |
| `--ids-speed-threshold` | `150` | IDS: maximum plausible speed [km/h] |
| `--ids-heading-tolerance` | `45` | IDS: maximum deviation between reported and position-derived heading [°] |
| `--sim-time` | `120` | Simulation duration [s] |
| `--RngRun` | `1` | ns-3 run number (seed). Same value gives an identical run |

Speed manipulation scales both Cartesian velocity components, so the direction of travel is preserved. The attack is persistent: every CPM of an attacker is manipulated.

## Output

All files are written to the working directory (`ns-3-dev/`) and are overwritten by each run.

| File | Content |
|---|---|
| `cpm_eval_summary.csv` | Confusion matrix (TP, FP, TN, FN) and metrics |
| `cpm_eval_log.csv` | One row per received perceived object: ground-truth label, IDS decision, outcome (TP/FP/TN/FN) |
| `cpm_groundtruth_log.csv` | Received object values and whether they were manipulated |
| `cpm_attack_log.csv` | Sender side, attackers only: original and manipulated speed/heading per object |
| `cpm_ids_log.csv` | Receiver side: IDS classification per object (`normal`, `anomalous_speed`, `anomalous_heading`, `anomalous_both`) |
| `cpm_attacker_offsets.csv` | Offsets applied per attacker (shows the drawn values in `fixed_random` mode) |

Speed values in the attack and ground-truth logs are in 0.01 m/s (ASN.1 units); the IDS log uses km/h.

## Reproducibility

- Runs are deterministic: the same parameters and the same `--RngRun` produce identical output.
- `--RngRun` changes **all** random streams in ns-3 (channel, backoff, …), not only the attack offsets. Different seeds therefore also lead to slightly different traffic and CPM counts.
- With the current environment (SUMO 1.26.0), the default `fixed` run evaluates 6,026 perceived objects, while the thesis reports 5,864. The difference also occurs without any of the post-thesis changes and is most likely caused by a changed environment (e.g. SUMO version). Results from this repository should therefore be compared against a fresh baseline run rather than against the thesis tables.

## Changes since the thesis

- **`fixed_random` attack mode:** per-vehicle random offsets, reproducible via `--RngRun`.
- **Log fix:** `cpm_attack_log.csv` and `cpm_ids_log.csv` were previously overwritten by the per-vehicle module instances and contained only one vehicle. The evaluation metrics reported in the thesis were not affected, because they come from the single global evaluation module.

## License

This fork inherits the license of VaN3Twin and ns-3 (GNU GPL v2). See the license files of the upstream projects.
