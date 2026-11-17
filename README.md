# VaN3Twin – CPM Attack & IDS Extension

This fork extends [VaN3Twin](https://github.com/DriveX-devs/VaN3Twin), an ETSI-compliant V2X simulation framework built on ns-3, with the ability to **simulate manipulation attacks on Collective Perception Messages (CPMs)** and to **evaluate intrusion detection systems (IDS)** against them, using per-object ground truth.

It was developed as part of the bachelor's thesis

> M. Krallinger, *Simulation and Detection of CPM Manipulation Attacks in VANETs Using Intrusion Detection Systems*, Bachelor's thesis, Salzburg University of Applied Sciences, 2026. Supervisor: FH-Prof. DI Dr. Thomas Rosenstatter.

## What this extension adds

| Component | File | Purpose |
|---|---|---|
| Attack module | `src/automotive/model/Facilities/CPMAttackModule.h` | Manipulates speed and heading of perceived objects before ASN.1 encoding; logs original and manipulated values |
| IDS module | `src/automotive/model/Facilities/CPMIDSModule.h` | Rule-based host IDS on the receiver side: speed plausibility check and heading consistency check |
| Evaluation module | `src/automotive/model/Facilities/CPMEvalModule.h` | Builds the confusion matrix during the run and computes precision, recall, FPR and accuracy |
| Attack hook | `src/automotive/model/Facilities/cpBasicService.cc` | `setAttackModule()` – the only change to upstream VaN3Twin code besides registering the new files in the two `CMakeLists.txt` |
| Simulation scenario | `src/automotive/examples/v2v-cpm-attack-80211p.cc` | Main simulation (IEEE 802.11p, SUMO via TraCI) |
| SUMO scenario | `src/automotive/examples/sumo_files_v2v_CPM_attack/` | Priority-regulated crossroads, 20 vehicles, 1 km × 1 km |

All other code is upstream VaN3Twin.

## Installation

The repository has the same layout as upstream VaN3Twin and is installed the same way: `sandbox_builder.sh` downloads ns-3 and installs this repository into `ns-3-dev/`. It is based on upstream commit [`4d65b39`](https://github.com/DriveX-devs/VaN3Twin/commit/4d65b39) (2 April 2026), the version used in the thesis, so `git diff 4d65b39` shows every change made by the extension. Tested on Ubuntu 22.04 (also under WSL). Install SUMO first (see the [VaN3Twin docs](https://github.com/DriveX-devs/VaN3Twin)).

```bash
git clone -b cpm-attack-ids-extension https://github.com/8943589648/VaN3Twin-cpm-attack-ids-extension.git
cd VaN3Twin-cpm-attack-ids-extension
./sandbox_builder.sh install-dependencies   # omit the argument if the ns-3 dependencies are already installed
cd ns-3-dev
./ns3 configure --build-profile=optimized --enable-examples --enable-tests --disable-python --disable-werror
./ns3 build
```

As in upstream VaN3Twin, the script removes the git metadata from the folder it runs in; keep a separate clone if you want to work with the history. `install-dependencies` also builds gRPC and OpenCV from source, which takes a while.

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
| `--attack-start` | `0` | Time [s] from which attackers manipulate their CPMs. Before that they behave like benign vehicles |
| `--eval-exclude-attackers` | `true` | Leave the IDS decisions of attacker vehicles (as receivers) out of the metrics. The IDS still runs on all vehicles |
| `--ids-speed-threshold` | `150` | IDS: maximum plausible speed [km/h] |
| `--ids-heading-tolerance` | `45` | IDS: maximum deviation between reported and position-derived heading [°] |
| `--sim-time` | `120` | Simulation duration [s] |
| `--RngRun` | `1` | ns-3 run number (seed). Same value gives an identical run |

Speed manipulation scales both Cartesian velocity components, so the direction of travel is preserved. Once started, the attack is persistent: every CPM of an attacker is manipulated.

**Ground-truth label:** a received object counts as manipulated if its sender is an attacker and that attacker had already generated a manipulated CPM, i.e. the attack was active when the CPM was generated.

## Output

All files are written to the working directory (`ns-3-dev/`) and are overwritten by each run.

| File | Content |
|---|---|
| `cpm_eval_summary.csv` | Confusion matrix (TP, FP, TN, FN) and metrics |
| `cpm_eval_log.csv` | One row per evaluated perceived object: ground-truth label, IDS decision, outcome (TP/FP/TN/FN) |
| `cpm_groundtruth_log.csv` | Received object values and whether they were manipulated |
| `cpm_attack_log.csv` | Sender side, attackers only: original and manipulated speed/heading per object |
| `cpm_ids_log.csv` | Receiver side: IDS classification per object (`normal`, `anomalous_speed`, `anomalous_heading`, `anomalous_both`) |
| `cpm_attacker_offsets.csv` | Offsets and start time per attacker (shows the drawn values in `fixed_random` mode) |

Speed values in the attack and ground-truth logs are in 0.01 m/s (ASN.1 units); the IDS log uses km/h.

## Reproducibility

- Runs are deterministic: the same parameters and the same `--RngRun` produce identical output.
- `--RngRun` changes **all** random streams in ns-3 (channel, backoff, …), not only the attack offsets. Different seeds therefore also lead to slightly different traffic and CPM counts.
- With the current environment (SUMO 1.26.0), the default `fixed` run evaluates 6,026 perceived objects, while the thesis reports 5,864. The difference also occurs without any of the post-thesis changes and is most likely caused by a changed environment (e.g. SUMO version). Results from this repository should therefore be compared against a fresh baseline run rather than against the thesis tables.

## Changes since the thesis

- **`fixed_random` attack mode:** per-vehicle random offsets, reproducible via `--RngRun`.
- **Log fix:** `cpm_attack_log.csv` and `cpm_ids_log.csv` were previously overwritten by the per-vehicle module instances and contained only one vehicle. The evaluation metrics reported in the thesis were not affected, because they come from the single global evaluation module.
- **Attack start time** (`--attack-start`): attackers can start manipulating later in the run; the ground-truth label follows the actual start.
- **Attacker receivers excluded from the evaluation** (`--eval-exclude-attackers`, on by default): in the thesis, IDS decisions of attacker vehicles were counted as well.

To reproduce the evaluation method used in the thesis, run with `--eval-exclude-attackers=false --attack-start=0`.

## Verification

`verify.sh` checks the attack modes and the logs, `verify_eval.sh` checks the attack start time and the receiver exclusion. Run both from `ns-3-dev/`.

## License

This fork inherits the license of VaN3Twin and ns-3 (GNU GPL v2). See the license files of the upstream projects.
