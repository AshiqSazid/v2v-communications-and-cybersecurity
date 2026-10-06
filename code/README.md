# V2V identity-keyed misbehaviour detection

This repository contains an ns-3.40 experiment for an **identity-keyed,
sequential plausibility/evidence detector** for V2V Basic Safety Messages
(BSMs). It is a research artifact under revision for an IEEE submission.

The detector is not a calibrated Bayesian posterior and is not an operational
STRIDE/DREAD risk engine. Its score is a bounded **sequential log-evidence
score** formed by accumulating evidence from physical-plausibility checks and
mapped to [0,1] by a logistic. That mapped value is not a probability: the
checks are correlated, non-firing checks contribute nothing by default, and the
weights are assumptions. Do not write `P(compromised | evidence)` for it.

There is exactly one decision variable. A pair is COMPROMISED iff its window
peak score exceeds the frozen threshold. The STRIDE/DREAD layer produces an
**ordinal risk-priority index** `Q = S x I(class)` that ranks alerts already
raised; it never feeds detection, so every detection number is independent of
the expert-assigned impact weights.

Threat attribution is keyed on the **largest evidence contribution**, not the
largest impact. An earlier revision selected by impact, which made the assigned
class a function of the weights that are then multiplied in again. Attribution
that is not separable — runner-up class within `STRIDE_AMBIGUITY` = 0.5
log-evidence units — is reported as ambiguous rather than forced to one label.

Read [result.md](result.md) before quoting a number. The older result files were
produced with definitions that do not satisfy the v4 evaluation contract;
they are historical diagnostics, not publication results.

## What the artifact evaluates

Each honest receiver maintains detector state by the untrusted
`claimed_id`. The experiment records enough oracle information to evaluate
three different questions without silently conflating them:

1. **Malicious-stream detection:** did this receiver/claimed-ID stream contain
   at least one message explicitly labelled malicious after the declared attack
   onset? Assigned attacker status alone is not a positive message label.
2. **Owner attribution:** does the claimed identity actually belong to an
   attacker? An alert on an impersonated honest identity is a false
   attribution under this definition.
3. **Clean-pair false alarms:** did an alert occur on an honest identity whose
   stream never contained a malicious message?

Impersonation exposure is reported both as receiver–victim pairs and as unique
victim identities. These denominators are different and must not be described
as numbers of vehicles interchangeably.

The primary operational decision is identical for every label: a pair is
COMPROMISED iff its peak score over the declared evaluation window exceeds the
frozen threshold. Crossing times remain secondary latency telemetry and never
replace that rule for positives or negatives.

Mid-stream intervention arms enforce `warmup < attackStart < simTime`, and
assigned attackers transmit honest, nominal-rate messages before
`attackStart`. Paired steady-state controls intentionally use `attackStart=0`
so attackers are adversarial from their first message. Replay is malicious
only when a captured message is actually replayed. Evidence forgetting uses
elapsed seconds (`decayHalfLife`), not the number of received messages.
Validation stores merged half-open crossing intervals so threshold selection
exactly reproduces the runtime rule.

## Layout

```text
code/
├── v2v_cybersecurity_v2.cc   ns-3 simulation (filename kept for build compatibility)
├── run_experiments.sh        strict experiment runner and manifest generation
├── aggregate.py              schema validation and seed-clustered summaries
├── baselines.py              transparent structural-rule comparisons
├── project.md                design, threat model, metrics, and CLI reference
├── result.md                 result status and claim boundary
├── results/                  versioned artifacts; v9 is the next valid sweep
├── test/                     source-derived detector tests
└── traces/                   optional per-reception traces (normally gitignored)
```

The C++ filename and ns-3 target retain `v2` only for compatibility. The
machine-readable output declares its own schema version.

## Build and run

Verified against ns-3.40:

```bash
cp v2v_cybersecurity_v2.cc <ns-3-root>/scratch/
cd <ns-3-root>
./ns3 build v2v_cybersecurity_v2

./ns3 run "v2v_cybersecurity_v2 \
  --attack=mixedhard \
  --nVehicles=70 \
  --attackerFraction=0.3 \
  --scoreModel=reference \
  --gpsSigma=2 \
  --detectorGpsSigma=2 \
  --run=1"
```

Ask the binary for the authoritative summary schema:

```bash
./ns3 run "v2v_cybersecurity_v2 --csvHeader=true"
```

The analysis workflow requires Python 3.10+ with NumPy, SciPy and matplotlib.
**Use a virtual environment.** On a system that has matplotlib from both apt and
pip, `mpl_toolkits` resolves to the apt copy while `matplotlib` resolves to the
pip one -- the apt package installs `matplotlib-<ver>-nspkg.pth`, which pins the
namespace package to `dist-packages`. The two then disagree and every figure run
prints `Unable to import Axes3D`. A venv sees neither, which is the fix:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python make_scenario_figure.py        # no warning
```

`requirements.txt` gives the supported ranges; `requirements-lock.txt` pins the
exact versions the reported figures were produced with.

Important options:

- `--scoreModel=reference|simfit` selects either the documented reference
  evidence weights or weights fitted on this simulator's own traces.
  `simfit` is a circular sensitivity analysis, not external calibration.
- `--gpsSigma` controls the noise used to generate observations.
- `--detectorGpsSigma` is the noise level assumed by the detector. Keeping
  these separate permits a genuine misspecification experiment.
- `--pairOutput=<path>` writes one auditable record per
  receiver/claimed-identity pair.
- `--attackStart=<seconds>` declares the intervention time and must lie
  strictly between warm-up and simulation end.
- `--decayHalfLife=<seconds>` controls elapsed-time forgetting; `-1` disables
  forgetting. The old per-message `--decay` input is deprecated and converted.
- `--trace=<path>` writes the per-reception trace, including receiver position
  receiver-observable source IPv4, and clearly prefixed evaluation-only oracle
  fields for role, onset, and per-message maliciousness.

The simulation validates enumerated options, ranges, and finite numeric inputs.
Unknown attack or score-model names are errors.

## Tests and experiments

```bash
# ns-3-independent checks derived from the shipped source
bash test/run_tests.sh

# show the current experiment-runner interface
bash run_experiments.sh smoke --help

# fast 40-run end-to-end check; archives an older smoke output if present
bash run_experiments.sh smoke --fresh --jobs 4

# validate and summarize a completed result set
python3 aggregate.py --help

# Fit baseline settings on validation traces only.
python3 baselines.py \
  --traces results/v9/full/runs/validation \
  --pattern '**/trace.csv' \
  --score-model reference \
  --threshold-json results/v9/full/analysis/selected_threshold.json \
  --fit-output results/v9/full/analysis/baseline_parameters.json

# Apply the frozen artifact to held-out test traces.
python3 baselines.py \
  --traces results/v9/full/runs/test \
  --pattern '**/trace.csv' \
  --score-model reference \
  --threshold-json results/v9/full/analysis/selected_threshold.json \
  --baseline-parameters results/v9/full/analysis/baseline_parameters.json \
  --metrics-output results/v9/full/analysis/baseline_metrics.json
```

## Regenerating every paper figure and table

`run_experiments.sh` produces the sweep, the merged tables, `analysis/report_v4.md`
and the manifest. It does **not** produce the figures or the extended analyses —
those are the commands below. Run them in this order after the sweep completes;
`R` is the frozen result root, e.g. `results/v9/full`.

```bash
R=results/v9/full

# --- extended analyses -------------------------------------------------
# arm_inventory.csv (Table: experimental inventory) and extended_metrics.csv,
# which carry the association diagnostics: track purity, merges, fragments,
# identity switches, and the per-keying alert rates.
python3 extended_analysis.py \
  --summary "$R/summary_v4.csv" --pairs "$R/pairs_v4.csv" \
  --output-dir "$R/analysis"

# Kendall-tau stability of the priority ranking under alternative DREAD
# weight sets (Table: impact sensitivity).
python3 impact_sensitivity.py \
  --pairs "$R/pairs_v4.csv" \
  --json-out "$R/analysis/impact_sensitivity.json"

# Contingency table of simulated attack type vs assigned STRIDE class
# (reviewer point 4). Reported as a contingency table, never as accuracy:
# no external ground truth assigns one correct consequence class per attack.
python3 attribution_matrix.py --pairs "$R/pairs_v4.csv" \
  --out-csv "$R/analysis/attribution_matrix.csv" \
  --out-tex "$R/analysis/attribution_matrix.tex"

# Detection stratified by receiver-sender distance (Section: blind spots).
python3 distance_analysis.py \
  --traces "$R/runs/test" --pattern '**/trace.csv' \
  --output "$R/analysis/distance_metrics.csv"

# --- figures -----------------------------------------------------------
# Fig. methodology: run/arm counts are read from the frozen TSV plans, never
# transcribed. This is the command that keeps the figure reconciled with
# the inventory table.
python3 make_methodology_figure.py --results-root "$R"

# Fig. detection (arm-level detection and discrimination).
python3 make_result_figures.py --metrics "$R/analysis/metrics_v4.csv"

# Fig. risk (priority index and attributed threat class).
python3 make_risk_figure.py --pairs "$R/pairs_v4.csv" \
  --out-csv "$R/analysis/risk_metrics.csv"

# Fig. ROC/PR with the frozen operating point marked on the test curve.
# NOTE: --metrics-csv is an OUTPUT path. Pointing it at metrics_v4.csv
# overwrites the aggregate's own metrics file with the five-row ROC summary
# and breaks make_result_figures.py, which reads metrics_v4.csv as input.
python3 make_roc_figure.py --pairs "$R/pairs_v4.csv" \
  --threshold-json "$R/analysis/selected_threshold.json" \
  --metrics-csv "$R/analysis/roc_metrics.csv"

# Fig. ground-truth labels (schematic; consumes no results).
python3 make_labels_figure.py

# Fig. identity-vs-track ablation. NOTE: this reads the *baselines* report
# (the stdout of baselines.py), not analysis/report_v4.md -- it parses the
# "Attack stratum:" blocks and per-keying rows that only baselines.py emits.
python3 make_ids_figure.py --report "$R/analysis/baseline_report.txt"

# Fig. onset (score trajectories around attack activation).
python3 make_onset_figure.py --traces "$R/runs/test" \
  --pattern '**/trace.csv' --metrics "$R/analysis/metrics_v4.csv" \
  --output figures/fig_onset.pdf

# No publish step: ieee.tex loads code/figures/*.pdf directly, so a figure is
# live in the manuscript as soon as its generator writes it. There is no second
# copy of the figures to keep in sync.
```

Every number quoted in the manuscript comes from `$R/analysis/report_v4.md`,
`$R/analysis/extended_metrics.csv` or `$R/manifest_v4.json`. Nothing is
transcribed from an earlier sweep: the manifest records the source, binary,
plan, threshold and analysis hashes, and a result set is only citable when
those hashes match the shipped source and the completed-run count equals the
plan.

The publication workflow contains 439 validation and 1,040 held-out test runs
and keeps their RNG seeds separate. It adds paired onset-guard, focused
constant-offset activation-time controls at 5 s and 20 s, and honest
GNSS/fixed-clock-offset stress arms. The activation-time controls are
secondary/post-hoc and excluded from headline pooling. The clock arm models a
fixed per-vehicle offset, not clock drift. Attack-bearing validation runs use
the same N=50 and 30% prevalence as held-out pure-attack runs; the 299 benign
validation seeds retain N=70 to match the held-out benign target.
Threshold selection evaluates a preregistered 0.001 grid using the exact
runtime crossing rule. The full plan uses 299 independent benign validation
seeds: with zero seed-level false-alarm events, the exact one-sided 95% upper
bound is below 1%. The selected threshold is frozen before the test plan is
created. Smoke mode relaxes this inferential constraint and is only a pipeline
check. Manifests record the exact grid and software/binary provenance.

Detector CPU timing must be measured serially. Parallel wall-clock timing is
contaminated by host contention.

The summary reports per-call P50/P95/P99/max timing and timing-derived call
throughput. `estimated_state_payload_bytes_per_receiver` is a documented
field-payload estimate—not RSS—and excludes allocator/STL overhead. It includes
the identity history plus each live deployable track's fixed state and dynamic
replay FIFO/set and rate-window payload; oracle/evaluation tracks are excluded.

## Claim boundary

The artifact can test the detector's behavior and expose the attribution
failure of claimed-identity keying within this simulator. It currently does
**not** establish:

- superiority to any published detector;
- performance on VeReMi or another external benchmark;
- calibration of the decision score as a probability;
- generalization beyond the simulated channel, traffic, mobility, and attacks;
- resistance to Sybil or colluding adversaries; or
- execution cost on production vehicle hardware.

V4 adds an explicit `identity-contested` mitigation: a claimed identity is
flagged when it appears from multiple receiver-observable network sources.
This is a prototype output, not yet an externally validated security solution;
network-source spoofing and legitimate pseudonym changes remain limitations.
The summary also reports in-range malicious pair opportunities, the subset
observed, and zero-reception opportunities separately from detector confusion.

`baselines.py` therefore uses descriptive structural/fusion-rule names rather
than names of published detectors. Every tunable threshold and EWMA setting is
fit on all 439 validation traces, saved with trace hashes, and frozen before
held-out test replay. Each rule uses its own native-scale threshold under the
same exact one-sided 95% benign-seed upper-bound constraint (at most 1%) over
all 299 benign validation seeds. It also fits a supervised logistic-regression baseline using the
seven cumulative check-fire rates; the artifact records feature order,
scaling, coefficients, and threshold. Held-out output includes precision,
recall, F1, FP count, ROC-AUC, PR-AUC, delay/censoring, and seed-block
intervals. Reported replay runtime is analysis-host offline time, not OBU
latency. Headline baseline pooling is restricted to `test/pure_attack/*` plus
the explicitly defined `test/benign/*` population; onset and steady-state
controls are reported separately. The range and sudden-appearance rules use
the trace's receiver true position because no noisy receiver self-position is
recorded, so they are oracle-assisted structural upper bounds rather than
deployable baselines. Its oracle-source-keyed arm is an evaluation-only identifiability
diagnostic, not a deployable competitor. A published detector and an external
benchmark remain required before making a superiority claim.
