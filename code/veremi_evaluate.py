#!/usr/bin/env python3
"""Evaluate the detector on converted VeReMi NextGen runs.

    python3 veremi_evaluate.py --runs results/veremi \
        --threshold-json results/v9/full/analysis/selected_threshold.json \
        --baseline-parameters results/v9/full/analysis/baseline_parameters.json

Reports each endpoint twice:

  * at the threshold frozen on OUR generator (tau = 0.498), transferred
    unchanged -- the honest external test;
  * at a threshold re-frozen on VeReMi's own Validation split under the same
    macro-F1-under-a-false-alarm-bound rule -- the fair-calibration test.

The gap between them is the quantity of interest: it measures how much of the
operating point is generator-specific rather than a property of the detector.

Uncertainty is a RECEIVER-block bootstrap, which is weaker than the seed-block
bootstrap used everywhere else in the paper. VeReMi NextGen ships one simulation
per (scenario, attack, split), so there is no seed dimension to resample and the
exact seed-level false-alarm bound has no counterpart here. Receivers within one
simulation share a mobility and channel realisation, so these intervals
understate uncertainty and are labelled as such rather than presented as
equivalent to the in-generator ones.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import random
import statistics
import sys

import baselines
import veremi_track


def load_run(run: pathlib.Path, args):
    trace = run / "trace.csv"
    schema = baselines.read_schema(trace)
    meta = baselines.run_metadata(trace)
    eval_start, warmup = baselines.verify_replay_config(meta, args, meta.partition)
    ident = baselines.evaluate(trace, schema, "claimed", args, eval_start, warmup)
    tracks, drops = veremi_track.evaluate_track_keyed(trace, schema, args, eval_start, warmup)
    return ident, tracks, drops


def endpoints(ident, tracks, tau):
    """-> (stream TPR, clean FPR, per-receiver contributions for bootstrap)."""
    tp = fn = fp = tn = 0
    by_rx = {}
    for (rx, claimed), st in ident.items():
        hostile = st.malicious_stream
        alert = st.peak_signals["sequential-score"] > tau
        rec = by_rx.setdefault(rx, [0, 0, 0, 0])
        if hostile:
            tp += alert
            fn += not alert
            rec[0] += alert
            rec[1] += not alert
        else:
            fp += alert
            tn += not alert
            rec[2] += alert
            rec[3] += not alert
    tpr = tp / (tp + fn) if tp + fn else float("nan")
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    return tpr, fpr, by_rx, (tp, fn, fp, tn)


def boot(by_rx, index_num, index_den, reps=2000, seed=20260804):
    rng = random.Random(seed)
    keys = list(by_rx)
    vals = []
    for _ in range(reps):
        num = den = 0
        for k in (rng.choice(keys) for _ in keys):
            r = by_rx[k]
            num += r[index_num]
            den += r[index_num] + r[index_den]
        if den:
            vals.append(num / den)
    if not vals:
        return float("nan"), float("nan")
    vals.sort()
    return vals[int(0.025 * len(vals))], vals[int(0.975 * len(vals))]


def refreeze(runs, args, grid):
    """Re-select tau on the VeReMi Validation split, same rule as the paper."""
    best, best_f1 = None, -1.0
    for tau in grid:
        f1s, worst_fpr = [], 0.0
        for ident, _tracks, _d in runs:
            tpr, fpr, _by, (tp, fn, fp, tn) = endpoints(ident, None, tau)
            prec = tp / (tp + fp) if tp + fp else 0.0
            rec = tp / (tp + fn) if tp + fn else 0.0
            f1s.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
            worst_fpr = max(worst_fpr, 0.0 if fpr != fpr else fpr)
        if worst_fpr <= 0.01 and f1s and statistics.mean(f1s) > best_f1:
            best_f1, best = statistics.mean(f1s), tau
    return best, best_f1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=pathlib.Path, required=True)
    ap.add_argument("--threshold-json", type=pathlib.Path, required=True)
    ap.add_argument("--baseline-parameters", type=pathlib.Path, required=True)
    ap.add_argument("--road-length", default="5000")
    ap.add_argument("--road-width", default="5000")
    known, rest = ap.parse_known_args()
    sys.argv = [sys.argv[0], "--traces", str(known.runs), "--score-model", "reference",
                "--threshold-json", str(known.threshold_json),
                "--baseline-parameters", str(known.baseline_parameters),
                "--road-length", known.road_length, "--road-width", known.road_width, *rest]
    args = baselines.parse_args()
    frozen = json.loads(known.threshold_json.read_text())["threshold"]

    val, test = {}, {}
    for run in sorted(known.runs.iterdir()):
        if not (run / "trace.csv").exists():
            continue
        arm = run.name.split("__")[2]
        (val if run.name.startswith("validation__") else test)[arm] = load_run(run, args)

    grid = [i / 1000.0 for i in range(1001)]
    tau_new, f1_new = refreeze(list(val.values()), args, grid)
    print(f"threshold frozen on our generator : {frozen}")
    print(f"threshold re-frozen on VeReMi val : {tau_new}  (macro-F1 {f1_new:.4f})\n")

    for label, tau in (("transferred tau", frozen), ("re-frozen tau", tau_new)):
        if tau is None:
            print(f"{label}: no feasible threshold under the false-alarm bound\n")
            continue
        print(f"--- {label} = {tau} (held-out VeReMi Test) ---")
        print(f"{'attack':<22}{'TPR':>8}{'95% CI':>18}{'cleanFPR':>10}{'hostile':>9}{'clean':>8}")
        for arm in sorted(test):
            ident, tracks, _d = test[arm]
            tpr, fpr, by_rx, (tp, fn, fp, tn) = endpoints(ident, tracks, tau)
            lo, hi = boot(by_rx, 0, 1)
            ci = f"[{lo:.3f},{hi:.3f}]" if lo == lo else "--"
            print(f"{arm:<22}{tpr:>8.3f}{ci:>18}{fpr:>10.3f}{tp+fn:>9}{fp+tn:>8}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
