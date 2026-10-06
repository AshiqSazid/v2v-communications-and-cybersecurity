#!/usr/bin/env python3
"""Learned misbehaviour detectors on VeReMi NextGen, head-to-head with ours.

The manuscript compares its sequential score against rule-based detectors only.
This adds the learned comparison a reviewer in this area expects: supervised
tree ensembles of the kind used throughout the VeReMi literature, trained and
frozen on the dataset's own Validation split and scored on its Test split.

Three things make it a fair contest rather than a flattering one.

* **Same evaluation unit.** Features and labels are built on the
  (receiver, claimed identity) pair over the same evaluation window the paper
  uses, taken from ``baselines.evaluate`` so the pair set and the
  hostile-stream label are literally the same objects our detector is scored on.
* **Same selection protocol.** Each model's operating point is chosen on
  Validation under the false-alarm constraint the paper applies to every
  comparator (worst-arm clean FPR <= 0.01, maximise mean per-arm F1), then
  frozen before Test is touched.
* **Independent evidence.** The features are raw receiver-observable
  kinematics, not our seven check outputs. A model fed our checks would measure
  the checks, not an independent detector.

No oracle field reaches a feature: the sender's true position and the attacker
labels are used for training targets and scoring only.

    .venv-ml/bin/python learned_baseline.py \\
        --runs results/veremi \\
        --threshold-json results/v9/full/analysis/selected_threshold.json \\
        --baseline-parameters results/v9/full/analysis/baseline_parameters.json \\
        --out results/v9/full/analysis/learned_baseline.json
"""
from __future__ import annotations

import argparse
import json
import math
import pathlib
import random
import statistics
import sys

import numpy as np

import baselines

FEATURES = ("dist", "claimed_speed", "age", "implied_speed",
            "speed_residual", "heading_cos", "displacement", "gap")
STATS = ("mean", "sd", "max", "min")


def pair_features(path, schema, eval_start):
    """Per-(receiver, claimed id) kinematic summaries inside the window.

    Everything here is observable at the receiver: its own position, the
    asserted position/velocity, and arrival timing. Nothing consults the
    simulator's truth about the sender.
    """
    raw: dict[tuple[int, int], dict[str, list[float]]] = {}
    last: dict[tuple[int, int], tuple[float, float, float]] = {}
    for obs in baselines.observations(path, schema):
        if obs.now < eval_start:
            continue
        key = (obs.rx, obs.claimed)
        bucket = raw.setdefault(key, {name: [] for name in FEATURES})
        speed = math.hypot(obs.vx, obs.vy)
        bucket["dist"].append(math.hypot(obs.x - obs.rx_x, obs.y - obs.rx_y))
        bucket["claimed_speed"].append(speed)
        bucket["age"].append(obs.now - obs.tx)
        prev = last.get(key)
        if prev is not None:
            px, py, pt = prev
            dt = obs.tx - pt
            if dt > 1e-6:
                dx, dy = obs.x - px, obs.y - py
                disp = math.hypot(dx, dy)
                implied = disp / dt
                bucket["gap"].append(dt)
                bucket["displacement"].append(disp)
                bucket["implied_speed"].append(implied)
                bucket["speed_residual"].append(abs(implied - speed))
                if disp > 1e-6 and speed > 1e-6:
                    bucket["heading_cos"].append((dx * obs.vx + dy * obs.vy)
                                                 / (disp * speed))
        last[key] = (obs.x, obs.y, obs.tx)
    return raw


def vectorise(raw):
    """-> (keys, X). Empty statistics become 0.0 and are flagged by the count."""
    keys, rows = [], []
    for key, bucket in raw.items():
        row = [float(len(bucket["dist"]))]
        for name in FEATURES:
            values = bucket[name]
            if values:
                row += [statistics.fmean(values),
                        statistics.pstdev(values) if len(values) > 1 else 0.0,
                        max(values), min(values)]
            else:
                row += [0.0, 0.0, 0.0, 0.0]
        keys.append(key)
        rows.append(row)
    return keys, np.asarray(rows, dtype=float)


def column_names():
    return ["count"] + [f"{f}_{s}" for f in FEATURES for s in STATS]


def load_split(runs_dir, args, prefix):
    """-> {arm: (keys, X, y, our_peak, receivers)} for one split."""
    out = {}
    for run in sorted(runs_dir.iterdir()):
        trace = run / "trace.csv"
        if not trace.exists() or not run.name.startswith(prefix):
            continue
        arm = run.name.split("__")[2]
        schema = baselines.read_schema(trace)
        meta = baselines.run_metadata(trace)
        eval_start, warmup = baselines.verify_replay_config(meta, args, meta.partition)
        ident = baselines.evaluate(trace, schema, "claimed", args, eval_start, warmup)
        raw = pair_features(trace, schema, eval_start)
        keys = [k for k in ident if k in raw]
        _, X = vectorise({k: raw[k] for k in keys})
        y = np.array([ident[k].malicious_stream for k in keys], dtype=int)
        ours = np.array([ident[k].peak_signals["sequential-score"] for k in keys])
        out[arm] = (keys, X, y, ours, np.array([k[0] for k in keys]))
    return out


def select_threshold(scores_by_arm, labels_by_arm, grid, max_fpr=0.01):
    """The paper's rule: max mean per-arm F1 subject to worst-arm clean FPR."""
    best, best_f1 = None, -1.0
    for tau in grid:
        f1s, worst = [], 0.0
        for arm in scores_by_arm:
            s, y = scores_by_arm[arm], labels_by_arm[arm]
            alert = s > tau
            tp = int((alert & (y == 1)).sum()); fn = int((~alert & (y == 1)).sum())
            fp = int((alert & (y == 0)).sum()); tn = int((~alert & (y == 0)).sum())
            prec = tp / (tp + fp) if tp + fp else 0.0
            rec = tp / (tp + fn) if tp + fn else 0.0
            f1s.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
            worst = max(worst, fp / (fp + tn) if fp + tn else 0.0)
        if worst <= max_fpr and f1s and statistics.fmean(f1s) > best_f1:
            best_f1, best = statistics.fmean(f1s), tau
    return best, best_f1


def rates(scores, y, tau):
    alert = scores > tau
    tp = int((alert & (y == 1)).sum()); fn = int((~alert & (y == 1)).sum())
    fp = int((alert & (y == 0)).sum()); tn = int((~alert & (y == 0)).sum())
    return (tp / (tp + fn) if tp + fn else float("nan"),
            fp / (fp + tn) if fp + tn else float("nan"), tp, fn, fp, tn)


def receiver_bootstrap(scores, y, receivers, tau, reps=2000, seed=20260804):
    """Resample receiver blocks, matching the external-validation section."""
    rng = random.Random(seed)
    blocks: dict[int, list[int]] = {}
    for i, r in enumerate(receivers):
        blocks.setdefault(int(r), []).append(i)
    keys = list(blocks)
    alert = scores > tau
    vals = []
    for _ in range(reps):
        num = den = 0
        for k in (rng.choice(keys) for _ in keys):
            idx = blocks[k]
            for i in idx:
                if y[i] == 1:
                    den += 1
                    num += bool(alert[i])
        if den:
            vals.append(num / den)
    if not vals:
        return float("nan"), float("nan")
    vals.sort()
    return vals[int(0.025 * len(vals))], vals[int(0.975 * len(vals))]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=pathlib.Path, required=True)
    ap.add_argument("--threshold-json", type=pathlib.Path, required=True)
    ap.add_argument("--baseline-parameters", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path)
    ap.add_argument("--seed", type=int, default=20260804)
    ap.add_argument("--road-length", default="5000")
    ap.add_argument("--road-width", default="5000")
    known, rest = ap.parse_known_args()
    sys.argv = [sys.argv[0], "--traces", str(known.runs), "--score-model", "reference",
                "--threshold-json", str(known.threshold_json),
                "--baseline-parameters", str(known.baseline_parameters),
                "--road-length", known.road_length,
                "--road-width", known.road_width, *rest]
    args = baselines.parse_args()
    frozen_tau = json.loads(known.threshold_json.read_text())["threshold"]

    from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier

    val = load_split(known.runs, args, "validation__")
    test = load_split(known.runs, args, "test__")
    if not val or not test:
        raise SystemExit(f"{known.runs}: need validation__* and test__* runs")

    Xtr = np.vstack([v[1] for v in val.values()])
    ytr = np.concatenate([v[2] for v in val.values()])
    print(f"train pairs {Xtr.shape[0]} ({int(ytr.sum())} hostile), "
          f"features {Xtr.shape[1]}, arms {sorted(val)}")
    print(f"test  pairs {sum(v[1].shape[0] for v in test.values())}, arms {sorted(test)}\n")

    models = {
        "random-forest": RandomForestClassifier(
            n_estimators=400, min_samples_leaf=2, n_jobs=-1,
            class_weight="balanced_subsample", random_state=known.seed),
        "gradient-boosting": HistGradientBoostingClassifier(
            max_iter=400, learning_rate=0.06, random_state=known.seed),
    }
    grid = [i / 1000.0 for i in range(1001)]
    report = {"frozen_tau_ours": frozen_tau, "features": column_names(),
              "train_pairs": int(Xtr.shape[0]), "detectors": {}}

    # Our detector on the identical pairs, twice. The transferred threshold is
    # the honest external test; the re-selected one puts our rule under exactly
    # the selection protocol the learned models get, so the comparison is not
    # decided by which detector was allowed to see VeReMi's validation split.
    ours_val = {a: val[a][3] for a in val}
    ours_val_y = {a: val[a][2] for a in val}
    tau_refrozen, f1_refrozen = select_threshold(ours_val, ours_val_y, grid)
    ours_variants = [("sequential-score (ours, transferred tau)", frozen_tau,
                      "frozen on our generator, transferred unchanged")]
    if tau_refrozen is not None:
        ours_variants.append(
            ("sequential-score (ours, re-frozen tau)", tau_refrozen,
             "VeReMi Validation, same selection rule as the learned models"))
    for label, tau, source in ours_variants:
        entry = {"threshold": tau, "threshold_source": source, "per_arm": {}}
        if label.endswith("re-frozen tau)"):
            entry["validation_mean_f1"] = f1_refrozen
        for arm in sorted(test):
            s, y, rx = test[arm][3], test[arm][2], test[arm][4]
            tpr, fpr, tp, fn, fp, tn = rates(s, y, tau)
            lo, hi = receiver_bootstrap(s, y, rx, tau)
            entry["per_arm"][arm] = {"tpr": tpr, "ci95": [lo, hi], "clean_fpr": fpr,
                                     "hostile": tp + fn, "clean": fp + tn}
        report["detectors"][label] = entry

    for name, model in models.items():
        model.fit(Xtr, ytr)
        val_scores = {a: model.predict_proba(val[a][1])[:, 1] for a in val}
        val_labels = {a: val[a][2] for a in val}
        tau, f1 = select_threshold(val_scores, val_labels, grid)
        if tau is None:
            report["detectors"][name] = {"threshold": None,
                                         "note": "no feasible operating point"}
            print(f"{name}: no threshold meets the false-alarm bound")
            continue
        entry = {"threshold": tau, "validation_mean_f1": f1,
                 "threshold_source": "VeReMi Validation, paper's selection rule",
                 "per_arm": {}}
        for arm in sorted(test):
            keys, X, y, _ours, rx = test[arm]
            s = model.predict_proba(X)[:, 1]
            tpr, fpr, tp, fn, fp, tn = rates(s, y, tau)
            lo, hi = receiver_bootstrap(s, y, rx, tau)
            entry["per_arm"][arm] = {"tpr": tpr, "ci95": [lo, hi], "clean_fpr": fpr,
                                     "hostile": tp + fn, "clean": fp + tn}
        if hasattr(model, "feature_importances_"):
            order = np.argsort(model.feature_importances_)[::-1][:6]
            entry["top_features"] = [(column_names()[i],
                                      round(float(model.feature_importances_[i]), 4))
                                     for i in order]
        report["detectors"][name] = entry

    if known.out:
        known.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    arms = sorted(test)
    print(f"{'detector':<26}{'tau':>7}" + "".join(f"{a[:11]:>13}" for a in arms))
    for name, entry in report["detectors"].items():
        if entry.get("threshold") is None:
            continue
        row = f"{name:<26}{entry['threshold']:>7.3f}"
        for arm in arms:
            row += f"{entry['per_arm'][arm]['tpr']:>13.3f}"
        print(row)
    print("\nclean-pair FPR, same order:")
    for name, entry in report["detectors"].items():
        if entry.get("threshold") is None:
            continue
        row = f"{name:<26}{'':>7}"
        for arm in arms:
            row += f"{entry['per_arm'][arm]['clean_fpr']:>13.3f}"
        print(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
