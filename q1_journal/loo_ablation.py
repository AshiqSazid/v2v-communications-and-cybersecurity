#!/usr/bin/env python3
"""Report the leave-one-check-out ablation from one baseline replay.

baselines.py carries seven extra arms, ``seq-no-<check>``, each the sequential
rule with one check silenced. They ride along in the same pass, so this reads a
single metrics file rather than re-running anything:

    python3 baselines.py --traces results/v9/full/runs/test \\
        --pattern '**/trace.csv' --score-model reference \\
        --threshold-json  results/v9/full/analysis/selected_threshold.json \\
        --baseline-parameters results/v9/full/analysis/baseline_parameters.json \\
        --metrics-output results/v9/full/analysis/baseline_metrics_loo.json

    python3 loo_ablation.py \\
        --metrics results/v9/full/analysis/baseline_metrics_loo.json \\
        --out results/v9/full/analysis/loo_ablation.json

The threshold is the frozen one in every arm. Re-selecting per arm would ask
how well a reduced check set could do if retuned; holding it fixed asks what
losing a check costs the detector that was actually frozen.
"""
from __future__ import annotations

import argparse
import json
import statistics as st
from pathlib import Path

REFERENCE = "sequential-score"


def summarise(per_run, detector, families, mode="claimed"):
    rows = [r for r in per_run
            if r["detector"] == detector and r["mode"] == mode
            and r["family"] in families]
    tpr = [r["stream_tpr"] for r in rows if r["stream_tpr"] is not None]
    fpr = [r["clean_fpr"] for r in rows if r["clean_fpr"] is not None]
    by_attack: dict[str, list[float]] = {}
    for r in rows:
        if r["stream_tpr"] is not None:
            by_attack.setdefault(r["attack"], []).append(r["stream_tpr"])
    return {
        "pooled_tpr": st.mean(tpr) if tpr else None,
        "clean_fpr": st.mean(fpr) if fpr else None,
        "per_attack_tpr": {k: st.mean(v) for k, v in sorted(by_attack.items())},
        "seed_count": len({r["seed"] for r in rows}),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--metrics", type=Path, required=True)
    p.add_argument("--out", type=Path)
    args = p.parse_args()

    blob = json.loads(args.metrics.read_text())
    per_run = blob["per_run_metrics"]
    families = set(blob["headline_families"])
    arms = sorted({r["detector"] for r in per_run if r["detector"].startswith("seq-no-")})
    if not arms:
        raise SystemExit(
            f"{args.metrics}: no seq-no-* arms. Regenerate with the current "
            "baselines.py, which carries the leave-one-check-out detectors."
        )

    control = summarise(per_run, REFERENCE, families)
    report = {
        "detector": REFERENCE,
        "note": "threshold frozen across arms; checks silenced, not retuned",
        "control": control,
        "removed": {},
    }
    for arm in arms:
        check = arm[len("seq-no-"):]
        v = summarise(per_run, arm, families)
        v["delta_pooled_tpr"] = v["pooled_tpr"] - control["pooled_tpr"]
        v["delta_clean_fpr"] = v["clean_fpr"] - control["clean_fpr"]
        report["removed"][check] = v

    if args.out:
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print(f"{'check removed':<16}{'pooled TPR':>12}{'delta':>10}{'clean FPR':>12}")
    print(f"{'(none)':<16}{control['pooled_tpr']:>12.4f}{'--':>10}"
          f"{control['clean_fpr']:>12.4f}")
    for check, v in sorted(report["removed"].items(),
                           key=lambda kv: kv[1]["delta_pooled_tpr"]):
        print(f"{check:<16}{v['pooled_tpr']:>12.4f}"
              f"{v['delta_pooled_tpr']:>+10.4f}{v['clean_fpr']:>12.4f}")


if __name__ == "__main__":
    main()
