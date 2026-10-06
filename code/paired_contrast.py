#!/usr/bin/env python3
"""Paired seed-block contrast between fusion rules on the frozen held-out set.

Every comparator is replayed on the same traces under the same seeds, so the
rule-to-rule difference is paired at the seed level.  The published table
reports each rule's marginal TPR, which leaves the reader unable to tell a
0.002 gap from a 0.002 standard error.  This script resamples whole seed
blocks -- the same resampling unit every interval in the paper uses -- and
reports the distribution of the *difference*.

It consumes only analysis/baseline_metrics.json from the frozen result root and
adds no new simulation.

    python3 paired_contrast.py --metrics results/v9/full/analysis/baseline_metrics.json
"""
from __future__ import annotations

import argparse
import json
import statistics as st
from pathlib import Path

import numpy as np

REFERENCE = "sequential-score"


def pooled_by_seed(per_run, detector, families, mode="claimed"):
    """Pooled stream TPR per seed: mean over the attack arms that seed ran."""
    by_seed: dict[int, list[float]] = {}
    for r in per_run:
        if (r["detector"] == detector and r["family"] in families
                and r["mode"] == mode and r["stream_tpr"] is not None):
            by_seed.setdefault(r["seed"], []).append(r["stream_tpr"])
    return {s: st.mean(v) for s, v in by_seed.items()}


def paired_bootstrap(a: dict[int, float], b: dict[int, float], reps: int, seed: int):
    """Resample seed blocks with replacement; return the difference a - b."""
    seeds = sorted(set(a) & set(b))
    if len(seeds) != len(a) or len(seeds) != len(b):
        raise SystemExit("detectors do not share an identical seed set")
    d = np.array([a[s] - b[s] for s in seeds])
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(d), size=(reps, len(d)))
    draws = d[idx].mean(axis=1)
    return {
        "n_seeds": len(d),
        "mean_difference": float(d.mean()),
        "ci95_low": float(np.percentile(draws, 2.5)),
        "ci95_high": float(np.percentile(draws, 97.5)),
        "seeds_favouring_reference": int((d > 0).sum()),
        "seeds_tied": int((d == 0).sum()),
        "seeds_favouring_comparator": int((d < 0).sum()),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--metrics", type=Path, required=True)
    p.add_argument("--out", type=Path)
    p.add_argument("--reps", type=int, default=10000)
    p.add_argument("--seed", type=int, default=20260731)
    args = p.parse_args()

    blob = json.loads(args.metrics.read_text())
    per_run = blob["per_run_metrics"]
    families = set(blob["headline_families"])

    ref = pooled_by_seed(per_run, REFERENCE, families)
    detectors = sorted({r["detector"] for r in per_run} - {REFERENCE})

    out = {
        "reference": REFERENCE,
        "partition": blob.get("partition"),
        "families": sorted(families),
        "bootstrap_replicates": args.reps,
        "bootstrap_seed": args.seed,
        "resampling_unit": "RNG seed block (all arms of a seed move together)",
        "reference_pooled_tpr": st.mean(ref.values()),
        "contrasts": {},
    }
    for det in detectors:
        other = pooled_by_seed(per_run, det, families)
        if not other or set(other) != set(ref):
            continue
        res = paired_bootstrap(ref, other, args.reps, args.seed)
        res["comparator_pooled_tpr"] = st.mean(other.values())
        res["excludes_zero"] = not (res["ci95_low"] <= 0.0 <= res["ci95_high"])
        out["contrasts"][det] = res

    text = json.dumps(out, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n")
    print(text)


def _selfcheck() -> None:
    """A rule that is uniformly 0.10 better must give a CI strictly above zero."""
    per_run = []
    for s in range(1, 31):
        for arm in ("a", "b"):
            per_run.append({"detector": "sequential-score", "family": "f", "mode": "claimed",
                            "seed": s, "arm": arm, "stream_tpr": 0.60 + 0.001 * s})
            per_run.append({"detector": "worse", "family": "f", "mode": "claimed",
                            "seed": s, "arm": arm, "stream_tpr": 0.50 + 0.001 * s})
    a = pooled_by_seed(per_run, "sequential-score", {"f"})
    b = pooled_by_seed(per_run, "worse", {"f"})
    r = paired_bootstrap(a, b, 2000, 1)
    assert abs(r["mean_difference"] - 0.10) < 1e-9, r
    assert r["ci95_low"] > 0.0 and r["seeds_favouring_reference"] == 30, r
    # identical rules must straddle zero with zero width
    r0 = paired_bootstrap(a, a, 2000, 1)
    assert r0["mean_difference"] == 0.0 and r0["ci95_low"] == r0["ci95_high"] == 0.0, r0
    print("selfcheck ok")


if __name__ == "__main__":
    import sys
    if "--selfcheck" in sys.argv:
        _selfcheck()
    else:
        main()
