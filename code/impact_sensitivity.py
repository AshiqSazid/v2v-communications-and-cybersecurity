#!/usr/bin/env python3
"""Does the DREAD impact term actually change the alert ordering, and is that
ordering stable if the weights are wrong?

The priority index is Q = S x I(c). S is measured; I(c) is an ordinal expert
judgement with one rater. A reviewer is right to ask whether conclusions
survive plausible changes to I. This script answers two separate questions and
refuses to conflate them:

  1. CONTRIBUTION. How often does ranking by Q disagree with ranking by S
     alone? If they never disagree, the impact term is decorative and the paper
     should say so.

  2. STABILITY. Under perturbed or reordered weights, does the Q-ranking hold?
     Reported as Kendall tau against the reference ranking. High tau under
     perturbation means the conclusions do not rest on the exact magnitudes.

Both are computed only among alerts in the held-out pure-attack family: $Q$ is
an alert-priority index and has no operational ranking role for trusted pairs.
Intervals resample RNG-seed blocks because pairs within a seed are not
independent.

Usage:
    python3 impact_sensitivity.py --pairs results/<release>/full/pairs_v4.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path

# Reference weights, mirroring g_dread[] in the simulator. Keep in sync.
REFERENCE = {
    "spoofing": 0.73,
    "tampering": 0.6775,
    "repudiation": 0.565,
    "info_disclosure": 0.52,
    "denial_of_service": 0.74,
    "elevation_of_privilege": 0.54,
    "none": 0.0,
}

# Alternative weightings. Each asks a different "what if the elicitation was
# wrong" question, and they are deliberately not all small perturbations.
VARIANTS = {
    # Every class equally severe: isolates whether ANY differentiation matters.
    "uniform": {k: (0.0 if k == "none" else 0.65) for k in REFERENCE},
    # Severity order reversed: the adversarial case for an ordinal claim.
    "reversed": {
        "spoofing": 0.56,
        "tampering": 0.62,
        "repudiation": 0.72,
        "info_disclosure": 0.66,
        "denial_of_service": 0.54,
        "elevation_of_privilege": 0.74,
        "none": 0.0,
    },
    # Spread the scale out: same order, larger gaps.
    "stretched": {
        "spoofing": 0.85,
        "tampering": 0.70,
        "repudiation": 0.40,
        "info_disclosure": 0.30,
        "denial_of_service": 0.95,
        "elevation_of_privilege": 0.35,
        "none": 0.0,
    },
    # Compress toward the mean: same order, nearly no gaps.
    "compressed": {
        "spoofing": 0.66,
        "tampering": 0.65,
        "repudiation": 0.63,
        "info_disclosure": 0.62,
        "denial_of_service": 0.67,
        "elevation_of_privilege": 0.62,
        "none": 0.0,
    },
}


def kendall_tau(pairs: list[tuple[float, float]]) -> float:
    """Kendall tau-b over sampled pairs of (a, b) values.

    Implemented directly rather than via SciPy so the sampling and tie handling
    are visible: the caller passes an already-sampled subset because the full
    O(n^2) comparison over a million pairs is not worth its runtime.
    """
    con = dis = ta = tb = 0
    n = len(pairs)
    for i in range(n):
        ai, bi = pairs[i]
        for j in range(i + 1, n):
            aj, bj = pairs[j]
            da, db = ai - aj, bi - bj
            if da == 0 and db == 0:
                continue
            if da == 0:
                ta += 1
            elif db == 0:
                tb += 1
            elif (da > 0) == (db > 0):
                con += 1
            else:
                dis += 1
    denom = math.sqrt((con + dis + ta) * (con + dis + tb))
    return (con - dis) / denom if denom else math.nan


def load(path: Path) -> dict[str, list[tuple[float, str]]]:
    """seed -> alerted [(score, class)] in the held-out pure-attack family."""
    by_seed: dict[str, list[tuple[float, str]]] = defaultdict(list)
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("stage") != "test" or row.get("family") != "pure_attack":
                continue
            if row.get("eligible") not in ("1", "true", "True"):
                continue
            if row.get("trust_decision", "").lower() != "compromised":
                continue
            stride_class = row.get("stride_class", "none")
            try:
                score = float(row["window_peak_score"])
            except (KeyError, ValueError):
                continue
            by_seed[row.get("seed", "")].append(
                (score, stride_class)
            )
    return by_seed


def bootstrap_mean(values: list[float], rng: random.Random,
                   replicates: int = 2000) -> tuple[float, float, float]:
    """Mean and percentile interval with RNG seed as the resampling unit."""
    clean = [v for v in values if math.isfinite(v)]
    if not clean:
        return math.nan, math.nan, math.nan
    point = sum(clean) / len(clean)
    draws = sorted(
        sum(rng.choice(clean) for _ in clean) / len(clean)
        for _ in range(replicates)
    )
    lo = draws[int(0.025 * replicates)]
    hi = draws[min(replicates - 1, int(0.975 * replicates))]
    return point, lo, hi


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pairs", type=Path, required=True)
    ap.add_argument("--sample", type=int, default=500,
                    help="alerts sampled per seed for O(n^2) comparisons (default 500)")
    ap.add_argument("--seed", type=int, default=20260802)
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    if not args.pairs.exists():
        print(f"error: {args.pairs} not found. Run the full sweep first.",
              file=sys.stderr)
        return 2

    by_seed = load(args.pairs)
    if not by_seed:
        print("error: no eligible test pairs parsed", file=sys.stderr)
        return 2

    rng = random.Random(args.seed)
    results: dict[str, dict[str, float]] = {}
    sampled = {
        seed: (rows if len(rows) <= args.sample else rng.sample(rows, args.sample))
        for seed, rows in by_seed.items()
    }

    # --- 1. contribution: does Q ever reorder against S alone? -------------
    disc_per_seed = []
    for sample in sampled.values():
        disc = tot = 0
        for i in range(len(sample)):
            si, ci = sample[i]
            qi = si * REFERENCE.get(ci, 0.0)
            for j in range(i + 1, len(sample)):
                sj, cj = sample[j]
                qj = sj * REFERENCE.get(cj, 0.0)
                if si == sj or qi == qj:
                    continue
                tot += 1
                if (si > sj) != (qi > qj):
                    disc += 1
        if tot:
            disc_per_seed.append(disc / tot)
    mean_disc, disc_lo, disc_hi = bootstrap_mean(disc_per_seed, rng)
    results["discordance_vs_score"] = {
        "mean": mean_disc,
        "ci95_low": disc_lo,
        "ci95_high": disc_hi,
        "seeds": len(disc_per_seed),
        "alerts": sum(len(rows) for rows in by_seed.values()),
        "note": (
            "fraction of alert comparisons where Q and S disagree on order; "
            "held-out pure-attack family only"
        ),
    }

    # --- 2. stability: tau of Q under alternative weights ------------------
    for name, weights in VARIANTS.items():
        taus = []
        for sample in sampled.values():
            pts = [
                (s * REFERENCE.get(c, 0.0), s * weights.get(c, 0.0))
                for s, c in sample
            ]
            tau = kendall_tau(pts)
            if not math.isnan(tau):
                taus.append(tau)
        mean_tau, tau_lo, tau_hi = bootstrap_mean(taus, rng)
        results[f"tau_{name}"] = {
            "mean": mean_tau,
            "ci95_low": tau_lo,
            "ci95_high": tau_hi,
            "min": min(taus) if taus else math.nan,
            "seeds": len(taus),
        }

    print(f"pairs file : {args.pairs}")
    print(f"population : held-out pure-attack alerts only")
    print(f"alerts     : {sum(len(rows) for rows in by_seed.values())}")
    print(f"seeds      : {len(by_seed)}   max sampled/seed: {args.sample}")
    print()
    print(f"Q vs S discordance      : {mean_disc:.4f} "
          f"[{disc_lo:.4f}, {disc_hi:.4f}] "
          f"({mean_disc * 100:.2f}% of comparisons reordered by impact)")
    print()
    print("Kendall tau of Q-ranking under alternative impact weights")
    print("  (1.0 = ranking unchanged; low = conclusions depend on the weights)")
    for name in VARIANTS:
        r = results[f"tau_{name}"]
        print(f"  {name:12} tau = {r['mean']:.4f} "
              f"[{r['ci95_low']:.4f}, {r['ci95_high']:.4f}]"
              f"   worst seed = {r['min']:.4f}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(results, indent=2, sort_keys=True))
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
