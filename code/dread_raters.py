#!/usr/bin/env python3
"""Inter-rater agreement for the DREAD impact scores.

The manuscript's impact weights are one person's ordinal judgements, which is
the weakest link in the prioritisation claim. This computes the statistics a
reviewer asks for once more than one person has scored the same register:
Kendall's W over the rank orderings, pairwise Spearman, and the spread of the
resulting normalised impact weight I_c per STRIDE class.

It does NOT invent raters. ``dread_ratings.csv`` ships with the manuscript's
existing scores in the ``rater1`` columns and nothing else; add ``rater2`` ...
``raterN`` column groups with other people's scores and re-run.

    python3 dread_raters.py --ratings dread_ratings.csv --out dread_agreement.json
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import math
import statistics as st
from pathlib import Path

SUBSCORES = ("D", "R", "E", "A", "Ds")


def load(path):
    """-> {rater: {stride_class: {subscore: value}}}"""
    out: dict[str, dict[str, dict[str, float]]] = {}
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            cls = row["stride_class"].strip()
            for key, value in row.items():
                if key == "stride_class" or value is None or value.strip() == "":
                    continue
                rater, _, sub = key.partition("_")
                if sub not in SUBSCORES:
                    continue
                out.setdefault(rater, {}).setdefault(cls, {})[sub] = float(value)
    return out


def impact(scores):
    """Normalised ordinal impact weight, the manuscript's I_c."""
    return st.fmean(scores[s] for s in SUBSCORES) / 10.0


def ranks(values):
    """Average ranks, ties shared."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        shared = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            out[order[k]] = shared
        i = j + 1
    return out


def kendall_w(rank_rows):
    """Kendall's coefficient of concordance over m raters and n items."""
    m, n = len(rank_rows), len(rank_rows[0])
    if m < 2:
        return None
    totals = [sum(row[i] for row in rank_rows) for i in range(n)]
    mean_total = st.fmean(totals)
    s = sum((t - mean_total) ** 2 for t in totals)
    denom = m * m * (n ** 3 - n)
    return 12.0 * s / denom if denom else None


def spearman(a, b):
    ra, rb = ranks(a), ranks(b)
    n = len(a)
    d2 = sum((x - y) ** 2 for x, y in zip(ra, rb))
    return 1.0 - 6.0 * d2 / (n * (n * n - 1)) if n > 2 else None


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--ratings", type=Path, required=True)
    p.add_argument("--out", type=Path)
    args = p.parse_args()

    data = load(args.ratings)
    raters = sorted(data)
    classes = sorted({c for r in data.values() for c in r})
    weights = {r: [impact(data[r][c]) for c in classes] for r in raters}

    report = {
        "raters": raters,
        "stride_classes": classes,
        "impact_weights": {r: dict(zip(classes, weights[r])) for r in raters},
    }
    if len(raters) < 2:
        report["status"] = (
            f"only {len(raters)} rater present; Kendall's W needs at least two. "
            "Add rater2_D ... rater2_Ds columns and re-run."
        )
        print(report["status"])
    else:
        rank_rows = [ranks(weights[r]) for r in raters]
        report["kendall_w"] = kendall_w(rank_rows)
        report["pairwise_spearman"] = {
            f"{a}|{b}": spearman(weights[a], weights[b])
            for a, b in itertools.combinations(raters, 2)
        }
        report["weight_spread"] = {
            c: {"min": min(weights[r][i] for r in raters),
                "max": max(weights[r][i] for r in raters),
                "sd": st.pstdev([weights[r][i] for r in raters])}
            for i, c in enumerate(classes)
        }
        print(f"raters: {len(raters)}   Kendall's W = {report['kendall_w']:.4f}")
        for pair, rho in report["pairwise_spearman"].items():
            print(f"  Spearman {pair}: {rho:+.4f}")

    if args.out:
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def _demo() -> None:
    """Self-check: identical raters concord perfectly, reversed raters do not."""
    same = [[1.0, 2.0, 3.0, 4.0], [1.0, 2.0, 3.0, 4.0]]
    assert abs(kendall_w([ranks(r) for r in same]) - 1.0) < 1e-9
    opposed = [[1.0, 2.0, 3.0, 4.0], [4.0, 3.0, 2.0, 1.0]]
    assert kendall_w([ranks(r) for r in opposed]) < 1e-9
    assert abs(spearman([1, 2, 3, 4], [4, 3, 2, 1]) + 1.0) < 1e-9
    print("dread_raters self-check passed")


if __name__ == "__main__":
    import sys
    if "--selfcheck" in sys.argv:
        _demo()
    else:
        main()
