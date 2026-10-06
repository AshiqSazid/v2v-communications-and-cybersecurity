#!/usr/bin/env python3
"""Contingency table of simulated attack type against assigned STRIDE class.

    python3 attribution_matrix.py --pairs results/v9/full/pairs_v4.csv \
        --out-csv results/v9/full/analysis/attribution_matrix.csv \
        --out-tex results/v9/full/analysis/attribution_matrix.tex

Reviewer point 4 asks for "a confusion matrix between simulated attack type and
assigned threat class". The simulated attack type IS known exactly -- it is the
generator's arm -- so the table is computable and is produced here.

What this is NOT: an accuracy measurement. There is no external ground truth
mapping an attack to a single "correct" STRIDE class, because STRIDE classes
describe consequence, not mechanism, and several attacks legitimately evidence
more than one. The table is therefore reported as a CONTINGENCY table showing
which consequence class the evidence lands in per attack, and no diagonal is
privileged, no accuracy/precision/recall is derived, and no cell is called an
error.

Rows are restricted to alerting hostile-stream pairs, because attribution is
only emitted for a raised alert; the denominator per row is printed so the
table is self-contained.
"""
import argparse
import collections
import csv
import sys
from pathlib import Path

# Presentation order: mechanism-similar attacks adjacent, silent ones last.
ARM_LABEL = {
    "pure_falsify": "Position falsification",
    "pure_revheading": "Reversed heading",
    "pure_dos": "Flooding",
    "pure_replay": "Replay",
    "pure_spoof": "Identity spoofing",
    "pure_constoffset": "Constant offset",
    "pure_slydos": "Rate-limited flooding",
}
CLASS_ORDER = ["spoofing", "tampering", "repudiation", "information_disclosure",
               "denial_of_service", "elevation_of_privilege", "none"]
CLASS_SHORT = {"spoofing": "S", "tampering": "T", "repudiation": "R",
               "information_disclosure": "I", "denial_of_service": "D",
               "elevation_of_privilege": "E", "none": "--"}


def load(pairs_path, arms):
    """-> {arm: Counter(stride_class)}, {arm: n_alerting}, {arm: n_ambiguous}"""
    counts = collections.defaultdict(collections.Counter)
    alerting = collections.Counter()
    ambiguous = collections.Counter()
    seen_classes = set()
    csv.field_size_limit(10 ** 8)
    with open(pairs_path, newline="") as fh:
        for row in csv.DictReader(fh):
            arm = row.get("arm")
            if arm not in arms:
                continue
            # attribution exists only where an alert was raised on a hostile stream
            if row.get("window_alert") not in ("1", "true", "True"):
                continue
            cls = (row.get("stride_class") or "none").strip() or "none"
            seen_classes.add(cls)
            counts[arm][cls] += 1
            alerting[arm] += 1
            if row.get("stride_ambiguous") in ("1", "true", "True"):
                ambiguous[arm] += 1
    return counts, alerting, ambiguous, seen_classes


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pairs", type=Path, required=True)
    ap.add_argument("--out-csv", type=Path)
    ap.add_argument("--out-tex", type=Path)
    args = ap.parse_args()

    counts, alerting, ambiguous, seen = load(args.pairs, set(ARM_LABEL))
    if not alerting:
        sys.exit(f"error: no alerting pairs found in {args.pairs} for the "
                 f"pure-attack arms; nothing to tabulate")

    classes = [c for c in CLASS_ORDER if c in seen] + \
              sorted(seen.difference(CLASS_ORDER))

    # ---- console ----
    w = max(len(v) for v in ARM_LABEL.values()) + 1
    print(f"{'attack':<{w}}{'n':>7}  " +
          "".join(f"{CLASS_SHORT.get(c, c[:3]):>7}" for c in classes) + "   ambig")
    for arm, label in ARM_LABEL.items():
        n = alerting.get(arm, 0)
        if not n:
            print(f"{label:<{w}}{0:>7}   (no alerting pairs)")
            continue
        cells = "".join(f"{counts[arm][c] / n:>7.3f}" for c in classes)
        print(f"{label:<{w}}{n:>7}  {cells}   {ambiguous[arm] / n:>5.3f}")

    # ---- csv ----
    if args.out_csv:
        args.out_csv.parent.mkdir(parents=True, exist_ok=True)
        with args.out_csv.open("w", newline="") as fh:
            wr = csv.writer(fh)
            wr.writerow(["attack", "alerting_pairs"] +
                        [f"share_{c}" for c in classes] +
                        [f"count_{c}" for c in classes] + ["ambiguous_share"])
            for arm, label in ARM_LABEL.items():
                n = alerting.get(arm, 0)
                if not n:
                    continue
                wr.writerow([label, n] +
                            [f"{counts[arm][c] / n:.6f}" for c in classes] +
                            [counts[arm][c] for c in classes] +
                            [f"{ambiguous[arm] / n:.6f}"])
        print(f"\nwrote {args.out_csv}")

    # ---- latex ----
    if args.out_tex:
        args.out_tex.parent.mkdir(parents=True, exist_ok=True)
        hdr = " & ".join(CLASS_SHORT.get(c, c[:3]) for c in classes)
        lines = [
            "% generated by attribution_matrix.py -- do not edit by hand",
            "\\begin{table}[t]",
            "\\caption{Contingency table of simulated attack type against assigned "
            "STRIDE class, held-out test partition. Rows are alerting hostile-stream "
            "pairs; $n$ is the row denominator and cells are row shares, so each row "
            "sums to one. S/T/R/I/D/E are the six STRIDE classes and ``--'' is "
            "\\emph{none} (no check fired at the peak). \\textbf{This is not an "
            "accuracy measurement}: no external ground truth assigns one correct "
            "consequence class to an attack, so no diagonal is privileged and no "
            "cell is an error. ``Ambig.'' is the share whose second-best class lay "
            "within $0.5$ log-evidence units of the best.}",
            "\\label{tab:attribmatrix}",
            "\\centering",
            "\\footnotesize",
            "\\setlength{\\tabcolsep}{3pt}",
            "\\begin{tabular}{@{}L{0.30\\columnwidth}r" + "c" * len(classes) + "c@{}}",
            "\\toprule",
            f"Attack & $n$ & {hdr} & Ambig. \\\\",
            "\\midrule",
        ]
        for arm, label in ARM_LABEL.items():
            n = alerting.get(arm, 0)
            if not n:
                lines.append(f"{label} & 0 & " +
                             " & ".join(["---"] * len(classes)) + " & --- \\\\")
                continue
            cells = " & ".join(f"{counts[arm][c] / n:.3f}" for c in classes)
            lines.append(f"{label} & {n} & {cells} & {ambiguous[arm] / n:.3f} \\\\")
        lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
        args.out_tex.write_text("\n".join(lines) + "\n")
        print(f"wrote {args.out_tex}")


if __name__ == "__main__":
    main()
