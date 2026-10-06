#!/usr/bin/env python3
"""Plot descriptive pooled-pair ROC/PR curves for matched pure attacks.

Validation and held-out test are deliberately kept separate.  Validation rows
must be the seven ``threshold_selection/validation_<attack>`` arms (excluding
the benign threshold-constraint arm), and test rows must be the seven
``pure_attack/pure_<attack>`` arms.  Each corresponding arm must use the same
vehicle population size and attacker fraction.  This prevents onset, guard,
stress, scaling, timing, or prevalence-control rows from leaking into curves.

The negative class is exactly ``clean_pair``.  Stream-negative impersonated
victim rows are outside this estimand.  AUC and average precision pool eligible
receiver-identity pairs and are descriptive: pairs within a run share an RNG
seed, so the figure deliberately presents no pointwise confidence intervals.

Usage::

    python3 make_roc_figure.py --pairs results/<release>/full/pairs_v6.csv \
        --threshold-json results/<release>/full/analysis/selected_threshold.json \
        --metrics-csv results/<release>/full/analysis/roc_metrics.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402


import figstyle  # noqa: E402
from figstyle import INK, MUTED, RULE, SURFACE  # noqa: E402

# Three series have to stay apart in grayscale as well as colour, so this
# figure keeps its own muted triple rather than the two-colour scheme used by
# the schematic figures.
HOSTILE = "#D55E00"
CLEAN = "#0072B2"
VALID = "#8c8c8c"

# Every panel reserves the same strip above its axes for a legend, so the
# three titles sit on one line however many entries a legend carries.
LEGEND_ANCHOR = (0.0, 1.02)
TITLE_PAD = 34
ATTACK_ORDER = (
    "falsify",
    "revheading",
    "replay",
    "dos",
    "spoof",
    "constoffset",
    "slydos",
)
ATTACK_SET = set(ATTACK_ORDER)
REQUIRED_FIELDS = {
    "mode",
    "stage",
    "family",
    "arm",
    "seed",
    "attack",
    "n",
    "frac",
    "eligible",
    "window_peak_score",
    "malicious_use",
    "clean_pair",
}
METRIC_FIELDS = (
    "stage",
    "metric",
    "value",
    "pair_count",
    "positive_count",
    "negative_count",
    "positive_prevalence",
    "n_vehicles",
    "attacker_fraction",
    "attack_set",
    "aggregation_unit",
    "uncertainty",
    "population",
)


class RocFigureError(ValueError):
    """The input does not support the declared matched-population curves."""


@dataclass(frozen=True)
class Population:
    scores: np.ndarray
    truth: np.ndarray
    n_vehicles: int
    attacker_fraction: float
    attacks: tuple[str, ...]
    mode: str


@dataclass(frozen=True)
class LoadedData:
    populations: dict[str, Population]
    clean_test_scores: np.ndarray
    hostile_test_scores: np.ndarray


def parse_bool(value: object, *, field: str, line: int) -> bool:
    token = str(value).strip().lower()
    if token in {"1", "true", "yes"}:
        return True
    if token in {"0", "false", "no"}:
        return False
    raise RocFigureError(
        f"line {line}: {field} must be an explicit boolean, got {value!r}"
    )


def parse_int(value: object, *, field: str, line: int, minimum: int = 0) -> int:
    try:
        parsed = int(str(value).strip())
    except ValueError as exc:
        raise RocFigureError(f"line {line}: invalid {field} {value!r}") from exc
    if parsed < minimum:
        raise RocFigureError(f"line {line}: {field} must be >= {minimum}")
    return parsed


def parse_float(
    value: object,
    *,
    field: str,
    line: int,
    minimum: float,
    maximum: float,
) -> float:
    try:
        parsed = float(str(value).strip())
    except ValueError as exc:
        raise RocFigureError(f"line {line}: invalid {field} {value!r}") from exc
    if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
        raise RocFigureError(
            f"line {line}: {field} must be finite in [{minimum},{maximum}]"
        )
    return parsed


def curves(scores: np.ndarray, truth: np.ndarray):
    """Return tie-correct ROC/PR points, pooled-pair AUC, and pooled-pair AP.

    Thresholds descend through unique scores and move an entire tied group at
    once.  The returned PR curve uses the conventional recall-zero anchor with
    precision one for plotting; average precision is the right-continuous step
    integral, not trapezoidal interpolation.
    """

    scores = np.asarray(scores, dtype=float)
    truth = np.asarray(truth, dtype=bool)
    if scores.ndim != 1 or truth.ndim != 1 or scores.shape != truth.shape:
        raise RocFigureError("scores and truth must be equal-length 1-D arrays")
    if scores.size == 0 or not np.all(np.isfinite(scores)):
        raise RocFigureError("curve scores must be nonempty and finite")
    positives = int(truth.sum())
    negatives = int((~truth).sum())
    if not positives or not negatives:
        raise RocFigureError("each curve population requires positive and negative pairs")

    order = np.argsort(-scores, kind="mergesort")
    sorted_scores = scores[order]
    sorted_truth = truth[order]
    true_positives = np.cumsum(sorted_truth)
    false_positives = np.cumsum(~sorted_truth)
    # A threshold cannot split equal scores.  Retain the last row in every tied
    # group, after all members of that group have crossed the threshold.
    keep = np.r_[np.diff(sorted_scores) != 0, True]
    true_positives = true_positives[keep]
    false_positives = false_positives[keep]
    true_positive_rate = true_positives / positives
    false_positive_rate = false_positives / negatives
    precision = true_positives / (true_positives + false_positives)
    recall = true_positive_rate
    trapezoid = getattr(np, "trapezoid", None) or np.trapz
    auc = float(
        trapezoid(
            np.r_[0.0, true_positive_rate],
            np.r_[0.0, false_positive_rate],
        )
    )
    average_precision = float(
        np.sum(np.diff(np.r_[0.0, recall]) * precision)
    )
    return (
        np.r_[0.0, false_positive_rate],
        np.r_[0.0, true_positive_rate],
        np.r_[0.0, recall],
        np.r_[1.0, precision],
        auc,
        average_precision,
    )


def load(path: Path) -> LoadedData:
    """Load and validate matched validation/test pure-attack populations."""

    rows: dict[str, list[tuple[float, bool]]] = {"validation": [], "test": []}
    n_by_stage_attack: dict[str, dict[str, set[int]]] = {
        "validation": {attack: set() for attack in ATTACK_ORDER},
        "test": {attack: set() for attack in ATTACK_ORDER},
    }
    frac_by_stage_attack: dict[str, dict[str, set[float]]] = {
        "validation": {attack: set() for attack in ATTACK_ORDER},
        "test": {attack: set() for attack in ATTACK_ORDER},
    }
    attacks_seen: dict[str, set[str]] = {"validation": set(), "test": set()}
    modes: dict[str, set[str]] = {"validation": set(), "test": set()}
    clean_test: list[float] = []
    hostile_test: list[float] = []

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_FIELDS - set(reader.fieldnames or ())
        if missing:
            raise RocFigureError(
                f"{path}: missing required columns: {', '.join(sorted(missing))}"
            )
        for line, row in enumerate(reader, 2):
            stage = row["stage"].strip()
            if stage not in {"validation", "test"}:
                raise RocFigureError(f"line {line}: unknown stage {stage!r}")
            family = row["family"].strip()
            if stage == "validation":
                if family != "threshold_selection" or row["arm"] == "validation_none":
                    continue
            elif family != "pure_attack":
                continue

            attack = row["attack"].strip()
            if attack not in ATTACK_SET:
                raise RocFigureError(
                    f"line {line}: unknown attack in curve population {attack!r}"
                )
            expected_arm = (
                f"validation_{attack}" if stage == "validation" else f"pure_{attack}"
            )
            if row["arm"] != expected_arm:
                raise RocFigureError(
                    f"line {line}: arm {row['arm']!r} does not match {expected_arm!r}"
                )
            eligible = parse_bool(row["eligible"], field="eligible", line=line)
            if not eligible:
                continue
            n_vehicles = parse_int(row["n"], field="n", line=line, minimum=1)
            attacker_fraction = parse_float(
                row["frac"], field="frac", line=line, minimum=0.0, maximum=1.0
            )
            # Seed is not used as an IID unit for these descriptive curves, but
            # validating it prevents malformed rows from silently entering.
            parse_int(row["seed"], field="seed", line=line, minimum=0)
            score = parse_float(
                row["window_peak_score"],
                field="window_peak_score",
                line=line,
                minimum=0.0,
                maximum=1.0,
            )
            hostile = parse_bool(
                row["malicious_use"], field="malicious_use", line=line
            )
            clean = parse_bool(row["clean_pair"], field="clean_pair", line=line)
            if hostile and clean:
                raise RocFigureError(
                    f"line {line}: a pair cannot be both malicious_use and clean_pair"
                )
            # Stream-negative impersonated-victim pairs are neither the
            # positive hostile stream nor a declared clean negative.
            if not hostile and not clean:
                continue

            mode = row["mode"].strip()
            if mode not in {"smoke", "full"}:
                raise RocFigureError(f"line {line}: invalid mode {mode!r}")
            modes[stage].add(mode)
            attacks_seen[stage].add(attack)
            n_by_stage_attack[stage][attack].add(n_vehicles)
            frac_by_stage_attack[stage][attack].add(attacker_fraction)
            rows[stage].append((score, hostile))
            if stage == "test":
                (hostile_test if hostile else clean_test).append(score)

    for stage in ("validation", "test"):
        missing_attacks = ATTACK_SET - attacks_seen[stage]
        extra_attacks = attacks_seen[stage] - ATTACK_SET
        if missing_attacks or extra_attacks:
            raise RocFigureError(
                f"{stage} curve attack set mismatch: missing={sorted(missing_attacks)}, "
                f"extra={sorted(extra_attacks)}"
            )
        if len(modes[stage]) != 1:
            raise RocFigureError(
                f"{stage} curve must contain exactly one mode, got {sorted(modes[stage])}"
            )
        truth = np.array([truth_value for _, truth_value in rows[stage]], dtype=bool)
        if not truth.any() or truth.all():
            raise RocFigureError(
                f"{stage} curve requires both malicious_use positives and clean_pair negatives"
            )

    if modes["validation"] != modes["test"]:
        raise RocFigureError(
            "validation/test mode mismatch: "
            f"{sorted(modes['validation'])} versus {sorted(modes['test'])}"
        )
    for attack in ATTACK_ORDER:
        validation_n = n_by_stage_attack["validation"][attack]
        test_n = n_by_stage_attack["test"][attack]
        if len(validation_n) != 1 or len(test_n) != 1 or validation_n != test_n:
            raise RocFigureError(
                f"validation/test N mismatch for {attack}: "
                f"{sorted(validation_n)} versus {sorted(test_n)}"
            )
        validation_fraction = frac_by_stage_attack["validation"][attack]
        test_fraction = frac_by_stage_attack["test"][attack]
        if (
            len(validation_fraction) != 1
            or len(test_fraction) != 1
            or validation_fraction != test_fraction
        ):
            raise RocFigureError(
                f"validation/test attacker-fraction mismatch for {attack}: "
                f"{sorted(validation_fraction)} versus {sorted(test_fraction)}"
            )

    stage_population: dict[str, Population] = {}
    for stage in ("validation", "test"):
        scores = np.array([score for score, _ in rows[stage]], dtype=float)
        truth = np.array([truth_value for _, truth_value in rows[stage]], dtype=bool)
        # The equality checks above make these singletons common to all arms.
        n_values = {next(iter(n_by_stage_attack[stage][attack])) for attack in ATTACK_ORDER}
        fractions = {
            next(iter(frac_by_stage_attack[stage][attack])) for attack in ATTACK_ORDER
        }
        if len(n_values) != 1 or len(fractions) != 1:
            raise RocFigureError(
                f"{stage} pure-attack arms do not share one N/fraction population"
            )
        stage_population[stage] = Population(
            scores=scores,
            truth=truth,
            n_vehicles=next(iter(n_values)),
            attacker_fraction=next(iter(fractions)),
            attacks=ATTACK_ORDER,
            mode=next(iter(modes[stage])),
        )
    return LoadedData(
        populations=stage_population,
        clean_test_scores=np.array(clean_test, dtype=float),
        hostile_test_scores=np.array(hostile_test, dtype=float),
    )


def read_threshold(path: Path | None) -> float | None:
    if path is None:
        return None
    if not path.is_file():
        raise RocFigureError(f"threshold JSON not found: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        threshold = float(document["threshold"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise RocFigureError(f"invalid threshold JSON {path}: {exc}") from exc
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise RocFigureError("frozen threshold must be finite in [0,1]")
    return threshold


def metrics_rows(data: LoadedData) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for stage in ("validation", "test"):
        population = data.populations[stage]
        result = curves(population.scores, population.truth)
        positives = int(population.truth.sum())
        negatives = int((~population.truth).sum())
        common = {
            "stage": stage,
            "pair_count": population.scores.size,
            "positive_count": positives,
            "negative_count": negatives,
            "positive_prevalence": f"{positives / population.scores.size:.12g}",
            "n_vehicles": population.n_vehicles,
            "attacker_fraction": f"{population.attacker_fraction:.12g}",
            "attack_set": "|".join(population.attacks),
            "aggregation_unit": "eligible receiver-identity pair (pooled)",
            "uncertainty": "descriptive; no pointwise confidence intervals",
            "population": (
                "validation threshold_selection attack arms"
                if stage == "validation"
                else "held-out test pure_attack arms"
            ),
        }
        for metric, value in (("roc_auc", result[4]), ("average_precision", result[5])):
            output.append({**common, "metric": metric, "value": f"{value:.12g}"})
    return output


def write_metrics(path: Path, rows: Sequence[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=METRIC_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def render(data: LoadedData, *, threshold: float | None, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    results = {
        stage: curves(population.scores, population.truth)
        for stage, population in data.populations.items()
    }
    figstyle.apply()
    fig, axes = plt.subplots(1, 3, figsize=(figstyle.WDOC, 3.40))

    axis = axes[0]
    # Validation and test very nearly coincide (AUC 0.8767 vs 0.8771), so a
    # solid grey line under a solid colour one is invisible and its legend key
    # points at nothing the reader can find. The wider dashed grey reads as a
    # separate curve that happens to track the other closely, which is the
    # honest picture.
    for stage, colour, lw, dash in (("validation", VALID, 2.4, (0, (4, 2))),
                                    ("test", HOSTILE, 1.3, None)):
        fpr, tpr, _, _, auc, _ = results[stage]
        axis.plot(
            fpr,
            tpr,
            color=colour,
            lw=lw,
            ls=dash if dash else "-",
            label=f"{stage} (pooled-pair AUC {auc:.3f})",
            zorder=2 if dash else 3,
        )
    axis.plot([0, 1], [0, 1], color=RULE, lw=0.8, ls=(0, (3, 2)), zorder=1)
    if threshold is not None:
        population = data.populations["test"]
        predictions = population.scores > threshold
        op_fpr = float(
            (predictions & ~population.truth).sum() / (~population.truth).sum()
        )
        op_tpr = float((predictions & population.truth).sum() / population.truth.sum())
        axis.plot(
            [op_fpr],
            [op_tpr],
            marker="o",
            ms=5,
            color=INK,
            zorder=4,
            label=f"frozen $\\tau$={threshold:.3f}",
        )
    axis.set_xlabel("Clean-pair false-positive rate", fontsize=7.2, color=INK)
    axis.set_ylabel("Hostile-pair true-positive rate", fontsize=7.2, color=INK)
    axis.set_title(
        "A  Descriptive pooled-pair ROC", fontsize=7.4, loc="left", pad=TITLE_PAD
    )
    axis.legend(
        fontsize=6.2,
        frameon=False,
        loc="lower left",
        bbox_to_anchor=LEGEND_ANCHOR,
        labelcolor=INK,
        handlelength=1.6,
        borderpad=0.0,
        labelspacing=0.3,
    )

    axis = axes[1]
    for stage, colour, lw, dash in (("validation", VALID, 2.4, (0, (4, 2))),
                                    ("test", HOSTILE, 1.3, None)):
        _, _, recall, precision, _, average_precision = results[stage]
        axis.plot(
            recall,
            precision,
            color=colour,
            lw=lw,
            ls=dash if dash else "-",
            label=f"{stage} (pooled-pair AP {average_precision:.3f})",
            zorder=2 if dash else 3,
        )
    test_truth = data.populations["test"].truth
    prevalence = float(test_truth.mean())
    axis.axhline(prevalence, color=RULE, lw=0.8, ls=(0, (3, 2)), zorder=1)
    axis.text(0.02, prevalence + 0.02, "test prevalence", fontsize=6.0, color=MUTED)
    axis.set_xlabel("Recall", fontsize=7.5, color=INK)
    axis.set_ylabel("Precision", fontsize=7.5, color=INK)
    axis.set_title(
        "B  Descriptive pooled-pair PR", fontsize=7.4, loc="left", pad=TITLE_PAD
    )
    axis.legend(
        fontsize=6.2,
        frameon=False,
        loc="lower left",
        bbox_to_anchor=LEGEND_ANCHOR,
        labelcolor=INK,
        handlelength=1.6,
        borderpad=0.0,
        labelspacing=0.3,
    )

    axis = axes[2]
    bins = np.linspace(0, 1, 60)
    for values, colour, label in (
        # Prose labels, not the CSV column names the classes are read from.
        (data.clean_test_scores, CLEAN, "clean pair"),
        (data.hostile_test_scores, HOSTILE, "hostile pair"),
    ):
        axis.hist(values, bins=bins, color=colour, alpha=0.65, label=label, log=True)
    if threshold is not None:
        # Both marks are named in the legend rather than labelled in place:
        # an in-plot rotated label here collides with the panel title.
        axis.axvline(
            threshold,
            color=INK,
            lw=1.0,
            zorder=3,
            label=f"frozen $\\tau$={threshold:.3f}",
        )
        worst = float(data.clean_test_scores.max())
        axis.axvline(
            worst,
            color=CLEAN,
            lw=1.0,
            ls=(0, (2, 2)),
            zorder=3,
            label="max clean score",
        )
        print(
            f"max clean-pair score {worst:.4f}, margin below tau "
            f"{threshold - worst:+.4f}"
        )
    axis.set_xlabel("Window peak score", fontsize=7.5, color=INK)
    axis.set_ylabel("Eligible pairs (log)", fontsize=7.5, color=INK)
    axis.set_title(
        "C  Held-out score separation", fontsize=7.4, loc="left", pad=TITLE_PAD
    )
    axis.legend(
        fontsize=5.9,
        frameon=False,
        loc="lower left",
        bbox_to_anchor=LEGEND_ANCHOR,
        labelcolor=INK,
        handlelength=1.3,
        borderpad=0.0,
        labelspacing=0.25,
        ncol=2,
        columnspacing=0.6,
        handletextpad=0.35,
    )
    axis.legend(
        fontsize=6.2,
        frameon=False,
        loc="lower left",
        bbox_to_anchor=LEGEND_ANCHOR,
        labelcolor=INK,
        handlelength=1.6,
        borderpad=0.0,
        labelspacing=0.3,
        ncol=2,
        columnspacing=1.0,
    )

    for axis in axes:
        axis.tick_params(labelsize=6.4, colors=MUTED)
        for spine in ("top", "right"):
            axis.spines[spine].set_visible(False)
        for spine in ("left", "bottom"):
            axis.spines[spine].set_color(RULE)
    # Population, pooling and "descriptive, no pointwise CIs" belong to the
    # LaTeX caption, not inside the artwork.
    fig.tight_layout()
    figstyle.assert_no_text_overlap(fig)
    for extension in ("pdf", "png"):
        fig.savefig(out_dir / f"fig_roc.{extension}", dpi=400, facecolor=SURFACE)
    plt.close(fig)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--pairs", type=Path, required=True)
    parser.add_argument("--threshold-json", type=Path)
    parser.add_argument("--metrics-csv", type=Path)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "figures")
    args = parser.parse_args(argv)
    if not args.pairs.is_file():
        raise SystemExit(f"error: {args.pairs} not found; run the sweep first")
    try:
        threshold = read_threshold(args.threshold_json)
        data = load(args.pairs)
        rows = metrics_rows(data)
        render(data, threshold=threshold, out_dir=args.out)
        if args.metrics_csv is not None:
            write_metrics(args.metrics_csv, rows)
    except (OSError, RocFigureError) as exc:
        raise SystemExit(f"error: {exc}") from exc

    print(f"wrote {args.out}/fig_roc.pdf")
    if args.metrics_csv is not None:
        print(f"wrote {args.metrics_csv}")
    indexed = {(row["stage"], row["metric"]): row for row in rows}
    for stage in ("validation", "test"):
        auc = indexed[(stage, "roc_auc")]
        average_precision = indexed[(stage, "average_precision")]
        print(
            f"{stage:11} pooled-pair AUC={float(auc['value']):.4f}  "
            f"AP={float(average_precision['value']):.4f}  "
            f"n={auc['pair_count']}  prevalence={float(auc['positive_prevalence']):.4f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
