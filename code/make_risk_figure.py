#!/usr/bin/env python3
"""Render held-out risk-layer results from the pure-attack test population.

Usage::

    python3 make_risk_figure.py --pairs results/<release>/full/pairs_v6.csv

``Q = S_peak * Impact`` is an ordinal ranking index and is defined here only
for pairs that crossed the frozen detector threshold.  Likewise, STRIDE tags
are summarized only among alerted hostile pairs.  Clean negatives are exactly
rows declared ``clean_pair``; stream-negative impersonated-victim rows are not
silently counted as clean false alarms.

All intervals resample independent RNG-seed blocks.  For a ratio, each draw
recomputes the ratio of the resampled seed-block totals.  A seed with no alert
remains in the resampling frame with a zero denominator.  Thus a missing clean
Q estimate is reported as ``NA (no alerted clean pairs)``, never as zero or
``nan``.  STRIDE shares are internal, detector-assigned evidence tags rather
than agreement with external ground truth.
"""

from __future__ import annotations

import argparse
import csv
import math
import random
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402


import figstyle  # noqa: E402
from figstyle import INK, MUTED, RULE, SURFACE  # noqa: E402

CLEAN, HOSTILE = "#8c8c8c", "#D55E00"

# Each panel reserves the same strip above its axes for its legend, so the
# three titles sit on one line and no legend covers plotted data.
LEGEND_ANCHOR = (0.0, 1.02)
TITLE_PAD = 34
# Ordinal priority bands drawn as reference lines in panel A.
BANDS = ((0.30, "low"), (0.60, "med"))
STRIDE_ORDER = (
    "tampering",
    "repudiation",
    "denial_of_service",
    "spoofing",
    "none",
)
STRIDE_COLOUR = {
    "tampering": "#D55E00",
    "repudiation": "#0072B2",
    "denial_of_service": "#8a5cd6",
    "spoofing": "#009E73",
    "none": "#d0cfcb",
}
ATTACKS = (
    ("falsify", "Falsify"),
    ("revheading", "Rev. heading"),
    ("replay", "Replay"),
    ("dos", "Flooding"),
    ("spoof", "Spoofing"),
    ("constoffset", "Const. offset"),
    ("slydos", "Sly DoS"),
)
ATTACK_NAMES = {attack for attack, _ in ATTACKS}
REQUIRED_FIELDS = {
    "stage",
    "family",
    "arm",
    "seed",
    "attack",
    "eligible",
    "malicious_use",
    "clean_pair",
    "trust_decision",
    "priority_index",
    "stride_class",
    "stride_ambiguous",
}
CSV_FIELDS = (
    "attack",
    "metric",
    "stratum",
    "mean",
    "ci95_low",
    "ci95_high",
    "numerator",
    "denominator",
    "pair_count",
    "seed_count",
    "bootstrap_valid_replicates",
    "status",
    "ci_unit",
    "ci_method",
    "population",
)
POPULATION = "stage=test; family=pure_attack; eligible; hostile or clean_pair"


class RiskFigureError(ValueError):
    """The pair table cannot support the declared risk estimand."""


@dataclass(frozen=True)
class Interval:
    point: float | None
    low: float | None
    high: float | None
    valid_replicates: int


@dataclass
class RiskData:
    # (attack, seed, hostile) -> [priority sum, alerted-pair count]
    priority: dict[tuple[str, int, bool], list[float]]
    # (attack, seed, stride class) -> alerted-hostile-pair count
    stride: dict[tuple[str, int, str], int]
    # (attack, seed) -> [ambiguous attributed alerts, attributed alerts]
    ambiguous: dict[tuple[str, int], list[int]]
    # (attack, seed) -> [TP, FN, FP, TN], where negatives are clean_pair only
    confusion: dict[tuple[str, int], list[int]]

    def attacks(self) -> list[tuple[str, str]]:
        present = {attack for attack, _ in self.confusion}
        return [(attack, label) for attack, label in ATTACKS if attack in present]

    def seeds(self, attack: str) -> list[int]:
        return sorted(seed for candidate, seed in self.confusion if candidate == attack)


def parse_bool(value: object, *, field: str, line: int) -> bool:
    token = str(value).strip().lower()
    if token in {"1", "true", "yes"}:
        return True
    if token in {"0", "false", "no"}:
        return False
    raise RiskFigureError(
        f"line {line}: {field} must be an explicit boolean, got {value!r}"
    )


def parse_seed(value: object, *, line: int) -> int:
    try:
        seed = int(str(value).strip())
    except ValueError as exc:
        raise RiskFigureError(f"line {line}: invalid seed {value!r}") from exc
    if seed < 0:
        raise RiskFigureError(f"line {line}: seed must be nonnegative")
    return seed


def parse_priority(value: object, *, line: int) -> float:
    try:
        priority = float(str(value).strip())
    except ValueError as exc:
        raise RiskFigureError(
            f"line {line}: invalid alerted priority_index {value!r}"
        ) from exc
    if not math.isfinite(priority) or not 0.0 <= priority <= 1.0:
        raise RiskFigureError(
            f"line {line}: alerted priority_index must be finite in [0,1]"
        )
    return priority


def load(path: Path) -> RiskData:
    """Strictly load eligible held-out pure-attack rows.

    Rows from onset, guard, stress, scaling, and other control families are
    excluded before aggregation.  Relevant malformed rows raise rather than
    disappearing from the estimand through a permissive ``continue``.
    """

    priority: defaultdict[tuple[str, int, bool], list[float]] = defaultdict(
        lambda: [0.0, 0.0]
    )
    stride: defaultdict[tuple[str, int, str], int] = defaultdict(int)
    ambiguous: defaultdict[tuple[str, int], list[int]] = defaultdict(
        lambda: [0, 0]
    )
    confusion: defaultdict[tuple[str, int], list[int]] = defaultdict(
        lambda: [0, 0, 0, 0]
    )

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_FIELDS - set(reader.fieldnames or ())
        if missing:
            raise RiskFigureError(
                f"{path}: missing required columns: {', '.join(sorted(missing))}"
            )
        for line, row in enumerate(reader, 2):
            if row["stage"] != "test" or row["family"] != "pure_attack":
                continue
            attack = row["attack"].strip()
            if attack not in ATTACK_NAMES:
                raise RiskFigureError(
                    f"line {line}: unknown pure-attack label {attack!r}"
                )
            if row["arm"] != f"pure_{attack}":
                raise RiskFigureError(
                    f"line {line}: arm {row['arm']!r} does not match attack {attack!r}"
                )
            eligible = parse_bool(row["eligible"], field="eligible", line=line)
            if not eligible:
                continue
            hostile = parse_bool(
                row["malicious_use"], field="malicious_use", line=line
            )
            clean = parse_bool(row["clean_pair"], field="clean_pair", line=line)
            if hostile and clean:
                raise RiskFigureError(
                    f"line {line}: a pair cannot be both malicious_use and clean_pair"
                )
            # Impersonated-victim streams can be neither.  They are valid but
            # outside both the hostile and clean-negative strata in this plot.
            if not hostile and not clean:
                continue
            seed = parse_seed(row["seed"], line=line)
            decision = row["trust_decision"].strip().lower()
            if decision not in {"trusted", "compromised"}:
                raise RiskFigureError(
                    f"line {line}: invalid trust_decision {row['trust_decision']!r}"
                )
            alerted = decision == "compromised"
            index = (0 if alerted else 1) if hostile else (2 if alerted else 3)
            confusion[(attack, seed)][index] += 1

            if not alerted:
                continue
            value = parse_priority(row["priority_index"], line=line)
            accumulator = priority[(attack, seed, hostile)]
            accumulator[0] += value
            accumulator[1] += 1.0
            if not hostile:
                continue
            stride_class = row["stride_class"].strip().lower()
            if stride_class not in STRIDE_ORDER:
                raise RiskFigureError(
                    f"line {line}: unknown STRIDE evidence tag {stride_class!r}"
                )
            stride[(attack, seed, stride_class)] += 1
            if stride_class != "none":
                is_ambiguous = parse_bool(
                    row["stride_ambiguous"], field="stride_ambiguous", line=line
                )
                ambiguous[(attack, seed)][1] += 1
                ambiguous[(attack, seed)][0] += int(is_ambiguous)

    if not confusion:
        raise RiskFigureError(
            f"{path}: no eligible test/pure_attack hostile or clean_pair rows"
        )
    return RiskData(dict(priority), dict(stride), dict(ambiguous), dict(confusion))


def seed_block_bootstrap(
    per_seed: Mapping[int, object],
    statistic: Callable[[Sequence[object]], float | None],
    *,
    replicates: int = 2000,
    random_seed: int = 20260801,
) -> Interval:
    """Percentile bootstrap over seed blocks; undefined draws are counted."""

    keys = sorted(per_seed)
    if not keys:
        return Interval(None, None, None, 0)
    point = statistic([per_seed[key] for key in keys])
    if point is None or not math.isfinite(point):
        return Interval(None, None, None, 0)
    rng = random.Random(random_seed)
    draws: list[float] = []
    for _ in range(replicates):
        draw = statistic([per_seed[rng.choice(keys)] for _ in keys])
        if draw is not None and math.isfinite(draw):
            draws.append(draw)
    if not draws:
        return Interval(point, point, point, 0)
    draws.sort()
    low_index = max(0, math.floor(0.025 * len(draws)))
    high_index = min(len(draws) - 1, math.ceil(0.975 * len(draws)) - 1)
    return Interval(point, draws[low_index], draws[high_index], len(draws))


def ratio(payloads: Iterable[Sequence[float]], numerator: int, denominator: int) -> float | None:
    num = sum(payload[numerator] for payload in payloads)
    den = sum(payload[denominator] for payload in payloads)
    return num / den if den else None


def mean_priority(payloads: Iterable[Sequence[float]]) -> float | None:
    return ratio(payloads, 0, 1)


def confusion_rate(payloads: Iterable[Sequence[int]], event: int, other: int) -> float | None:
    payload_list = list(payloads)
    numerator = sum(payload[event] for payload in payload_list)
    denominator = numerator + sum(payload[other] for payload in payload_list)
    return numerator / denominator if denominator else None


def formatted(value: float | None) -> str:
    return "NA" if value is None else f"{value:.6g}"


def metric_row(
    *,
    attack: str,
    metric: str,
    stratum: str,
    interval: Interval,
    numerator: float | int,
    denominator: int,
    pair_count: int,
    seed_count: int,
    missing_reason: str,
) -> dict[str, object]:
    estimable = interval.point is not None
    return {
        "attack": attack,
        "metric": metric,
        "stratum": stratum,
        "mean": formatted(interval.point),
        "ci95_low": formatted(interval.low),
        "ci95_high": formatted(interval.high),
        "numerator": f"{numerator:.12g}" if isinstance(numerator, float) else numerator,
        "denominator": denominator,
        "pair_count": pair_count,
        "seed_count": seed_count,
        "bootstrap_valid_replicates": interval.valid_replicates,
        "status": "estimated" if estimable else missing_reason,
        "ci_unit": "independent RNG seed block",
        "ci_method": "percentile seed-block bootstrap of pooled ratio",
        "population": POPULATION,
    }


def style(axis) -> None:
    for spine in ("top", "right"):
        axis.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        axis.spines[spine].set_color(RULE)
    axis.tick_params(colors=MUTED, labelsize=7.0, length=3)
    axis.set_axisbelow(True)


def render(
    data: RiskData,
    *,
    out_dir: Path,
    out_csv: Path,
    bootstrap_replicates: int = 2000,
    bootstrap_seed: int = 20260801,
) -> list[dict[str, object]]:
    arms = data.attacks()
    if not arms:
        raise RiskFigureError("no known pure-attack arms were parsed")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    figstyle.apply()
    fig, axes = plt.subplots(
        # Drawn at 7.16 in rather than the WDOC measure the other figures use.
        # This panel carries two rotated per-series n-labels inside each arm
        # slot; at 6.5 in they touch, and the layout assertion refuses the
        # figure. The typesetter rescales it by 0.91, which costs a little type
        # size and keeps the labels legible.
        1, 3, figsize=(7.16, 3.55), gridspec_kw={"width_ratios": [1.05, 1.05, 1.0]}
    )

    # A: Q conditional on an alert.  Missing bars are explicitly labelled NA.
    axis = axes[0]
    width = 0.36
    legend_handles: list[Patch] = []
    # Positions where a series has no alerted pair. Collected rather than drawn
    # inline: when BOTH series are empty at one arm, two identical "NA" labels
    # land a few points apart and collide. One centred label says the same
    # thing and is what the arm actually means.
    na_offsets: dict[int, list[float]] = {}
    for offset, hostile, colour, label in (
        (-width / 2 - 0.01, False, CLEAN, "alerted clean pair"),
        (+width / 2 + 0.01, True, HOSTILE, "alerted hostile pair"),
    ):
        legend_handles.append(Patch(facecolor=colour, label=label))
        for position, (attack, _) in enumerate(arms):
            seeds = data.seeds(attack)
            per_seed = {
                seed: data.priority.get((attack, seed, hostile), [0.0, 0.0])
                for seed in seeds
            }
            interval = seed_block_bootstrap(
                per_seed,
                mean_priority,
                replicates=bootstrap_replicates,
                random_seed=bootstrap_seed,
            )
            total_priority = sum(payload[0] for payload in per_seed.values())
            alert_count = int(sum(payload[1] for payload in per_seed.values()))
            rows.append(
                metric_row(
                    attack=attack,
                    metric="mean_peak_priority",
                    stratum="hostile" if hostile else "clean",
                    interval=interval,
                    numerator=total_priority,
                    denominator=alert_count,
                    pair_count=alert_count,
                    seed_count=len(seeds),
                    missing_reason="NA_no_alerted_pairs",
                )
            )
            x = position + offset
            if interval.point is None:
                na_offsets.setdefault(position, []).append(offset)
                continue
            assert interval.low is not None and interval.high is not None
            axis.bar(x, interval.point, width=width, color=colour, zorder=2)
            axis.errorbar(
                [x],
                [interval.point],
                yerr=[[interval.point - interval.low], [interval.high - interval.point]],
                fmt="none",
                ecolor=MUTED,
                lw=0.8,
                capsize=1.8,
                zorder=3,
            )
            # Inside the bar, as in panel B: above it the label would have to
            # grow into the legend strip.
            axis.text(
                x,
                interval.point - 0.03,
                f"$n={alert_count}$",
                ha="center",
                va="top",
                fontsize=5.8,
                color="#ffffff",
                rotation=90,
                zorder=4,
            )
    # One line, not two: rotated, a second line would be wider than this
    # series' half of the arm slot and run into the bar. Where both series are
    # empty the label is centred on the arm instead of drawn twice.
    for position, offsets in na_offsets.items():
        xs = [position] if len(offsets) > 1 else [position + offsets[0]]
        for x in xs:
            axis.text(x, 0.035, "NA ($n=0$)", ha="center", va="bottom",
                      fontsize=5.8, color=MUTED, rotation=90)

    for y, _ in BANDS:
        axis.axhline(y, color=RULE, lw=0.7, ls=(0, (3, 2)), zorder=1)
    # The band names ride on a right-hand secondary axis rather than inside
    # the panel: any in-panel position collides with a bar for some data.
    bands = axis.secondary_yaxis("right")
    bands.set_yticks([y for y, _ in BANDS], labels=[name for _, name in BANDS])
    bands.tick_params(colors=MUTED, labelsize=6.2, length=0, pad=1.5)
    bands.spines["right"].set_visible(False)
    axis.set_ylabel("Mean alert priority index $Q$", fontsize=7.5, color=INK)
    axis.set_ylim(0, 1.0)
    axis.legend(
        handles=legend_handles,
        fontsize=6.2,
        frameon=False,
        loc="lower left",
        bbox_to_anchor=LEGEND_ANCHOR,
        ncol=1,
        handlelength=1.2,
        handletextpad=0.4,
        borderpad=0.0,
        labelspacing=0.3,
    )
    axis.set_title(
        "A  $Q = S \\times I$ (alerts only)", fontsize=7.6, loc="left", pad=TITLE_PAD
    )

    # B: seed-block bootstrap of pooled STRIDE evidence-tag shares.
    axis = axes[1]
    bottoms = [0.0] * len(arms)
    stride_totals: list[int] = []
    for attack, _ in arms:
        stride_totals.append(
            sum(
                value
                for (candidate, _seed, _stride), value in data.stride.items()
                if candidate == attack
            )
        )
    for stride_class in STRIDE_ORDER:
        values: list[float] = []
        for attack, _ in arms:
            seeds = data.seeds(attack)
            per_seed = {
                seed: [
                    data.stride.get((attack, seed, stride_class), 0),
                    sum(data.stride.get((attack, seed, cls), 0) for cls in STRIDE_ORDER),
                ]
                for seed in seeds
            }
            interval = seed_block_bootstrap(
                per_seed,
                lambda payloads: ratio(payloads, 0, 1),
                replicates=bootstrap_replicates,
                random_seed=bootstrap_seed,
            )
            numerator = sum(payload[0] for payload in per_seed.values())
            denominator = sum(payload[1] for payload in per_seed.values())
            rows.append(
                metric_row(
                    attack=attack,
                    metric="stride_share",
                    stratum=stride_class,
                    interval=interval,
                    numerator=numerator,
                    denominator=denominator,
                    pair_count=denominator,
                    seed_count=len(seeds),
                    missing_reason="NA_no_alerted_hostile_pairs",
                )
            )
            values.append(interval.point if interval.point is not None else 0.0)
        axis.bar(
            range(len(arms)),
            values,
            bottom=bottoms,
            width=0.62,
            color=STRIDE_COLOUR[stride_class],
            label=stride_class.replace("_", " "),
            zorder=2,
        )
        bottoms = [bottom + value for bottom, value in zip(bottoms, values)]
    for index, ((attack, _), total) in enumerate(zip(arms, stride_totals)):
        if total:
            axis.text(
                index,
                0.985,
                f"$n={total}$",
                ha="center",
                va="top",
                fontsize=6.0,
                color="#ffffff",
                rotation=90,
            )
        else:
            axis.text(index, 0.035, "NA\n$n=0$", ha="center", fontsize=6.0, color=MUTED)
        seeds = data.seeds(attack)
        per_seed = {
            seed: data.ambiguous.get((attack, seed), [0, 0]) for seed in seeds
        }
        interval = seed_block_bootstrap(
            per_seed,
            lambda payloads: ratio(payloads, 0, 1),
            replicates=bootstrap_replicates,
            random_seed=bootstrap_seed,
        )
        numerator = sum(payload[0] for payload in per_seed.values())
        denominator = sum(payload[1] for payload in per_seed.values())
        rows.append(
            metric_row(
                attack=attack,
                metric="stride_ambiguous_share",
                stratum="attributed_alerts",
                interval=interval,
                numerator=numerator,
                denominator=denominator,
                pair_count=denominator,
                seed_count=len(seeds),
                missing_reason="NA_no_attributed_alerts",
            )
        )
    axis.set_ylabel("Share of alerted hostile pairs", fontsize=7.5, color=INK)
    axis.set_ylim(0, 1.10)
    axis.legend(
        fontsize=6.2,
        frameon=False,
        loc="lower left",
        ncol=2,
        bbox_to_anchor=LEGEND_ANCHOR,
        columnspacing=0.8,
        handlelength=1.2,
        handletextpad=0.35,
        borderpad=0.0,
        labelspacing=0.3,
    )
    axis.set_title("B  STRIDE evidence tag", fontsize=7.6, loc="left", pad=TITLE_PAD)

    # C: frozen binary decision.  Negatives are explicitly clean_pair.
    axis = axes[2]
    for marker, event, other, colour, label, metric in (
        ("o", 0, 1, HOSTILE, "detection rate", "compromised_tpr"),
        ("s", 2, 3, CLEAN, "clean-pair false-alarm rate", "compromised_fpr"),
    ):
        for position, (attack, _) in enumerate(arms):
            seeds = data.seeds(attack)
            per_seed = {seed: data.confusion[(attack, seed)] for seed in seeds}
            interval = seed_block_bootstrap(
                per_seed,
                lambda payloads, e=event, o=other: confusion_rate(payloads, e, o),
                replicates=bootstrap_replicates,
                random_seed=bootstrap_seed,
            )
            numerator = sum(payload[event] for payload in per_seed.values())
            denominator = numerator + sum(payload[other] for payload in per_seed.values())
            rows.append(
                metric_row(
                    attack=attack,
                    metric=metric,
                    stratum="hostile" if event == 0 else "clean_pair",
                    interval=interval,
                    numerator=numerator,
                    denominator=denominator,
                    pair_count=denominator,
                    seed_count=len(seeds),
                    missing_reason="NA_no_pairs_in_stratum",
                )
            )
            if interval.point is None:
                axis.text(position, 0.03, "NA", ha="center", fontsize=6.0, color=MUTED)
                continue
            assert interval.low is not None and interval.high is not None
            axis.errorbar(
                [position],
                [interval.point],
                yerr=[[interval.point - interval.low], [interval.high - interval.point]],
                color=colour,
                marker=marker,
                markersize=4,
                lw=1.2,
                capsize=2,
                elinewidth=0.8,
                zorder=3,
            )
            # Upright labels would collide at seven arms in this width, so the
            # counts are turned and run into the empty middle of the panel:
            # down from a high point, up from a low one. The two series keep
            # separate label columns so a low detection rate and its arm's
            # false-alarm rate cannot stack on each other.
            upward = interval.point < 0.5
            axis.annotate(
                f"$n={denominator}$",
                (position, interval.point),
                xytext=(-5 if event == 0 else 5, 7 if upward else -7),
                textcoords="offset points",
                fontsize=6.0,
                color=MUTED,
                rotation=90,
                ha="center",
                va="bottom" if upward else "top",
            )
        # Legend proxy without drawing lines across attack arms.
        axis.plot([], [], color=colour, marker=marker, lw=1.2, label=label)
    axis.set_ylabel("Rate", fontsize=7.5, color=INK)
    axis.set_ylim(-0.04, 1.04)
    axis.legend(
        fontsize=6.2,
        frameon=False,
        loc="lower left",
        bbox_to_anchor=LEGEND_ANCHOR,
        ncol=1,
        labelspacing=0.3,
        handlelength=1.3,
        handletextpad=0.4,
        borderpad=0.0,
    )
    axis.set_title("C  COMPROMISED decision", fontsize=7.6, loc="left", pad=TITLE_PAD)

    for axis in axes:
        axis.set_xticks(range(len(arms)))
        axis.set_xticklabels(
            [label for _, label in arms],
            fontsize=6.0,
            color=INK,
            rotation=38,
            ha="right",
            rotation_mode="anchor",
        )
        axis.grid(axis="y", color=RULE, lw=0.5, zorder=0)
        style(axis)

    # The provisos that used to be printed under the panels (eligible-pair
    # counts, bootstrap method, "conditional on alerts", "not ground truth")
    # live in the LaTeX caption. A journal figure carries no caption of its own.
    fig.tight_layout(pad=0.4)
    figstyle.assert_no_text_overlap(fig)
    for extension in ("pdf", "png"):
        fig.savefig(
            out_dir / f"fig_risk.{extension}", dpi=400, facecolor=SURFACE
        )
    plt.close(fig)

    with out_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return rows


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=Path, required=True)
    parser.add_argument("--out-csv", type=Path)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "figures")
    parser.add_argument("--bootstrap-replicates", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260801)
    args = parser.parse_args(argv)
    if not args.pairs.is_file():
        raise SystemExit(f"error: pair table not found: {args.pairs}")
    if args.bootstrap_replicates < 1:
        raise SystemExit("error: --bootstrap-replicates must be positive")
    out_csv = args.out_csv or args.pairs.parent / "analysis" / "risk_metrics.csv"
    try:
        data = load(args.pairs)
        rows = render(
            data,
            out_dir=args.out,
            out_csv=out_csv,
            bootstrap_replicates=args.bootstrap_replicates,
            bootstrap_seed=args.bootstrap_seed,
        )
    except (OSError, RiskFigureError) as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(f"wrote {args.out}/fig_risk.pdf and {out_csv}")
    for attack, _ in data.attacks():
        selected = {
            (row["metric"], row["stratum"]): row
            for row in rows
            if row["attack"] == attack
        }
        hostile_q = selected[("mean_peak_priority", "hostile")]["mean"]
        tpr = selected[("compromised_tpr", "hostile")]["mean"]
        fpr = selected[("compromised_fpr", "clean_pair")]["mean"]
        print(f"  {attack:<12} Q(hostile alerts)={hostile_q!s:>7}  TPR={tpr!s:>7}  FPR={fpr!s:>7}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
