#!/usr/bin/env python3
"""Render the methodology figure for the paper.

    python3 make_methodology_figure.py --results-root results/<release>/full

Writes fig_methodology.pdf (vector, for LaTeX) and .png (preview) to figures/.

Design constraints, in order of priority:
  * legible at IEEE two-column width (7.16 in) and in grayscale print;
  * colour is REDUNDANT with position and label everywhere, so the figure
    survives desaturation and colour-vision deficiency;
  * exactly one accent marks the contribution (the track-keyed branch) --
    everything else is neutral ink, so the eye lands on the fork.
"""
import argparse
import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

import figstyle
from figstyle import INK, MUTED, SURFACE

DEFAULT_OUT = Path(__file__).resolve().parent / "figures"

RULE = "#b8b7b2"      # heavier than the shared rule: these are box borders
BASE = "#0072B2"      # identity-keyed path (the baseline being critiqued)
ACCENT = "#D55E00"    # track-keyed path (the contribution)


def box(ax, x, y, w, h, label, sub=None, edge=RULE, face=SURFACE,
        lw=1.0, bold=False, fs=7.4, gap=0.030):
    ax.add_patch(
        FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0.012,rounding_size=0.02",
            linewidth=lw, edgecolor=edge, facecolor=face, zorder=2,
        )
    )
    ax.text(
        x + w / 2, y + h / 2 + (gap if sub else 0), label,
        ha="center", va="center", fontsize=fs, color=INK, zorder=3,
        fontweight="bold" if bold else "normal", linespacing=1.35,
    )
    if sub:
        ax.text(x + w / 2, y + h / 2 - gap, sub, ha="center", va="center",
                fontsize=6.2, color=MUTED, zorder=3, linespacing=1.3)


def arrow(ax, p0, p1, color=RULE, lw=1.0, label=None, dx=0.0, style="-|>"):
    ax.add_patch(
        FancyArrowPatch(p0, p1, arrowstyle=style, mutation_scale=8,
                        linewidth=lw, color=color, zorder=1,
                        shrinkA=1.5, shrinkB=1.5)
    )
    if label:
        ax.text((p0[0] + p1[0]) / 2 + dx, (p0[1] + p1[1]) / 2, label,
                fontsize=6.5, color=MUTED, ha="left", va="center",
                zorder=3, bbox=dict(fc=SURFACE, ec="none", pad=1.0))


def plan_vehicles(row):
    """Vehicle count for one plan row.

    The frozen plan carries no top-level `n`; the simulator argument vector in
    `args_json` is the single source of truth for what was actually run, so the
    count is read from there rather than from a column that could drift from it.
    """
    for arg in json.loads(row["args_json"]):
        if arg.startswith("--nVehicles="):
            return int(arg.split("=", 1)[1])
    raise KeyError(f"no --nVehicles in plan row {row['experiment_id']}")


def read_plan(results_root, name, expected_stage):
    """Read one frozen TSV plan and fail closed on duplicate or wrong-stage rows."""
    path = results_root / "plans" / f"{name}.tsv"
    if not path.exists():
        raise SystemExit(f"error: missing frozen plan {path}")
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))
    if not rows:
        raise SystemExit(f"error: frozen plan {path} contains no experiments")
    required = {"experiment_id", "stage", "family", "arm", "seed", "args_json"}
    missing = required.difference(rows[0])
    if missing:
        raise SystemExit(f"error: {path} lacks columns {sorted(missing)}")
    ids = [row["experiment_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise SystemExit(f"error: duplicate experiment_id in {path}")
    wrong = {row["stage"] for row in rows if row["stage"] != expected_stage}
    if wrong:
        raise SystemExit(
            f"error: {path} contains stage(s) {sorted(wrong)}, expected {expected_stage}"
        )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-root", type=Path, required=True,
        help="Frozen result root containing plans/validation.tsv and plans/test.tsv",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    validation = read_plan(args.results_root, "validation", "validation")
    test = read_plan(args.results_root, "test", "test")
    validation_arms = len({row["arm"] for row in validation})
    test_arms = len({row["arm"] for row in test})
    test_families = len({row["family"] for row in test})
    try:
        vehicle_counts = sorted({plan_vehicles(row) for row in validation + test})
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: non-integer vehicle count in frozen plan: {exc}")
    vehicle_label = (
        f"{vehicle_counts[0]} vehicles"
        if len(vehicle_counts) == 1
        else f"{vehicle_counts[0]}–{vehicle_counts[-1]} vehicles"
    )

    args.out.mkdir(parents=True, exist_ok=True)
    figstyle.apply()
    fig, ax = plt.subplots(figsize=(figstyle.WDOC, 4.15))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # ---------------- left column: simulation -> evidence ----------------
    box(ax, 0.02, 0.855, 0.40, 0.105,
        f"{vehicle_label} · IEEE 802.11p · highway",
        "honest + up to 7 attacker roles; activation varies by arm", bold=True)
    arrow(ax, (0.22, 0.855), (0.22, 0.775),
          label="  BSM broadcast, 10 Hz")

    box(ax, 0.02, 0.665, 0.40, 0.110,
        "Seven noise-aware plausibility checks",
        "position jump · speed · heading · staleness\nreplay · rate · map bounds")
    arrow(ax, (0.22, 0.665), (0.22, 0.585),
          label="  per-check log-evidence")

    box(ax, 0.02, 0.475, 0.40, 0.110,
        "Sequential evidence accumulation",
        "time-decayed, clamped; a decision score,\nnot a calibrated probability")

    # ---------------- the fork: the contribution -------------------------
    arrow(ax, (0.20, 0.475), (0.118, 0.432), color=BASE, lw=1.5)
    arrow(ax, (0.24, 0.475), (0.322, 0.432), color=ACCENT, lw=1.5)

    box(ax, 0.015, 0.268, 0.185, 0.164, "claimed\nidentity",
        "baseline:\nforged + genuine\nshare one state",
        edge=BASE, lw=1.5, bold=True, fs=7.0, gap=0.048)
    box(ax, 0.235, 0.268, 0.185, 0.164, "kinematic\ntrack",
        "proposed:\ntrajectories separate\nby content alone",
        edge=ACCENT, lw=1.5, bold=True, fs=7.0, gap=0.048)

    # Route the merge arrows down the OUTER edges so the corridor between the
    # two branches stays clear for the decision box.
    arrow(ax, (0.055, 0.268), (0.105, 0.196), color=BASE, lw=1.5)
    arrow(ax, (0.380, 0.268), (0.330, 0.196), color=ACCENT, lw=1.5)

    # ---------------- decision -------------------------------------------
    box(ax, 0.045, 0.062, 0.345, 0.134,
        "Decision: peak score over $W$ > $\\tau$",
        "$W=[\\max(\\mathrm{warmup},\\,t_a+g),\\,T]$ — one rule, both classes,\n"
        "both keyings scored in one run; AUC ranks the\n"
        "same statistic the operating point thresholds", bold=True)

    # ---------------- right column: protocol + outputs -------------------
    ax.plot([0.475, 0.475], [0.055, 0.965], color=RULE, lw=0.7, ls=(0, (3, 3)))

    box(ax, 0.515, 0.855, 0.465, 0.105,
        f"Validation — {len(validation)} planned runs",
        f"{validation_arms} arms; select $\\tau$ under a benign-seed FP bound\n"
        "then write threshold + input hashes and FREEZE", bold=True)
    arrow(ax, (0.7475, 0.855), (0.7475, 0.785), label="  $\\tau$ frozen")

    box(ax, 0.515, 0.675, 0.465, 0.110,
        f"Held-out test — {len(test)} planned runs, disjoint seeds",
        f"{test_arms} arms across {test_families} families; exact inventory\n"
        "read from frozen TSV plan, never transcribed", bold=True)
    arrow(ax, (0.7475, 0.675), (0.7475, 0.605))

    box(ax, 0.515, 0.475, 0.465, 0.130,
        "Evaluation, per (receiver, identity) pair",
        "stream detection · owner attribution · clean false\n"
        "alarms · victim framing · time-to-detect (censored)\n"
        "pairs with no exposure in $W$ are excluded, not scored")

    # paired contrasts -- the two results the design exists to produce
    ax.add_patch(FancyBboxPatch(
        (0.515, 0.065), 0.465, 0.355,
        boxstyle="round,pad=0.012,rounding_size=0.02",
        linewidth=1.0, edgecolor=RULE, facecolor="#faf9f7", zorder=1))
    # The two items are spread over the band the resampling-method sentence
    # used to occupy; that sentence is in the LaTeX caption now. The panel keeps
    # its bottom edge so it still lines up with the left column.
    ax.text(0.7475, 0.370, "Two paired contrasts, same seeds",
            fontsize=7.4, color=INK, ha="center", va="center",
            fontweight="bold")

    ax.text(0.535, 0.290, "1", fontsize=7.0, color=SURFACE, ha="center",
            va="center", zorder=4,
            bbox=dict(boxstyle="circle,pad=0.24", fc=MUTED, ec="none"))
    ax.text(0.560, 0.295,
            "$t_a=0$ vs mid-stream onset", fontsize=6.8, color=INK,
            ha="left", va="center", fontweight="bold")
    ax.text(0.560, 0.253,
            "separates detecting the attack from detecting\n"
            "its switch-on transient", fontsize=6.1, color=MUTED,
            ha="left", va="center", linespacing=1.35)

    ax.text(0.535, 0.155, "2", fontsize=7.0, color=SURFACE, ha="center",
            va="center", zorder=4,
            bbox=dict(boxstyle="circle,pad=0.24", fc=ACCENT, ec="none"))
    ax.text(0.560, 0.160,
            "identity keying vs track keying", fontsize=6.8, color=INK,
            ha="left", va="center", fontweight="bold")
    ax.text(0.560, 0.118,
            "quantifies victim framing under impersonation,\n"
            "and how much of it the proposed keying removes",
            fontsize=6.1, color=MUTED, ha="left", va="center",
            linespacing=1.35)

    # column captions
    ax.text(0.22, 0.985, "SIMULATION AND DETECTOR", fontsize=6.6,
            color=MUTED, ha="center", va="center", fontweight="bold")
    ax.text(0.7475, 0.985, "EXPERIMENTAL PROTOCOL", fontsize=6.6,
            color=MUTED, ha="center", va="center", fontweight="bold")

    fig.tight_layout(pad=0.15)
    figstyle.assert_no_text_overlap(fig)
    for ext in ("pdf", "png"):
        fig.savefig(args.out / f"fig_methodology.{ext}", dpi=400,
                    bbox_inches="tight", facecolor=SURFACE)
    print(f"wrote {args.out}/fig_methodology.pdf and .png")


if __name__ == "__main__":
    main()
