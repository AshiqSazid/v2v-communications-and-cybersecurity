#!/usr/bin/env python3
"""Render the results figures from measured data.

    python3 make_result_figures.py --metrics results/<release>/full/analysis/metrics_v4.csv

Reads an explicitly selected final metrics table and writes to figures/:
    fig_detection.pdf   detection per attack, with bootstrap intervals
    fig_mitigation.pdf  victim misattribution, identity vs track keying
    fig_cost.pdf        network and CPU cost, detector on vs off

Every value is read from the analysis output; nothing here is typed in. These
replace three earlier figures that could not be reproduced from any version of
the simulator:

  IDS_Comparison.png     unsupported "with vs without model" comparison;
                         replaced by measured detection per attack type.
  Latency_Comparison.png "average message latency: DSRC vs C-V2X"
  (PDR figure)           "packet delivery ratio: DSRC vs C-V2X"
                         -- the simulator implements IEEE 802.11p only. There
                         is no C-V2X stack, so no such comparison can be
                         produced. Replaced by the measured cost of running
                         the detector, which is the claim the originals were
                         reaching for.
"""
import argparse
import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import figstyle
from figstyle import INK, MUTED, RULE, SURFACE, BASE, OURS, ALT, FAINT, W1, W2

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "figures"



def load(metrics):
    table = {}
    with open(metrics) as f:
        for r in csv.DictReader(f):
            try:
                lo, hi = float(r["ci95_low"]), float(r["ci95_high"])
            except (ValueError, KeyError):
                lo = hi = float(r["mean"]) if r["mean"] else float("nan")
            try:
                table[(r["arm"], r["metric"])] = (float(r["mean"]), lo, hi)
            except ValueError:
                pass
    return table


def style(ax):
    figstyle.despine(ax)


def fig_detection(t):
    arms = [
        ("pure_falsify", "Position\nfalsification"),
        ("pure_revheading", "Reversed\nheading"),
        ("pure_replay", "Replay"),
        ("pure_dos", "Flooding"),
        # Prevalence named on the axis, as in the detection table: "mixed"
        # alone does not identify which of the four mixed arms this is.
        ("mixedhard_frac_0p3", "Mixed\nadversary (30%)"),
        ("pure_spoof", "Identity\nspoofing"),
        ("pure_constoffset", "Constant\noffset"),
        ("pure_slydos", "Rate-limited\nflooding"),
    ]
    vals = [t[(a, "stream_tpr")] for a, _ in arms]
    fprs = [t[(a, "clean_fpr")][0] for a, _ in arms]
    fig, ax = plt.subplots(figsize=(figstyle.WDOC, 2.55))
    x = range(len(arms))
    err = [[v[0] - v[1] for v in vals], [v[2] - v[0] for v in vals]]
    ax.bar(x, [v[0] for v in vals], width=0.58, color=OURS, yerr=err,
           error_kw=dict(ecolor=MUTED, lw=1.0, capsize=2.5), zorder=2)
    # Selective direct labels. A number over every bar restates the axis eight
    # times; the three the text argues about are the best, the worst non-zero,
    # and the undetected case.
    label_at = {0, len(arms) - 2, len(arms) - 1}
    for i, v in enumerate(vals):
        if i in label_at:
            ax.text(i, v[2] + 0.035, f"{v[0]:.3f}", ha="center", va="bottom",
                    fontsize=6.8, color=INK)
    ax.set_xticks(list(x))
    ax.set_xticklabels([n for _, n in arms], fontsize=7.0, color=INK)
    ax.set_ylabel("True-positive rate", fontsize=8, color=INK)
    ax.set_ylim(0, 1.12)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    figstyle.grid_y(ax)
    fpr_note = (
        f"clean-pair FPR range: {min(fprs):.3f}–{max(fprs):.3f}"
        if min(fprs) != max(fprs)
        else f"clean-pair FPR: {fprs[0]:.3f} in every shown arm"
    )
    ax.text(0.995, 0.965, fpr_note,
            transform=ax.transAxes, ha="right", va="top", fontsize=6.8,
            color=MUTED)
    style(ax)
    fig.tight_layout(pad=0.3)
    for e in ("pdf", "png"):
        fig.savefig(OUT / f"fig_detection.{e}", dpi=400, bbox_inches="tight",
                    facecolor=SURFACE)
    plt.close(fig)


def fig_mitigation(t):
    """Identity-keyed vs track-keyed victim alerts.

    A dumbbell, not grouped bars. The quantity the section argues about is the
    *drop* from one keying to the other; grouped bars encode it as the
    difference of two heights the eye has to subtract, while a connector
    encodes it as a length the eye reads directly. Four categories is also well
    under the point where connectors start crossing.
    """
    arms = [
        ("pure_replay", "Replay"),
        ("mixedhard_frac_0p3", "Mixed 30%"),
        ("mixedhard_frac_0p5", "Mixed 50%"),
        ("pure_spoof", "Spoofing"),
    ]
    ident = [t[(a, "victim_pair_post_onset_alert_rate")] for a, _ in arms]
    track = [t[(a, "victim_pair_track_alert_rate")] for a, _ in arms]

    fig, ax = plt.subplots(figsize=(W1, 2.15))
    y = list(range(len(arms)))[::-1]          # first arm on top

    for row, lo, hi in zip(y, track, ident):
        ax.plot([lo[0], hi[0]], [row, row], color=RULE, lw=1.3,
                solid_capstyle="butt", zorder=1)
    # Bootstrap intervals drawn as whiskers through each marker, in the
    # marker's own colour so the pairing survives greyscale.
    for row, v, colour in ([(r, v, ALT) for r, v in zip(y, track)] +
                           [(r, v, BASE) for r, v in zip(y, ident)]):
        ax.plot([v[1], v[2]], [row, row], color=colour, lw=2.2, alpha=0.35,
                zorder=2, solid_capstyle="butt")
    ax.scatter([v[0] for v in ident], y, s=22, color=BASE, zorder=3,
               edgecolor=SURFACE, linewidth=0.8, label="claimed identity")
    ax.scatter([v[0] for v in track], y, s=22, color=ALT, zorder=3,
               edgecolor=SURFACE, linewidth=0.8, label="kinematic track")

    # Direct labels on the endpoints only, pushed clear of the interval rather
    # than of the marker, so a wide interval never collides with its own number.
    for row, lo, hi in zip(y, track, ident):
        ax.text(hi[2] + 0.045, row, f"{hi[0]:.2f}", ha="left", va="center",
                fontsize=6.2, color=INK)
        ax.text(lo[1] - 0.045, row, f"{lo[0]:.2f}", ha="right", va="center",
                fontsize=6.2, color=INK)

    ax.set_yticks(y)
    ax.set_yticklabels([n for _, n in arms], fontsize=7.0, color=INK)
    ax.set_xlabel("Victim-exposed alert rate", fontsize=7.5, color=INK)
    ax.set_xlim(-0.12, 1.12)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_ylim(-0.55, len(arms) - 0.35)
    ax.grid(axis="x", color=RULE, lw=0.5, zorder=0)
    ax.grid(axis="y", visible=False)
    ax.legend(fontsize=6.6, frameon=False, loc="lower center",
              bbox_to_anchor=(0.5, 1.0), ncol=2, labelcolor=INK,
              handletextpad=0.3, columnspacing=1.4)
    figstyle.despine(ax, keep=("bottom",))
    ax.tick_params(axis="y", length=0)
    fig.tight_layout(pad=0.3)
    figstyle.assert_no_text_overlap(fig)
    for e in ("pdf", "png"):
        fig.savefig(OUT / f"fig_mitigation.{e}", dpi=400, bbox_inches="tight",
                    facecolor=SURFACE)
    plt.close(fig)


def fig_cost(t):
    lat_on = t[("detector_on", "latency_ms")]
    lat_off = t[("detector_off", "latency_ms")]
    pdr_on = t[("detector_on", "pdr")]
    pdr_off = t[("detector_off", "pdr")]
    cpu = t[("detector_on", "det_us")]

    fig, axes = plt.subplots(1, 3, figsize=(figstyle.WDOC, 2.15))
    panels = [
        (axes[0], "Application latency (ms)", [lat_off, lat_on],
         ["detector off", "detector on"], [BASE, OURS]),
        (axes[1], "Packet delivery ratio", [pdr_off, pdr_on],
         ["detector off", "detector on"], [BASE, OURS]),
    ]
    for ax, title, vals, labels, colours in panels:
        ax.bar(range(2), [v[0] for v in vals], width=0.5, color=colours,
               zorder=2,
               yerr=[[v[0] - v[1] for v in vals], [v[2] - v[0] for v in vals]],
               error_kw=dict(ecolor=MUTED, lw=0.9, capsize=3))
        for i, v in enumerate(vals):
            ax.text(i, v[2] * 1.02, f"{v[0]:.3f}", ha="center", va="bottom",
                    fontsize=7.0, color=INK)
        ax.set_xticks([0, 1])
        ax.set_xticklabels(labels, fontsize=7.0, color=INK)
        ax.set_title(title, fontsize=8, color=INK, pad=7)
        ax.set_ylim(0, max(v[2] for v in vals) * 1.30)
        figstyle.grid_y(ax)
        style(ax)

    ax = axes[2]
    ax.bar([0], [cpu[0]], width=0.5, color=OURS, zorder=2,
           yerr=[[cpu[0] - cpu[1]], [cpu[2] - cpu[0]]],
           error_kw=dict(ecolor=MUTED, lw=0.9, capsize=3))
    ax.text(0, cpu[2] * 1.02, f"{cpu[0]:.3f}", ha="center", va="bottom",
            fontsize=7.0, color=INK)
    ax.set_xticks([0])
    ax.set_xticklabels(["detector on"], fontsize=7.0, color=INK)
    ax.set_title("Detector cost (µs/message)", fontsize=8, color=INK, pad=7)
    ax.set_ylim(0, cpu[2] * 1.35)
    figstyle.grid_y(ax)
    style(ax)

    # Paired-seed design and the parity-verification reading are stated in the
    # LaTeX caption, not printed under the panels.
    fig.tight_layout(pad=0.4)
    figstyle.assert_no_text_overlap(fig)
    for e in ("pdf", "png"):
        fig.savefig(OUT / f"fig_cost.{e}", dpi=400, bbox_inches="tight",
                    facecolor=SURFACE)
    plt.close(fig)


def main():
    global OUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()
    if not args.metrics.exists():
        raise SystemExit(f"error: metrics table not found: {args.metrics}")
    OUT = args.out
    OUT.mkdir(parents=True, exist_ok=True)
    figstyle.apply()
    t = load(args.metrics)
    fig_detection(t)
    fig_mitigation(t)
    fig_cost(t)
    print(f"wrote fig_detection, fig_mitigation, fig_cost to {OUT}")


if __name__ == "__main__":
    main()
