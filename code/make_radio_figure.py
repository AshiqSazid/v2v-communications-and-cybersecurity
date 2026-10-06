#!/usr/bin/env python3
"""Render the radio-access comparison figure from measured data.

    python3 make_radio_figure.py

Reads results/radio/radio_raw.csv (written by results/radio/radio_sweep) and
writes figures/fig_radio.pdf and .png.

WHAT THIS FIGURE IS, AND WHAT IT IS NOT
---------------------------------------
It compares IEEE 802.11p direct broadcast against LTE Uu, i.e. 3GPP C-V2X
*mode 3*, in which safety messages are relayed uplink to the eNB, through the
EPC, and back down to peers.

It is NOT a DSRC-vs-C-V2X-sidelink comparison. Mode 4 -- autonomous direct
sidelink, which is what most V2V literature means by "C-V2X" -- has no model in
mainline ns-3 and the 5G-LENA `nr` module is not installed, so mode 4 was not
simulated and no claim is made about it. The measured gap here is a property of
the access ARCHITECTURE (two hops through a core network versus one direct
hop), not evidence about sidelink performance. The caption says so, because a
reader who skims will otherwise take it for the mode-4 result.

This replaces two earlier figures (Latency_Comparison.png, and the PDR figure)
that showed C-V2X *beating* DSRC on both metrics. Those numbers are not
reproducible from any version of this codebase, and the measurement here points
the other way for a structural reason.
"""
import csv
import statistics as st
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import figstyle
from figstyle import INK, MUTED, RULE, SURFACE

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "results/radio/radio_raw.csv"
OUT = ROOT / "figures"

DSRC, CV2X = "#0072B2", "#D55E00"


def load():
    """-> {(tech, n): {"latency_ms": [...], "pdr": [...]}}"""
    runs = defaultdict(lambda: defaultdict(list))
    with open(RAW) as f:
        for r in csv.DictReader(f):
            try:
                n = int(r["n_vehicles"])
                lat, pdr = float(r["latency_ms"]), float(r["pdr"])
            except (ValueError, KeyError):
                continue
            if lat != lat or pdr != pdr:       # NaN guard
                continue
            runs[(r["tech"], n)]["latency_ms"].append(lat)
            runs[(r["tech"], n)]["pdr"].append(pdr)
    return runs


def mean_sd(xs):
    if not xs:
        return float("nan"), 0.0
    return st.mean(xs), (st.stdev(xs) if len(xs) > 1 else 0.0)


def style(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(RULE)
    ax.tick_params(colors=MUTED, labelsize=7.5, length=3)
    ax.set_axisbelow(True)


def panel(ax, runs, counts, field, ylabel, logy=False):
    for tech, colour, label, marker in (
        ("dsrc", DSRC, "IEEE 802.11p (direct)", "o"),
        ("cv2x", CV2X, "LTE Uu / C-V2X mode 3 (via eNB)", "s"),
    ):
        ms = [mean_sd(runs[(tech, n)][field]) for n in counts]
        ax.errorbar(counts, [m for m, _ in ms], yerr=[s for _, s in ms],
                    color=colour, marker=marker, markersize=4.5, lw=1.8,
                    capsize=2.5, elinewidth=0.9, label=label, zorder=3)
    ax.set_xlabel("Vehicles in the 5 km segment", fontsize=7.5, color=INK)
    ax.set_ylabel(ylabel, fontsize=7.5, color=INK)
    ax.set_xticks(counts)
    if logy:
        ax.set_yscale("log")
    ax.grid(axis="y", color=RULE, lw=0.6, zorder=0)
    style(ax)


def main():
    OUT.mkdir(exist_ok=True)
    figstyle.apply()
    runs = load()
    counts = sorted({n for _, n in runs})
    if not counts:
        raise SystemExit(f"no usable rows in {RAW}")

    fig, axes = plt.subplots(1, 2, figsize=(figstyle.WDOC, 2.95))
    panel(axes[0], runs, counts, "latency_ms",
          "Mean one-way latency (ms)", logy=True)
    panel(axes[1], runs, counts, "pdr", "Packet delivery ratio")
    axes[1].set_ylim(0, 1.0)

    # Both panels draw the same two series, so one shared legend above the
    # panels serves both and sits clear of the plotted lines.
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", bbox_to_anchor=(0.5, 0.915),
               ncol=2, frameon=False, fontsize=7.0, labelcolor=INK,
               handlelength=1.8, columnspacing=2.2, handletextpad=0.6)

    # The mode-3-not-mode-4 caveat is in the LaTeX caption, where a skimming
    # reader meets it, rather than set as a second caption inside the artwork.
    fig.tight_layout(rect=(0, 0, 1, 0.905))
    figstyle.assert_no_text_overlap(fig)
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"fig_radio.{ext}", dpi=400, facecolor=SURFACE)
    plt.close(fig)

    print(f"wrote {OUT}/fig_radio.pdf and .png")
    for n in counts:
        for tech in ("dsrc", "cv2x"):
            lat, _ = mean_sd(runs[(tech, n)]["latency_ms"])
            pdr, _ = mean_sd(runs[(tech, n)]["pdr"])
            k = len(runs[(tech, n)]["pdr"])
            print(f"  n={n:>3} {tech:>5}: latency {lat:8.2f} ms   "
                  f"PDR {pdr:.3f}   ({k} runs)")


if __name__ == "__main__":
    main()
