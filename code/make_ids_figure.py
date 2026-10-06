#!/usr/bin/env python3
"""Render the sequential-evidence fusion ablation figure.

    python3 make_ids_figure.py --report results/<release>/baselines.txt

Reads an explicitly selected report written by baselines.py and writes
figures/fig_ids_ablation.pdf and .png. There is deliberately no archived-result
default: a final figure must name the report from the frozen release.

WHAT THE ABLATION ISOLATES
--------------------------
Both arms replay the SAME seven plausibility checks over the SAME traces. Each
rule uses its own native threshold, selected on validation under the same
seed-level false-alarm constraint and then frozen for test. Message streams,
check outputs, partitions, and selection protocol are held fixed; each rule
and its selected threshold remain a single comparator:

  two-of-seven      instantaneous rule -- alert if >= 2 checks fire on a single
                    message. No memory across messages.
  sequential-score  time-decayed log-evidence accumulation across messages.

The operating-point comparison is therefore performance under an equal
selection protocol, not a fixed-numeric-threshold causal contrast; each native
threshold is part of its rule.
This replaces the earlier unsupported "with vs without Bayesian model" framing;
the score is not a calibrated posterior.

The measured story is more interesting than a uniform gap: fusion is worth
almost nothing where a single message is already blatantly implausible
(falsify), and is the difference between total failure and near-perfect
detection where no single message is damning and evidence must accumulate
(dos, revheading).

Detection delay and classification both use the first current alert after
hostile onset and the same peak-over-window endpoint as the main detector.
"""
import argparse
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import figstyle
from figstyle import INK, MUTED, RULE, SURFACE, BASE, OURS

ROOT = Path(__file__).resolve().parent
DEFAULT_OUT = ROOT / "figures"

MEMORYLESS, SEQUENTIAL = BASE, OURS

# (stratum in report, label on axis) -- ordered by how much fusion buys
ARMS = [
    ("revheading", "Reversed\nheading"),
    ("dos", "Flooding"),
    ("replay", "Replay"),
    ("spoof", "Identity\nspoofing"),
    ("falsify", "Position\nfalsification"),
    ("constoffset", "Constant\noffset"),
    ("slydos", "Rate-limited\nflooding"),
]
STAT = re.compile(r"(-?[\d.]+)\s+\[(-?[\d.]+),(-?[\d.]+)\]")


def parse(report):
    """-> {(stratum, rule): (mean, lo, hi)} for the claimed-identity keying."""
    text = report.read_text()
    out = {}
    for block in text.split("Attack stratum: ")[1:]:
        stratum = block.split("\n", 1)[0].strip()
        for line in block.splitlines():
            if not line.startswith("claimed"):
                continue
            for rule in ("two-of-seven", "sequential-score"):
                if f" {rule} " not in line:
                    continue
                tail = line.split(rule, 1)[1]
                m = STAT.search(tail)          # first stat is stream TPR
                # Keep the FIRST match only. The report also carries a
                # precision/recall/F1 table whose rows start with the same key
                # and rule names; overwriting would silently substitute
                # precision (which is 1.000 almost everywhere) for stream TPR.
                if m and (stratum, rule) not in out:
                    out[(stratum, rule)] = tuple(float(g) for g in m.groups())
    return out


def style(ax):  # noqa: D103 - kept for call-site compatibility
    figstyle.despine(ax)
    return


def _style_unused(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(RULE)
    ax.tick_params(colors=MUTED, labelsize=7.5, length=3)
    ax.set_axisbelow(True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    if not args.report.exists():
        raise SystemExit(f"error: report not found: {args.report}")
    args.out.mkdir(parents=True, exist_ok=True)
    d = parse(args.report)
    arms = [(s, lab) for s, lab in ARMS if (s, "sequential-score") in d]
    if not arms:
        raise SystemExit(f"no strata parsed from {args.report}")

    figstyle.apply()
    fig, ax = plt.subplots(figsize=(figstyle.WDOC, 2.75))
    x = range(len(arms))
    w = 0.32
    # A clear surface gap between the two bars of a pair: abutting fills read as
    # one divided block, which is the wrong unit -- the pair is the comparison.
    for off, rule, colour, label in (
        (-w / 2 - 0.035, "two-of-seven", MEMORYLESS, "instantaneous two-of-seven"),
        (+w / 2 + 0.035, "sequential-score", SEQUENTIAL, "sequential log-evidence"),
    ):
        vals = [d[(s, rule)] for s, _ in arms]
        ax.bar([i + off for i in x], [v[0] for v in vals], width=w, color=colour,
               label=label, zorder=2,
               yerr=[[v[0] - v[1] for v in vals], [v[2] - v[0] for v in vals]],
               error_kw=dict(ecolor=MUTED, lw=0.9, capsize=2))
        # Only the sequential bar is labelled. Fourteen numbers restate the
        # axis; the reader needs the level this paper's rule reaches, and the
        # grey bar beside it supplies the contrast by length.
        if rule == "sequential-score":
            for i, v in enumerate(vals):
                ax.text(i + off, v[2] + 0.025, f"{v[0]:.2f}", ha="center",
                        va="bottom", fontsize=6.2, color=INK)

    ax.set_xticks(list(x))
    ax.set_xticklabels([lab for _, lab in arms], fontsize=7.0, color=INK)
    ax.set_ylabel("Hostile-stream true-positive rate", fontsize=8, color=INK)
    ax.set_ylim(0, 1.14)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    figstyle.grid_y(ax)
    ax.legend(fontsize=7.0, frameon=False, loc="lower left", labelcolor=INK,
              handlelength=1.3, ncol=2, bbox_to_anchor=(0.0, 1.0))

    pooled_r = d.get(("POOLED (seed blocks retain all attack arms)", "two-of-seven"))
    pooled_b = d.get(("POOLED (seed blocks retain all attack arms)",
                      "sequential-score"))
    if pooled_r and pooled_b:
        ax.text(0.995, 0.965,
                f"pooled TPR: {pooled_r[0]:.3f} → {pooled_b[0]:.3f}",
                transform=ax.transAxes, ha="right", va="top", fontsize=6.8,
                color=MUTED)
    style(ax)

    # The selection-protocol proviso is stated in the LaTeX caption; the
    # artwork carries no caption of its own.
    fig.tight_layout(pad=0.4)
    figstyle.assert_no_text_overlap(fig)
    for ext in ("pdf", "png"):
        fig.savefig(args.out / f"fig_ids_ablation.{ext}", dpi=400,
                    bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)

    print(f"wrote {args.out}/fig_ids_ablation.pdf and .png")
    for s, lab in arms:
        r, b = d[(s, "two-of-seven")], d[(s, "sequential-score")]
        print(f"  {s:<12} rule {r[0]:.3f}   sequential {b[0]:.3f}   "
              f"delta {b[0] - r[0]:+.3f}")


if __name__ == "__main__":
    main()
