#!/usr/bin/env python3
"""Render the ground-truth label figure for the paper.

    python3 make_labels_figure.py

Writes fig_labels.pdf (vector, for LaTeX) and .png (preview) to figures/.

This figure answers reviewer point 7: the receiver-identity pair is the
evaluation unit, but under impersonation one logical identity carries both
genuine and forged transmissions, so the pair labels are not self-evident.

Two things must come across, because both are load-bearing for the results:
  * the labels are two orthogonal binary facts -- who owns the identity, and
    whether the stream carried a malicious message -- not a single spectrum;
  * the labels are properties of the whole window W, so the "transition" is
    the moment the defining event enters W, not a per-message state change.

Design constraints match the other figure scripts: legible at IEEE full width,
colour redundant with position and label so it survives grayscale and CVD.
Layout uses explicit non-overlapping bands; every y is declared once below.
"""
import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle

import figstyle
from figstyle import INK, MUTED, SURFACE

DEFAULT_OUT = Path(__file__).resolve().parent / "figures"

RULE = "#b8b7b2"      # heavier than the shared rule: these are box borders
BASE = "#0072B2"      # identity-keyed path (the baseline being critiqued)
ACCENT = "#D55E00"    # the victim-exposed case (the contribution's target)
WASH = "#faf9f7"

# Y_BOTTOM crops the strip left by the two caption paragraphs that used to sit
# below the panels; they are now in the LaTeX caption. Height scales with the
# crop so everything above keeps its size on the page and no other constant in
# this file has to move.
Y_BOTTOM = 0.285
SPAN_H = 3.90                                  # inches one full y unit spans
FIG_W, FIG_H = 7.16, SPAN_H * (1.0 - Y_BOTTOM)
TITLE_PT, BODY_PT = 6.5, 6.3
# One text line, in y units. Cell contents are stacked downwards from the top
# edge with these, so a two-line title can never land on the body below it.
# Divided by SPAN_H, not FIG_H: y still runs on the uncropped scale, so a line
# is the same fraction of it whether or not the bottom strip is shown.
TITLE_LINE = TITLE_PT * 1.30 / 72 / SPAN_H
BODY_LINE = BODY_PT * 1.34 / 72 / SPAN_H

# ---- panel A geometry ----
# Cell width is set by the widest body line (~0.162 of the figure) plus a
# margin; the row-label column is squeezed to the width of "is an attacker".
#
# CELL_PAD below is the boxstyle pad: every border is drawn that far OUTSIDE
# the rectangle given to cell(). Neighbouring cells must therefore be separated
# by more than 2*CELL_PAD or their borders intersect -- which is invisible in
# the numbers and obvious on the page. Column gap 0.024 and row gap 0.026 both
# clear it.
CELL_PAD = 0.008
A_LBL_R = 0.074                     # right edge of the row-label column
A_C1, A_C2, A_CW = 0.094, 0.294, 0.176
A_ROW1, A_ROW2, A_RH = 0.570, 0.314, 0.230
A_HEAD = 0.845
# ---- panel B geometry ----
B_LBL_R = 0.660                     # right edge of the lane-label column
B_T0, B_T1 = 0.678, 0.984
B_LANE_O, B_LANE_A = 0.792, 0.694
B_TOP, B_BOT = 0.850, 0.650
# The keying rows are not on the timeline, so they start further left and
# give their boxes room the timeline column cannot.
K_LBL_R, K_L, K_R = 0.578, 0.600, 0.984
KEY_PAD, KEY_GAP = 0.006, 0.024   # gap must exceed 2*KEY_PAD, see below


def cell(ax, x, y, w, h, title, body, edge=RULE, lw=1.0):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle=f"round,pad={CELL_PAD},rounding_size=0.015",
        linewidth=lw, edgecolor=edge, facecolor=SURFACE, zorder=2))
    top = y + h - 0.026
    ax.text(x + w / 2, top, title, ha="center", va="top",
            fontsize=TITLE_PT, color=INK, fontweight="bold", zorder=3,
            linespacing=1.30)
    ax.text(x + w / 2, top - (title.count("\n") + 1) * TITLE_LINE - 0.014,
            body, ha="center", va="top", fontsize=BODY_PT, color=MUTED,
            zorder=3, linespacing=1.34)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    figstyle.apply()

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    ax.set_xlim(0, 1)
    ax.set_ylim(Y_BOTTOM, 1)
    ax.axis("off")

    # ================= (A) the label matrix =================================
    ax.text(0.012, 0.982, "(A)  Pair labels are two orthogonal facts",
            fontsize=7.2, color=INK, ha="left", va="center", fontweight="bold")
    # Wrapped so the subtitle stays inside panel A's column, left of the rule.
    ax.text(0.012, 0.960,
            "evaluated over the whole window $W$, for one\n"
            "(receiver $r$, claimed identity $i$) pair",
            fontsize=6.2, color=MUTED, ha="left", va="top", linespacing=1.26)

    ax.text(A_C1 + A_CW / 2, A_HEAD, "$M(r,i)$ contains a\nmalicious message",
            fontsize=6.0, color=INK, ha="center", va="center", linespacing=1.28)
    ax.text(A_C2 + A_CW / 2, A_HEAD, "$M(r,i)$ contains\nnone",
            fontsize=6.0, color=INK, ha="center", va="center", linespacing=1.28)

    ax.text(A_LBL_R, A_ROW1 + A_RH / 2, "owner of $i$\nis honest",
            fontsize=6.0, color=INK, ha="right", va="center", linespacing=1.28)
    ax.text(A_LBL_R, A_ROW2 + A_RH / 2, "owner of $i$\nis an attacker",
            fontsize=6.0, color=INK, ha="right", va="center", linespacing=1.28)

    cell(ax, A_C1, A_ROW1, A_CW, A_RH, "VICTIM-EXPOSED",
         "hostile stream under an\nhonest key. An alert is a\n"
         "correct detection but a\nfalse owner attribution.",
         edge=ACCENT, lw=1.6)
    cell(ax, A_C2, A_ROW1, A_CW, A_RH, "CLEAN\nHONEST-OWNER",
         "the strict denominator\nfor the reported clean\nfalse-alarm rate.",
         edge=BASE, lw=1.3)
    cell(ax, A_C1, A_ROW2, A_CW, A_RH, "HOSTILE STREAM,\nOWNED BY ATTACKER",
         "both labels are correct:\nthe stream is hostile and\nthe owner is an attacker.")
    cell(ax, A_C2, A_ROW2, A_CW, A_RH, "NON-HOSTILE STREAM",
         "negative class. An empty-\nbuffer replayer sends\nbenign messages.")

    ax.plot([0.492, 0.492], [0.295, 0.945], color=RULE, lw=0.7, ls=(0, (3, 3)))

    # ================= (B) the transition during spoofing ===================
    ax.text(0.512, 0.968, "(B)  What changes when a spoofer claims $i$",
            fontsize=7.2, color=INK, ha="left", va="center", fontweight="bold")

    def T(t):
        return B_T0 + t * (B_T1 - B_T0)

    ta, guard = 0.44, 0.11
    wstart = ta + guard

    ax.add_patch(Rectangle((T(wstart), B_BOT), T(1.0) - T(wstart),
                           B_TOP - B_BOT, facecolor=WASH, edgecolor="none",
                           zorder=0))
    ax.plot([T(wstart), T(wstart)], [B_BOT, B_TOP], color=MUTED, lw=0.8)
    ax.text(T(wstart) + 0.005, 0.872, "$W$ starts", fontsize=6.3, color=MUTED,
            ha="left", va="center")
    ax.text(T(1.0), 0.872, "$T$", fontsize=6.3, color=MUTED,
            ha="right", va="center")
    ax.plot([T(ta), T(ta)], [B_BOT, B_TOP], color=ACCENT, lw=1.0,
            ls=(0, (2, 2)))
    ax.text(T(ta), 0.918, "$t_a$ spoofer starts", fontsize=6.5, color=ACCENT,
            ha="center", va="center", fontweight="bold")

    def lane(y, label, colour, t_from, marker):
        ax.text(B_LBL_R, y, label, fontsize=6.5, color=INK,
                ha="right", va="center", linespacing=1.28)
        ts = [x / 22 for x in range(1, 22) if x / 22 >= t_from]
        ax.plot([T(t) for t in ts], [y] * len(ts), marker, color=colour,
                markersize=2.5, linestyle="none", zorder=3)

    lane(B_LANE_O, "honest owner $O$\nsends under $i$", BASE, 0.0, "o")
    lane(B_LANE_A, "spoofer $A$\nsends under $i$", ACCENT, ta, "^")

    ax.annotate("", xy=(T(wstart), 0.622), xytext=(T(ta), 0.622),
                arrowprops=dict(arrowstyle="<->", color=MUTED, lw=0.7))
    ax.text((T(ta) + T(wstart)) / 2, 0.590, "guard $g$", fontsize=6.1,
            color=MUTED, ha="center", va="center")

    ax.plot([0.512, B_T1], [0.548, 0.548], color=RULE, lw=0.6)

    k_mid = (K_L + K_R) / 2
    ax.text(K_LBL_R, 0.480, "identity\nkeying", fontsize=6.5, color=BASE,
            ha="right", va="center", fontweight="bold", linespacing=1.28)
    ax.add_patch(FancyBboxPatch(
        (K_L, 0.442), K_R - K_L, 0.078,
        boxstyle="round,pad=0.006,rounding_size=0.012",
        linewidth=1.3, edgecolor=BASE, facecolor=SURFACE, zorder=2))
    ax.text(k_mid, 0.480,
            "one accumulator for $i$ -- $O$'s and $A$'s evidence merge",
            fontsize=6.5, color=INK, ha="center", va="center", zorder=3)

    # Two boxes split the same span. The gap between the rectangles has to
    # exceed 2*KEY_PAD or the two borders land on the same pixel and read as
    # one seam, which is invisible in these numbers.
    half = (K_R - K_L - KEY_GAP) / 2
    left_end, right_start = K_L + half, K_L + half + KEY_GAP
    ax.text(K_LBL_R, 0.356, "track\nkeying", fontsize=6.5, color=ACCENT,
            ha="right", va="center", fontweight="bold", linespacing=1.28)
    ax.add_patch(FancyBboxPatch(
        (K_L, 0.318), half, 0.078,
        boxstyle=f"round,pad={KEY_PAD},rounding_size=0.012",
        linewidth=1.3, edgecolor=BASE, facecolor=SURFACE, zorder=2))
    ax.text((K_L + left_end) / 2, 0.356, "$O$'s track: stays clean",
            fontsize=6.4, color=INK, ha="center", va="center", zorder=3)
    ax.add_patch(FancyBboxPatch(
        (right_start, 0.318), half, 0.078,
        boxstyle=f"round,pad={KEY_PAD},rounding_size=0.012",
        linewidth=1.3, edgecolor=ACCENT, facecolor=SURFACE, zorder=2))
    ax.text((right_start + K_R) / 2, 0.356, "$A$'s track: accumulates",
            fontsize=6.4, color=INK, ha="center", va="center", zorder=3)

    fig.tight_layout(pad=0.15)
    figstyle.assert_no_text_overlap(fig)
    figstyle.assert_boxes_clean(fig)
    for ext in ("pdf", "png"):
        fig.savefig(args.out / f"fig_labels.{ext}", dpi=400, facecolor=SURFACE)
    print(f"wrote {args.out}/fig_labels.pdf and .png")


if __name__ == "__main__":
    main()
