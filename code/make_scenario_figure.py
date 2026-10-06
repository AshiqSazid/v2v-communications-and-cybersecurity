#!/usr/bin/env python3
"""Render the V2V system-and-threat-model figure.

    python3 make_scenario_figure.py

Writes figures/fig_scenario.pdf (vector, for LaTeX) and .png (preview).

Shows one BSM exchange between two vehicles AND an impersonator transmitting
under the sender's identity, because that collision is what the paper is
about. A figure showing only "vehicle A talks to vehicle B" would restate the
two-node demonstration the work has moved past.

Colour convention is shared with fig_methodology: blue = the honest/claimed
identity path, orange = the adversary and the proposed handling of it. Colour
is redundant with line style and label, so the figure survives grayscale.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Arc, FancyArrowPatch, FancyBboxPatch, Polygon

import figstyle
from figstyle import INK, MUTED, SURFACE

OUT = Path(__file__).resolve().parent / "figures"

RULE = "#b8b7b2"          # heavier than the shared rule: these are box borders
ROAD = "#eeedea"
HONEST = "#0072B2"
ADVERSARY = "#D55E00"

# ---- vertical bands, declared once so nothing has to be eyeballed ----
# Y_BOTTOM crops the empty strip left by the caption sentence that used to sit
# under the road. Height scales with it, so every element keeps its size on the
# page and none of the layout constants below have to move.
Y_BOTTOM = 0.090
FIG_H = 3.05 * (1.0 - Y_BOTTOM)
BOX_TOP = 0.880                       # shared top edge of all three boxes
PACKET_BOT, ATB_BOT = 0.590, 0.520    # the collision panel runs deeper
ROAD_Y, CAR_Y = 0.185, 0.222
DROP_TO = 0.500                       # where the box-to-vehicle arrows stop
ARC_Y = 0.300                         # transmissions leave and arrive here


def car(ax, x, y, w=0.088, h=0.040, color=INK, label=None, sub=None,
        flip=False):
    """A simple side-view vehicle silhouette."""
    body = [
        (x, y), (x + w, y), (x + w, y + h * 0.55),
        (x + w * 0.72, y + h * 0.55), (x + w * 0.58, y + h),
        (x + w * 0.30, y + h), (x + w * 0.17, y + h * 0.55),
        (x, y + h * 0.55),
    ]
    if flip:
        body = [(2 * x + w - bx, by) for bx, by in body]
    ax.add_patch(Polygon(body, closed=True, facecolor=SURFACE,
                         edgecolor=color, linewidth=1.6, zorder=3,
                         joinstyle="round"))
    for cx in (x + w * 0.24, x + w * 0.76):
        ax.add_patch(plt.Circle((cx, y), h * 0.17, facecolor=color,
                                edgecolor=color, zorder=4))
    if label:
        ax.text(x + w / 2, y - 0.052, label, ha="center", va="center",
                fontsize=7.0, color=INK, fontweight="bold", zorder=5)
    if sub:
        ax.text(x + w / 2, y - 0.098, sub, ha="center", va="center",
                fontsize=6.1, color=MUTED, zorder=5)


def waves(ax, x, y, color, n=3, r0=0.030, dr=0.020, t1=25, t2=155, ls="-"):
    for i in range(n):
        r = r0 + i * dr
        ax.add_patch(Arc((x, y), r * 2, r * 2 * 0.62, angle=0,
                         theta1=t1, theta2=t2, edgecolor=color,
                         linewidth=1.1, linestyle=ls, zorder=2, alpha=0.85))


def packet(ax, x, y, w, h, title, lines, edge, title_color=None):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.010,rounding_size=0.014",
        linewidth=1.2, edgecolor=edge, facecolor=SURFACE, zorder=6))
    ax.text(x + w / 2, y + h - 0.042, title, ha="center", va="center",
            fontsize=6.8, color=title_color or edge, fontweight="bold",
            zorder=7)
    ax.text(x + w / 2, y + h / 2 - 0.040, lines, ha="center", va="center",
            fontsize=6.2, color=INK, zorder=7, linespacing=1.5,
            family="DejaVu Sans Mono")


def main():
    OUT.mkdir(exist_ok=True)
    figstyle.apply()
    fig, ax = plt.subplots(figsize=(figstyle.WDOC, FIG_H))
    ax.set_xlim(0, 1)
    ax.set_ylim(Y_BOTTOM, 1)
    ax.axis("off")

    # ---- road -----------------------------------------------------------
    ax.add_patch(FancyBboxPatch((0.02, ROAD_Y), 0.96, 0.145,
                                boxstyle="square,pad=0",
                                facecolor=ROAD, edgecolor="none", zorder=0))
    for x in range(4, 96, 7):
        ax.plot([x / 100, x / 100 + 0.030], [ROAD_Y + 0.0725] * 2,
                color=SURFACE, lw=1.6, zorder=1, solid_capstyle="butt")

    # ---- vehicles -------------------------------------------------------
    car(ax, 0.062, CAR_Y, color=HONEST, label="Vehicle A  (honest sender)",
        sub="broadcasts its own state at 10 Hz")
    car(ax, 0.428, CAR_Y, color=ADVERSARY, label="Vehicle M  (adversary)",
        sub="transmits under A's identity")
    car(ax, 0.815, CAR_Y, color=INK, label="Vehicle B  (receiver)",
        sub="runs the detector", flip=True)

    # ---- transmissions --------------------------------------------------
    # `rad` is applied in display space, so the apex of an arc rises
    # rad * chord_inches / 2 inches above the chord. Both are kept flat
    # enough that the apex stays below DROP_TO and clear of the boxes.
    ax.add_patch(FancyArrowPatch((0.152, ARC_Y), (0.856, ARC_Y + 0.010),
                                 arrowstyle="-|>", mutation_scale=9,
                                 color=HONEST, lw=1.4, zorder=2,
                                 connectionstyle="arc3,rad=-0.17"))
    ax.add_patch(FancyArrowPatch((0.516, ARC_Y - 0.012), (0.828, ARC_Y - 0.022),
                                 arrowstyle="-|>", mutation_scale=9,
                                 color=ADVERSARY, lw=1.4, zorder=2,
                                 linestyle=(0, (3, 2)),
                                 connectionstyle="arc3,rad=-0.26"))

    # ---- the two messages -----------------------------------------------
    packet(ax, 0.030, PACKET_BOT, 0.250, BOX_TOP - PACKET_BOT,
           "genuine BSM",
           "id      = A\ntime    = t\nposition= true\nvelocity= true",
           HONEST)
    packet(ax, 0.322, PACKET_BOT, 0.250, BOX_TOP - PACKET_BOT,
           "forged BSM",
           "id      = A   ← forged\ntime    = t\nposition= false\nvelocity= false",
           ADVERSARY)

    for x0 in (0.155, 0.447):
        ax.add_patch(FancyArrowPatch((x0, PACKET_BOT), (x0, DROP_TO),
                                     arrowstyle="-|>", mutation_scale=7,
                                     color=RULE, lw=0.9, zorder=1))

    # ---- the collision at the receiver ----------------------------------
    # Four bands inside the panel: heading, consequence, rule, alternative.
    ax.add_patch(FancyBboxPatch(
        (0.612, ATB_BOT), 0.368, BOX_TOP - ATB_BOT,
        boxstyle="round,pad=0.012,rounding_size=0.018",
        linewidth=1.2, edgecolor=RULE, facecolor="#faf9f7", zorder=2))
    ax.text(0.796, 0.842, "At B: both arrive claiming \"A\"",
            ha="center", va="center", fontsize=7.0, color=INK,
            fontweight="bold", zorder=3)
    # Terse labels for the two keyings. The sentences these replace read as
    # caption prose and now live in the LaTeX caption.
    ax.text(0.796, 0.740,
            "identity keying: one shared state,\n"
            "the penalty lands on A",
            ha="center", va="center", fontsize=6.4, color=MUTED,
            zorder=3, linespacing=1.5)
    ax.plot([0.634, 0.958], [0.648, 0.648], color=RULE, lw=0.7, zorder=3)
    ax.text(0.796, 0.586,
            "track keying: two trajectories,\n"
            "A stays clean",
            ha="center", va="center", fontsize=6.4, color=ADVERSARY,
            zorder=3, linespacing=1.5)

    # Starts outside the forged-BSM border (right edge 0.572 plus its pad).
    ax.add_patch(FancyArrowPatch((0.588, 0.730), (0.612, 0.730),
                                 arrowstyle="-|>", mutation_scale=7,
                                 color=RULE, lw=0.9, zorder=1))

    fig.tight_layout(pad=0.12)
    figstyle.assert_no_text_overlap(fig)
    figstyle.assert_boxes_clean(fig)
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"fig_scenario.{ext}", dpi=400, facecolor=SURFACE)
    print(f"wrote {OUT}/fig_scenario.pdf and .png")


if __name__ == "__main__":
    main()
