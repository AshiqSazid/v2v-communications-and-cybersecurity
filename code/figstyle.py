"""Shared figure styling and a layout check the figure scripts run before saving.

Two jobs, both mechanical:

``apply()``
    One font family and one set of type sizes across every figure, and
    TrueType font embedding.  Matplotlib defaults to ``pdf.fonttype=3``
    (Type 3), which IEEE PDF eXpress rejects; 42 embeds TrueType instead.

``assert_no_text_overlap(fig)``
    Renders the figure and compares the extents of every visible text
    artist.  Titles, axis labels, tick labels, legend entries and
    annotations that collide raise ``LayoutError`` instead of being written
    to disk.  Text inside one legend is exempt (a legend's own entries are
    laid out by matplotlib and never collide), as is trivial touching from
    bounding-box padding.

It does not check text against *plotted data* -- bars, curves and markers
have no text extent -- so a figure still needs looking at.
"""
from __future__ import annotations

import matplotlib.pyplot as plt
from matplotlib.legend import Legend
from matplotlib.patches import FancyBboxPatch, Rectangle
from matplotlib.text import Text

# Shared palette. Colour is redundant with position, line style and label in
# every figure, so the set survives grayscale printing.
INK, MUTED, RULE, SURFACE = "#0b0b0b", "#52514e", "#d8d7d3", "#ffffff"

# ---------------------------------------------------------------------------
# Series colours. Okabe--Ito, the colour-vision-deficiency-safe set designed for
# scientific figures, rather than a plotting library's default cycle. Checked
# with a CVD simulator: every adjacent pair used here clears a deuteranopia and
# protanopia separation of dE 11 or better against a white surface, and all
# three clear 3:1 contrast. The previous blue/orange pair was legible but read
# as an untouched default, which is the one thing Rougier's rule 5 ("do not
# trust the defaults") asks a figure not to do.
#
# Roles, not positions. BASE is the comparator and is deliberately achromatic
# so the eye goes to the proposed method; OURS carries this paper's rule; ALT
# is the second state in a before/after pair; THIRD is a rarely needed fourth
# level. Assign by role and never cycle: a reader who learns "grey is the
# baseline" must not meet a grey that means something else two figures later.
BASE   = "#8c8c8c"   # comparator / baseline, intentionally neutral
                     # (lightened from #6f6f6f: at that value it printed to the
                     #  same grey as ALT -- the self-check below catches this)
OURS   = "#0072B2"   # the sequential detector, this paper's method
ALT    = "#D55E00"   # the contrasting state (track keying, "after")
THIRD  = "#009E73"   # fourth level, used only where three are not enough
FAINT  = "#c9c8c4"   # inactive or out-of-scope marks

# Page geometry. Elsevier takes artwork at one of two widths, and anything else
# is rescaled by the typesetter -- which rescales the type with it. 90 mm is the
# single column, 190 mm the full measure.
W1, W2 = 3.54, 7.48
# The width these figures are actually placed at in the submitted manuscript
# (elsarticle 3p review \textwidth = 468 pt). Drawing at exactly this width
# means the typesetter rescales nothing, so 7 pt in the figure prints as 7 pt
# beside 7 pt body text. Regenerate at W2 for the two-column production layout.
WDOC = 6.5

RC = {
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans"],
    "font.size": 7.0,
    "axes.titlesize": 7.6,
    "axes.labelsize": 7.5,
    "xtick.labelsize": 6.6,
    "ytick.labelsize": 6.6,
    "legend.fontsize": 6.4,
    "axes.linewidth": 0.8,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
}


# Minimum visible separation between neighbouring box borders, in figure
# pixels at the default 100 dpi canvas -- about 0.03 in on the page.
MIN_BOX_GAP_PX = 3.0


class LayoutError(AssertionError):
    """Two pieces of text in the figure overlap."""


def apply() -> None:
    plt.rcParams.update(RC)


def _visible_texts(fig):
    """-> [(text, extent, owning legend id or None)] for non-empty text."""
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    legend_of = {
        id(text): id(legend)
        for legend in fig.findobj(Legend)
        for text in legend.findobj(Text)
    }
    found = []
    for text in fig.findobj(Text):
        if not text.get_visible() or not text.get_text().strip():
            continue
        # A diagonal label reports the axis-aligned box around its rotated
        # glyphs, which is far bigger than the ink -- neighbouring 38-degree
        # tick labels "overlap" by that measure while looking fine. Only
        # upright and quarter-turned text is checked; oblique text is left to
        # the eye.
        if text.get_rotation() % 90 != 0:
            continue
        extent = text.get_window_extent(renderer)
        if extent.width <= 0 or extent.height <= 0:
            continue
        found.append((text, extent, legend_of.get(id(text))))
    return found


def assert_no_text_overlap(fig, *, tolerance: float = 0.06) -> None:
    """Raise if two text artists overlap by more than `tolerance` of the smaller.

    A little slack is needed: rotated text reports an axis-aligned extent that
    is larger than the glyphs, and adjacent labels routinely share a pixel of
    padding without touching visually.
    """
    items = _visible_texts(fig)
    collisions = []
    for index, (text_a, box_a, legend_a) in enumerate(items):
        for text_b, box_b, legend_b in items[index + 1:]:
            if legend_a is not None and legend_a == legend_b:
                continue
            overlap = _intersection_area(box_a, box_b)
            if overlap <= 1.0:
                continue
            smaller = min(box_a.width * box_a.height, box_b.width * box_b.height)
            if smaller <= 0 or overlap / smaller <= tolerance:
                continue
            collisions.append(
                f"  {overlap / smaller:5.0%} overlap: "
                f"{_describe(text_a, box_a)}  <->  {_describe(text_b, box_b)}"
            )
    if collisions:
        raise LayoutError(
            f"{len(collisions)} overlapping text pair(s):\n" + "\n".join(collisions)
        )


def assert_boxes_clean(fig) -> None:
    """Raise if drawn boxes overlap each other, or if text straddles a border.

    The schematic figures are built from ``FancyBboxPatch`` cells whose
    ``boxstyle`` pad pushes the stroked border outside the rectangle passed in,
    so two boxes can collide while their nominal rectangles look well separated.
    Text is required to be wholly inside a box or wholly outside it; a label
    lying across a border is the other failure this catches.
    """
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()

    boxes = []
    for patch in fig.findobj(lambda o: isinstance(o, (FancyBboxPatch, Rectangle))):
        if not patch.get_visible():
            continue
        edge = patch.get_edgecolor()
        if len(edge) == 4 and edge[3] == 0:      # unstroked fill: no border to hit
            continue
        extent = patch.get_window_extent(renderer)
        if extent.width < 5 or extent.height < 5:
            continue
        if (extent.width > 0.98 * fig.bbox.width
                and extent.height > 0.98 * fig.bbox.height):
            continue                              # the figure background
        boxes.append((patch, extent))

    problems = []
    for index, (_, box_a) in enumerate(boxes):
        for _, box_b in boxes[index + 1:]:
            if _contains(box_a, box_b) or _contains(box_b, box_a):
                continue
            area = _intersection_area(box_a, box_b)
            if area > 1.0:
                problems.append(
                    f"  boxes overlap by {area:.0f}px^2 at "
                    f"({max(box_a.x0, box_b.x0):.0f},{max(box_a.y0, box_b.y0):.0f})"
                )
                continue
            # Abutting borders read as one thick seam and never register as
            # overlap, so neighbours must also be visibly apart.
            gap = _separation(box_a, box_b)
            if gap is not None and gap < MIN_BOX_GAP_PX:
                problems.append(
                    f"  boxes only {gap:.1f}px apart at "
                    f"({min(box_a.x1, box_b.x1):.0f},"
                    f"{max(box_a.y0, box_b.y0):.0f}) -- borders touch"
                )
    for text, extent, _ in _visible_texts(fig):
        for _, box in boxes:
            if _contains(box, extent) or _intersection_area(extent, box) == 0:
                continue
            problems.append(
                f"  {_describe(text, extent)} lies across a box border"
            )
    if problems:
        raise LayoutError(
            f"{len(problems)} box-geometry problem(s):\n" + "\n".join(problems)
        )


def _separation(box_a, box_b):
    """Edge-to-edge gap in px for boxes that face each other, else None.

    Only pairs whose projections overlap on one axis are "neighbours" on the
    other; two boxes on a diagonal are not sharing a seam and are ignored.
    """
    overlap_x = min(box_a.x1, box_b.x1) - max(box_a.x0, box_b.x0) > 0
    overlap_y = min(box_a.y1, box_b.y1) - max(box_a.y0, box_b.y0) > 0
    if overlap_y and not overlap_x:
        return max(box_a.x0, box_b.x0) - min(box_a.x1, box_b.x1)
    if overlap_x and not overlap_y:
        return max(box_a.y0, box_b.y0) - min(box_a.y1, box_b.y1)
    return None


def _contains(outer, inner) -> bool:
    return (inner.x0 >= outer.x0 and inner.x1 <= outer.x1
            and inner.y0 >= outer.y0 and inner.y1 <= outer.y1)


def _intersection_area(box_a, box_b) -> float:
    width = min(box_a.x1, box_b.x1) - max(box_a.x0, box_b.x0)
    height = min(box_a.y1, box_b.y1) - max(box_a.y0, box_b.y0)
    return width * height if width > 0 and height > 0 else 0.0


def _describe(text, box) -> str:
    label = " ".join(text.get_text().split())
    if len(label) > 34:
        label = label[:31] + "..."
    return f"{label!r} at ({box.x0:.0f},{box.y0:.0f})"



def despine(ax, *, keep=("left", "bottom")) -> None:
    """Drop the box, leave hairline rules on the axes that carry a scale."""
    for side in ("top", "right", "left", "bottom"):
        if side in keep:
            ax.spines[side].set_color(RULE)
            ax.spines[side].set_linewidth(0.6)
        else:
            ax.spines[side].set_visible(False)
    ax.tick_params(colors=MUTED, length=2.5, width=0.6)
    ax.set_axisbelow(True)


def grid_y(ax) -> None:
    """One hairline horizontal grid, behind the data, never dashed.

    Dashes add texture that competes with the marks; at 0.5 pt a solid rule
    reads as a guide and disappears when you stop looking for it.
    """
    ax.grid(axis="y", color=RULE, lw=0.5, zorder=0)
    ax.grid(axis="x", visible=False)


def _demo_palette() -> None:
    """Self-check: roles are distinct, and distinct once converted to grey."""
    def luma(h):
        r, g, b = (int(h[i:i + 2], 16) / 255 for i in (1, 3, 5))
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    roles = {"BASE": BASE, "OURS": OURS, "ALT": ALT, "THIRD": THIRD}
    assert len(set(roles.values())) == len(roles), "two roles share a colour"
    greys = sorted(luma(c) for c in roles.values())
    gaps = [b - a for a, b in zip(greys, greys[1:])]
    assert min(gaps) > 0.03, f"two roles collapse in greyscale: {gaps}"
    assert W1 < W2, "column widths out of order"
    print("figstyle palette self-check passed")

def _demo() -> None:
    """Self-check: the detector fires on a collision and stays quiet without one."""
    fig, ax = plt.subplots(figsize=(3, 2))
    ax.text(0.5, 0.5, "first label", ha="center")
    ax.text(0.5, 0.5, "second label", ha="center")
    try:
        assert_no_text_overlap(fig)
    except LayoutError as error:
        assert "overlap" in str(error), error
    else:
        raise AssertionError("stacked labels were not reported")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(3, 2))
    ax.text(0.1, 0.9, "top left", ha="left")
    ax.text(0.9, 0.1, "bottom right", ha="right")
    assert_no_text_overlap(fig)
    plt.close(fig)
    _demo_palette()
    print("figstyle self-check passed")


if __name__ == "__main__":
    _demo()
