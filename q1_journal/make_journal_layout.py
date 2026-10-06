#!/usr/bin/env python3
"""Emit the two-column journal-layout build from the VehCom source.

    python3 make_journal_layout.py            # -> manuscript_vehcom_journal.tex
    python3 make_journal_layout.py --selfcheck

manuscript_vehcom.tex is authored in elsarticle `review,3p` -- single column,
1.5-spaced, line-numbered, which is what Elsevier referees read. This script
produces the `final,5p,twocolumn` build instead: the typeset journal look that
Elsevier's own main.tex renders, single-spaced and two-column.

Three things have to change together, which is why this is a script and not a
one-line option swap:

  * the class options;
  * the floats -- the body is authored at a single-column measure, so every
    table has to become a column-spanning table* or it overflows into the
    gutter (reuses widen_for_twocolumn from make_variants.py);
  * \\linenumbers -- it sits after \\end{frontmatter}, and line numbers are a
    review aid that the journal layout does not carry.

The highlights environment is also dropped: in 5p it typesets as a near-empty
prelim page, and Elsevier wants Highlights uploaded as its own file anyway
(highlights.txt ships beside this script).
"""
import argparse
import re
import sys
from pathlib import Path

from make_variants import widen_for_twocolumn

HERE = Path(__file__).resolve().parent
SRC = HERE / "manuscript_vehcom.tex"

REVIEW_CLASS = "\\documentclass[review,3p,times]{elsarticle}"
JOURNAL_CLASS = "\\documentclass[final,5p,times,twocolumn]{elsarticle}"


def to_journal_layout(tex):
    if REVIEW_CLASS not in tex:
        raise SystemExit(f"error: expected {REVIEW_CLASS} in the source")
    tex = tex.replace(REVIEW_CLASS, JOURNAL_CLASS)
    # Line numbers are a review aid; the journal layout carries none.
    tex = re.sub(r"(?m)^\\linenumbers\s*$", "%\\\\linenumbers  % review-only",
                 tex)
    # In 5p the highlights prelim page typesets nearly empty; Elsevier takes
    # Highlights as a separate upload regardless.
    tex = re.sub(r"\n\\begin\{highlights\}.*?\\end\{highlights\}\n",
                 "\n%% Highlights ship as highlights.txt, per Elsevier.\n",
                 tex, flags=re.S)
    # The float transform applies to the body only -- the frontmatter has no
    # floats and \columnwidth there means the full measure.
    cut = tex.find("\\end{frontmatter}")
    if cut < 0:
        raise SystemExit("error: no \\end{frontmatter} in the source")
    cut += len("\\end{frontmatter}")
    return tex[:cut] + widen_for_twocolumn(tex[cut:])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path,
                    default=HERE / "manuscript_vehcom_journal.tex")
    args = ap.parse_args()
    args.out.write_text(to_journal_layout(SRC.read_text()))
    print(f"wrote {args.out.name}")


def _selfcheck():
    src = (REVIEW_CLASS + "\n\\usepackage{lineno}\n"
           "\\begin{document}\\begin{frontmatter}\n"
           "\\begin{highlights}\\item one\\end{highlights}\n"
           "\\end{frontmatter}\n\\linenumbers\n"
           "\\begin{table}[h]\\begin{tabularx}{\\columnwidth}{Y}a"
           "\\end{tabularx}\\end{table}\n")
    out = to_journal_layout(src)
    assert JOURNAL_CLASS in out and REVIEW_CLASS not in out
    assert "\n%\\linenumbers" in out, "linenumbers not commented"
    assert "\\begin{highlights}" not in out, "highlights not removed"
    assert "\\begin{table*}[t]" in out, "float not promoted"
    assert "\\columnwidth" not in out, "columnwidth not widened"
    # the frontmatter must be left alone
    assert out.count("\\end{frontmatter}") == 1
    print("selfcheck ok")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        _selfcheck()
    else:
        main()
