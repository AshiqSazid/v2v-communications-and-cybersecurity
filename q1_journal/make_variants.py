#!/usr/bin/env python3
"""Generate the IEEE and APA manuscript variants from the VehCom source.

    python3 make_variants.py            # writes manuscript_ieee.tex, manuscript_apa.tex
    python3 make_variants.py --selfcheck

manuscript_vehcom.tex is the single source of truth. The variants differ only in
preamble, title block and bibliography style -- the body is byte-identical apart
from the citation command APA needs.

This exists because the three files were maintained by hand and drifted: the
IEEE and APA copies still carried the superseded "weights buy nothing" abstract
after the paired contrast overturned it, and were missing 356 lines of results.
Regenerating is cheaper than diffing three 100 KB files by eye.

The venue preambles are lifted verbatim from the existing variants (they are
venue scaffolding, not content) and cached beside this script, so a future run
does not depend on the generated files it is about to overwrite.
"""
import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "manuscript_vehcom.tex"


def split_source(tex):
    """-> (frontmatter, body) where body runs to just before \\bibliographystyle."""
    fm = re.search(r"\\begin\{frontmatter\}(.*?)\\end\{frontmatter\}", tex, re.S)
    if not fm:
        raise SystemExit("error: no frontmatter block in " + str(SRC))
    after = tex[fm.end():]
    cut = after.find("\\bibliographystyle")
    if cut < 0:
        raise SystemExit("error: no \\bibliographystyle in " + str(SRC))
    return fm.group(1), after[:cut].strip()


def field(fm, name):
    m = re.search(r"\\" + name + r"\{(.*?)\n?\}\n", fm, re.S)
    return m.group(1).strip() if m else None


def environ(fm, name):
    m = re.search(r"\\begin\{" + name + r"\}(.*?)\\end\{" + name + r"\}", fm, re.S)
    return m.group(1).strip() if m else None


def keywords(fm):
    kw = environ(fm, "keyword")
    if not kw:
        return []
    return [k.strip() for k in kw.replace("\n", " ").split("\\sep") if k.strip()]


def author_name(fm):
    m = re.search(r"\\author\[[^\]]*\]\{([^\\}]+)", fm)
    return m.group(1).strip() if m else "Author"


def affiliation_lines(fm):
    """The affiliation fields in source order, TODOs included so they stay visible."""
    m = re.search(r"\\affiliation\[[^\]]*\]\{(.*?)\n?\}\n", fm, re.S)
    if not m:
        return []
    return [v.strip() for v in re.findall(r"=\{([^}]*)\}", m.group(1))]


def widen_for_twocolumn(body):
    """Make the single-column body survive IEEEtran's two-column measure.

    The shared body is authored at the VehCom single-column measure, where
    \\columnwidth is the full text width. In a two-column class it is half that,
    so every table sized to it overflows -- worst case 54pt into the gutter.
    Promoting the floats to the starred (column-spanning) form restores the
    measure they were written for.
    """
    body = re.sub(r"\\begin\{table\}\[[^\]]*\]", r"\\begin{table*}[t]", body)
    body = re.sub(r"\\begin\{table\}(?!\*)", r"\\begin{table*}[t]", body)
    body = body.replace("\\end{table}", "\\end{table*}")
    # Inside a spanning float \columnwidth is still the narrow column.
    body = re.sub(r"(\\begin\{(?:tabular|tabularx)\}(?:\{[^}]*\})?\{[^}]*?)\\columnwidth",
                  lambda m: m.group(1) + "\\textwidth", body)
    body = body.replace("{\\columnwidth}", "{\\textwidth}")
    body = body.replace("\\parbox{\\columnwidth}", "\\parbox{\\textwidth}")
    # A figure placed at its native width can exceed the narrow column.
    body = re.sub(r"\\includegraphics\{", r"\\includegraphics[width=\\columnwidth]{", body)
    return body


def ieee_title_break(title, limit=60):
    """Break a long title at the word boundary nearest its midpoint.

    IEEEtran sets the title in a narrow block. This used to hardcode the break
    after "Detection:" and "Prioritisation,", which silently became a no-op the
    moment the title changed -- so it is computed from the text instead.
    """
    title = " ".join(title.split())
    if len(title) <= limit:
        return title
    mid = len(title) / 2
    spaces = [i for i, c in enumerate(title) if c == " "]
    if not spaces:
        return title
    cut = min(spaces, key=lambda i: abs(i - mid))
    return title[:cut] + "\\\\" + title[cut + 1:]

def ieee_variant(preamble, fm, body):
    title = field(fm, "title").replace("\n", " ")
    title = ieee_title_break(title)
    aff = ", ".join(affiliation_lines(fm)) or "Affiliation"
    email = field(fm, "ead") or ""
    kw = ", ".join(keywords(fm))
    body = widen_for_twocolumn(body)
    head = (
        f"\\title{{{title}}}\n\n"
        f"\\author{{\\IEEEauthorblockN{{{author_name(fm)}}}\n"
        f"\\IEEEauthorblockA{{{aff}\\\\\n{email}}}}}\n\n"
        "\\maketitle\n\n"
        f"\\begin{{abstract}}\n{environ(fm, 'abstract')}\n\\end{{abstract}}\n\n"
        f"\\begin{{IEEEkeywords}}\n{kw}\n\\end{{IEEEkeywords}}\n"
    )
    return f"{preamble}\n\n{head}\n{body}\n\n\\bibliographystyle{{IEEEtran}}\n\\bibliography{{refs}}\n\n\\end{{document}}\n"


def apa_variant(preamble, fm, body):
    title = field(fm, "title").replace("\n", " ")
    aff = ", ".join(affiliation_lines(fm)) or "Affiliation"
    kw = ", ".join(keywords(fm))
    head = (
        "\\begin{titlepage}\n\\thispagestyle{apaheadings}\n\\vspace*{2in}\n"
        f"\\begin{{center}}\n\\textbf{{{title}}}\n\n"
        f"\\vspace{{2\\baselineskip}}\n{author_name(fm)}\n\n{aff}\n"
        "\\end{center}\n\\vfill\n\\end{titlepage}\n\n"
        "\\setcounter{page}{2}\n\\begin{center}\n\\textbf{Abstract}\n\\end{center}\n"
        "\\begingroup\n\\setlength{\\parindent}{0pt}\n"
        f"{environ(fm, 'abstract')}\n\\par\n\\vspace{{\\baselineskip}}\n"
        f"\\textit{{Keywords:}} {kw}\n\\endgroup\n"
    )
    # apalike is author-year: \citep gives the parenthetical form \cite does not.
    body = re.sub(r"\\cite\{", r"\\citep{", body)
    return f"{preamble}\n\n{head}\n{body}\n\n\\bibliographystyle{{apalike}}\n\\bibliography{{refs}}\n\n\\end{{document}}\n"


def cached_preamble(variant):
    """Preamble up to and including \\begin{document}, cached on first use."""
    cache = HERE / f"preamble_{variant}.tex"
    if cache.exists():
        return cache.read_text().rstrip("\n")
    existing = HERE / f"manuscript_{variant}.tex"
    if not existing.exists():
        raise SystemExit(f"error: need {cache.name} or {existing.name} to take the "
                         f"{variant} preamble from")
    tex = existing.read_text()
    end = tex.find("\\begin{document}")
    if end < 0:
        raise SystemExit(f"error: no \\begin{{document}} in {existing.name}")
    pre = tex[:end + len("\\begin{document}")].rstrip("\n")
    cache.write_text(pre + "\n")
    print(f"  cached {cache.name}")
    return pre


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=HERE)
    args = ap.parse_args()
    fm, body = split_source(SRC.read_text())
    todo = [l for l in affiliation_lines(fm) if "TODO" in l]
    for variant, build in (("ieee", ieee_variant), ("apa", apa_variant)):
        pre = cached_preamble(variant)
        out = args.out / f"manuscript_{variant}.tex"
        out.write_text(build(pre, fm, body))
        print(f"wrote {out.name}")
    if todo:
        print(f"\nnote: {len(todo)} affiliation field(s) still TODO, carried into "
              f"both variants: {', '.join(todo)}")


def _selfcheck():
    fm = """
\\title{A Title: With Detection: Two Parts}
\\author[inst1]{Jane Roe\\corref{cor1}}
\\ead{j@example.org}
\\affiliation[inst1]{organization={Dept},
                    city={Town},
                    country={Nowhere}}
\\begin{abstract}
Body of abstract.
\\end{abstract}
\\begin{keyword}
alpha \\sep beta \\sep gamma
\\end{keyword}
"""
    assert author_name(fm) == "Jane Roe", author_name(fm)
    assert keywords(fm) == ["alpha", "beta", "gamma"], keywords(fm)
    assert affiliation_lines(fm) == ["Dept", "Town", "Nowhere"], affiliation_lines(fm)
    assert environ(fm, "abstract") == "Body of abstract."
    assert field(fm, "ead") == "j@example.org"
    src = ("junk\\begin{frontmatter}" + fm + "\\end{frontmatter}\n"
           "\\section{Introduction}\nSee \\cite{x}.\n\\bibliographystyle{z}\n")
    f2, b2 = split_source(src)
    assert b2.endswith("See \\cite{x}."), repr(b2)
    out = apa_variant("\\begin{document}", f2, b2)
    assert "\\citep{x}" in out and "\\cite{x}" not in out
    assert "Body of abstract." in out
    w = widen_for_twocolumn(
        "\\begin{table}[h]\\begin{tabularx}{\\columnwidth}{Y}a\\end{tabularx}\\end{table}"
        "\\includegraphics{f.pdf}")
    assert "\\begin{table*}[t]" in w and "\\end{table*}" in w, w
    assert "\\columnwidth" not in w.split("includegraphics")[0], w
    assert "\\includegraphics[width=\\columnwidth]{f.pdf}" in w, w
    out_i = ieee_variant("\\begin{document}", f2, b2)
    assert "\\IEEEauthorblockN{Jane Roe}" in out_i
    assert "\\cite{x}" in out_i, "IEEE keeps \\cite"
    assert ieee_title_break("short title") == "short title"
    long = ieee_title_break("aaaa bbbb cccc dddd eeee ffff gggg hhhh "
                            "iiii jjjj kkkk llll mmmm nnnn oooo")
    assert long.count("\\\\") == 1, long
    assert abs(long.index("\\\\") - len(long) / 2) < 12, long
    print("selfcheck ok")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        _selfcheck()
    else:
        main()
