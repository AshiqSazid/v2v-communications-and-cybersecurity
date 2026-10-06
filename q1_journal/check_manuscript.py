#!/usr/bin/env python3
"""Pre-submission checks on the manuscript source and build log.

    python3 check_manuscript.py manuscript_vehcom.tex [manuscript_vehcom.log]

Elsevier production requires every float to be cited in the text; an uncited
table or figure comes back as an author query. This caught eight of them once,
so it runs again before every resubmission rather than being eyeballed.

Exits non-zero if anything fails, so it can gate a build.
"""
import re
import sys
from pathlib import Path


def floats_uncited(tex):
    lab = set(re.findall(r"\\label\{((?:tab|fig):[^}]+)\}", tex))
    ref = set(re.findall(r"\\(?:ref|autoref)\{((?:tab|fig):[^}]+)\}", tex))
    return sorted(lab - ref)


def todos(tex):
    return [f"{i}: {l.strip()}" for i, l in enumerate(tex.split("\n"), 1)
            if "TODO" in l and not l.lstrip().startswith("%")]


def abstract_words(tex):
    # elsarticle and IEEEtran use the environment; the APA variant sets the
    # abstract as a centred heading followed by a \begingroup block, so looking
    # only for \begin{abstract} silently reported "None" on that file.
    m = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", tex, re.S)
    if not m:
        m = re.search(r"\\textbf\{Abstract\}\s*\\end\{center\}(.*?)\\par",
                      tex, re.S)
    if not m:
        return None
    body = re.sub(r"\\[a-zA-Z]+\*?(\[[^\]]*\])?(\{[^}]*\})?", " ", m.group(1))
    return len(body.split())


def overfull(log):
    pts = re.findall(r"Overfull \\hbox \(([0-9.]+)pt", log)
    # Under ~1pt is narrower than a character and invisible on the page.
    return sorted((float(p) for p in pts if float(p) > 1.0), reverse=True)


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    tex = Path(sys.argv[1]).read_text()
    fails = []

    unc = floats_uncited(tex)
    print(f"floats never cited in text : {unc or 'none'}")
    if unc:
        fails.append(f"{len(unc)} uncited float(s)")

    t = todos(tex)
    print(f"unresolved TODO lines      : {len(t)}")
    for line in t:
        print(f"    {line}")
    if t:
        fails.append(f"{len(t)} TODO line(s)")

    w = abstract_words(tex)
    print(f"abstract words             : {w} (Elsevier cap 250)")
    if w and w > 250:
        fails.append(f"abstract {w} words")

    if len(sys.argv) > 2 and Path(sys.argv[2]).exists():
        o = overfull(Path(sys.argv[2]).read_text())
        print(f"overfull hboxes > 1pt      : {[f'{x:.1f}pt' for x in o] or 'none'}")
        if any(x > 5 for x in o):
            fails.append(f"{sum(x > 5 for x in o)} overfull box(es) > 5pt")

    print()
    if fails:
        print("FAIL: " + "; ".join(fails))
        return 1
    print("PASS")
    return 0


def _selfcheck():
    assert floats_uncited(r"\label{tab:a}\label{fig:b}\ref{tab:a}") == ["fig:b"]
    assert floats_uncited(r"\label{tab:a}\ref{tab:a}") == []
    assert todos("% TODO ignored\nreal TODO here") == ["2: real TODO here"]
    assert abstract_words(r"\begin{abstract}one two three\end{abstract}") == 3
    apa = ("\\textbf{Abstract}\n\\end{center}\n\\begingroup\n"
           "one two three four\n\\par\n")
    assert abstract_words(apa) == 4, abstract_words(apa)
    assert abstract_words("no abstract here") is None
    assert overfull("Overfull \\hbox (9.1pt too wide)\nOverfull \\hbox (0.5pt x)") == [9.1]
    print("selfcheck ok")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        _selfcheck()
    else:
        sys.exit(main())
