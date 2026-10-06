# Vehicular Communications (Elsevier) submission package

*Track-Keyed Sequential Evidence for Misbehaviour Detection
and Impact Prioritisation in V2V Networks*

Target: **Vehicular Communications**, Elsevier. Submission portal:
<https://www.editorialmanager.com/vehcom/>

## Submit these

| File | Role |
|---|---|
| `manuscript_vehcom.tex` | **The manuscript.** `elsarticle`, `review` mode (double-spaced, line-numbered), numbered citations via `elsarticle-num`. 48 pp. in review mode, 27 pp. in the journal's two-column layout (21 body, 2 appendix, 4 references). |
| `highlights.txt` | Separate highlights file the journal asks for. 5 bullets, all under the 85-character limit. |
| `refs.bib` | 59 references, all cited, all DOIs resolving. |
| `figures/` | 11 vector PDFs. |

`manuscript_ieee.tex` and `manuscript_apa.tex` are fallback-venue variants.
**Do not submit them** -- `manuscript_apa.tex` uses author-year citations, which
this journal does not accept.

They are **generated**, not maintained:

```
python3 make_variants.py          # regenerate both from manuscript_vehcom.tex
python3 make_variants.py --selfcheck
```

`manuscript_vehcom.tex` is the single source of truth. The variants take their
preamble from `preamble_ieee.tex` / `preamble_apa.tex` and everything else --
title, author, abstract, keywords, body -- from the VehCom source, so the three
cannot disagree on content. Edit the VehCom file and rerun; never hand-edit a
variant, it will be overwritten.

This replaced three hand-maintained copies that had drifted badly: both variants
were missing 356 lines of results (the learned-detector comparison, the paired
contrast, the leave-one-check-out ablation, the change-detection section) and
still carried the superseded abstract claiming the evidence weights buy nothing
-- the finding the paired contrast overturned.

Known layout cost of sharing one body: the tables are sized for the VehCom
single-column measure, so the IEEE two-column build has three tables
overflowing its narrower column (worst 54 pt) and the APA build one (27 pt).
Harmless for a reference copy; fix the sizing if either becomes a real target.

## Journal requirements, as verified against the Guide for Authors

- **Single-anonymized review.** Real names and affiliations are required. The
  manuscript still has `TODO` placeholders for affiliation and corresponding
  author email -- fill these in. Do **not** submit anonymized.
- **Citations** are numbered in square brackets, in order of appearance.
  `elsarticle-num` handles this; do not switch to author-year.
- **Abstract** is capped at 250 words. Ours is 190.
- **Highlights**: 3-5 bullets, each at most 85 characters including spaces,
  submitted as a separate file with "highlights" in the name.
- **Declarations** present in the manuscript: competing interest, CRediT
  authorship contribution statement, and the data/code availability section.
- Double-column layout is permitted for LaTeX. Swap `3p` for `5p` in the
  `\documentclass` line to preview the typeset journal layout; keep `review`
  for what the referees see.

## Build

```
latexmk -pdf manuscript_vehcom.tex
```

Requires `elsarticle`, `lineno` and `hyperref`. All three are in Overleaf's TeX
Live. `hyperref` is not optional here: `elsarticle-num.bst` emits `\href`, and
without it the `.bbl` fallback redefines `\path` naively and every DOI
containing an underscore breaks the build.

## Overleaf

Upload `overleaf_vehcom.zip` via **New Project -> Upload Project**, then set the
main document to `manuscript_vehcom.tex`. Compiler: pdfLaTeX.

## Before you click submit

Fill in the `TODO` markers (affiliation, email, co-authors, CRediT roles), and
decide on the GitHub URL in the availability section -- the review is
single-anonymized, so the real URL is fine, but confirm you want the repository
public at submission time rather than at acceptance.

## What changed in this revision

- **Paired seed-block contrast added** (`paired_contrast.py`, `paired_contrast.json`).
  Reproduces all published marginal rates exactly, then reports the *difference*
  between rules. The sequential score beats unweighted EWMA on 30/30 seeds,
  +0.0024, 95% CI [0.0019, 0.0029] -- excluding zero. The old claim that the
  weights could not be shown to help was an artifact of comparing marginals.
  Abstract, results and conclusion now reflect this. Exploratory, not predeclared.
- **ART and SAW correctly identified as published baselines.** They were
  described as "oracle-assisted references that no deployed receiver could run."
  They are not: ART uses the receiver's *own* position, which any receiver knows
  from its own GNSS. The real idealisation is that our traces record that
  position without error, which is now stated precisely. The paper no longer
  claims zero published baselines.
- **Sequential-analysis grounding** (new Section 4.9): the score is related to
  SPRT, CUSUM and Lorden's change detection, with the three deliberate
  deviations and an explicit statement of which classical guarantees do not
  transfer and why.
- **References 41 -> 59**, all Crossref-verified with resolving DOIs. Includes
  F2MD, 8 papers from this journal, and the sequential-analysis classics.
- Related Work now covers F2MD and recent learned/federated detection, and says
  plainly what this paper does and does not add over them.
- Abstract reframed around the three substantive results; 233 words (limit 250).
- Further paraphrase damage repaired in Sections 4.8 and 6.6, plus three
  redundancy fixes.

## Figures

All eleven are regenerated from `code/make_*.py` against the frozen result
root. Shared styling lives in `code/figstyle.py`.

- **Palette is Okabe-Ito**, the colour-vision-deficiency-safe set designed for
  scientific figures, replacing a blue/orange pair that read as a plotting
  default. Roles are fixed and never cycled: grey is always the comparator,
  blue always this paper's detector, vermillion always the contrasting state.
  `figstyle.py` carries a self-check that fails if two roles collapse to the
  same grey in print -- it caught one such collision during this pass.
- **Drawn at the width they are placed at.** The manuscript measure is 468 pt
  (6.5 in), so the figures are 6.5 in and the typesetter rescales nothing; 7 pt
  in a figure prints as 7 pt beside 7 pt body text. `fig_mitigation` is drawn at
  the 90 mm single-column measure and included at native size -- it was
  previously stretched from 3.5 in to 6.5 in, which scaled its type to roughly
  13 pt and was the most obvious defect in the set.
- **`fig_mitigation` is now a dumbbell rather than grouped bars**, because the
  quantity the section argues about is the drop between the two keyings.
- **Selective direct labels.** A number on every bar restates the axis; only the
  values the text argues about are labelled.
- Regenerate at the 190 mm Elsevier production measure by setting
  `figstyle.WDOC = figstyle.W2` before the final submission, if the editor asks.

Two figures could not be regenerated from their own committed source before
this pass -- `fig_labels` and `fig_risk` both failed their layout assertions on
overlapping text. Both are fixed, so every figure in the manuscript now
reproduces from the scripts.

## Leave-one-check-out (new)

`baselines.py` now carries seven `seq-no-<check>` arms -- the sequential rule
with one check silenced -- evaluated in the same replay pass at the same frozen
threshold. `loo_ablation.py` reports them from
`analysis/baseline_metrics_loo.json`. Results are Table 11 in the manuscript and
`loo_ablation.json` here. The complete rule reproduces its published 0.646
exactly, which validates the masking path. Headline: heading (-0.149) and rate
(-0.125) are the only checks without which an attack becomes invisible; map
bounds contributes nothing measurable on this road geometry.

## Learned-detector comparison (new)

`learned_baseline.py` trains a random forest and a gradient-boosting classifier
on VeReMi NextGen's Validation split and scores them on its Test split, on the
same (receiver, claimed identity) pairs, same window and same labels our
detector is scored on. Features are raw receiver-observable kinematics, not our
check outputs. Needs scikit-learn: `python3 -m venv --system-site-packages
.venv-ml && .venv-ml/bin/pip install scikit-learn`.

Result is Table 16 in the manuscript and `learned_baseline.json` here, and it
does not favour our detector: both models detect more on all four attacks
(DoS 1.000/0.998 vs 0.000; constant offset 0.333/0.407 vs 0.029) while our rule
false-alarms 3-10x less (0.000-0.003 vs 0.010-0.035). The DoS gap is explained
-- VeReMi's DoS beacons at a 0.33 s mean gap against 1.00 s honest, below our
fixed 20 msg/s rate limit, so our check never fires while the models read the
inter-arrival gap directly. That is the Section 6.5 blind-spot conjecture
confirmed on independent data.

Our detector is reported twice, at the transferred threshold and at one
re-selected on VeReMi Validation under the same rule the learned models get, so
the comparison is not decided by who saw which split. The re-frozen value lands
at 0.425, matching what the external-validation section already reports.

## Still open -- have answers ready

- **The impact ranking has no outcome ground truth.** `Q` is an uncalibrated
  score times a single-rater ordinal weight. Coupling with SUMO and a safety
  application (TTC violations as ground truth, NDCG for the ranking) is the fix.
- **Mobility is a constant-velocity highway** with one localisation-error family.
- **DREAD weights are single-rater.** `dread_raters.py` + `dread_ratings.csv`
  are ready: the CSV holds the manuscript's existing scores as `rater1`. Add
  `rater2_D ... rater2_Ds` column groups from other people and re-run for
  Kendall's W, pairwise Spearman and the per-class weight spread. The script
  refuses to report agreement from a single rater.
- **Timings are from an i7 laptop.** `obu_timing.py` runs the detector loop on
  any machine. Note it times the *Python* reference implementation (~46 us/msg
  on x86, recorded in `obu_timing_x86.json`), not the C++ detector Table 14
  times at 2.7 us. Run it on both the x86 host and the target board and use the
  **ratio** -- the absolute Python number would overstate OBU cost tenfold.
- **Urban mobility.** `make_urban_scenario.py` builds a signalised 800x800 m
  SUMO grid and exports `urban.ns2.tcl` in the ns-2 format `Ns2MobilityHelper`
  reads (70 vehicles, 20541 waypoints, mean 9.3 m/s, 23% of samples stationary
  at lights). The simulator still needs an `Ns2MobilityHelper` branch and a
  re-run of the frozen sweep before any urban number can be reported.
