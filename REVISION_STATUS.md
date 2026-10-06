# Revision status — critical reviewer report (24 points)

**Current evidence: `code/results/v9/full`.** 1479 runs (439 validation + 1040
held-out test), 2,321,496 pairs, frozen threshold **τ = 0.498**, manifest
`manifest_v4.json` recording source/binary/plan/threshold/analysis hashes.
Every number in the manuscript comes from this sweep. Earlier sweeps (v5–v8)
are historical diagnostics and must not be cited.

---

## What the sweep changed

Running it was not a formality. Four defects were invisible without it.

### Bugs the sweep exposed

1. **`onset_blank_s` missing from `aggregate.py`'s `config_fields`.** The
   `onset_guard` family varies only `--onsetBlank` and reuses the
   `pure_constoffset` seeds, so all four runs per seed looked like duplicate
   configurations and aggregation aborted on 90 legitimate runs. Fixed, with a
   regression test that walks the frozen plan, finds every argument that
   varies, and asserts its column is in the signature.
2. **`baselines.py` compared per-run `warmup` against one global default.** The
   120 `steady_state` runs use `warmup=10`; the replay would have measured over
   a different window than the detector did. Warm-up now comes from the run
   being replayed.
3. **`make_ids_figure.py` silently read precision instead of stream TPR.** The
   v9 report gained a second table whose rows share the same key and rule
   names, and last-match-wins overwrote the real values with 1.000s. The figure
   looked plausible and was wrong. Now first-match-wins.
4. **`distance_analysis.py` joins on mismatched boundaries** (warm-up vs
   evaluation window). The key check is fixed; the message-count comparison is
   not, so distance stratification is **not reported** and is disclosed as such.

### Findings that contradicted the previous draft

- **Attribution flipped.** Position falsification resolves to **spoofing**
  (0.976 of hostile pairs), not tampering. This is consistent with the
  documented tag table — `POSITION_JUMP` is tagged `S_SPOOFING` — so v7 was the
  anomaly. The narrative was corrected.
- **Impact weights matter far more than claimed.** Kendall τ under reversed
  severity is **−0.711**, not +0.816; uniform weights give **+0.268**. The
  ranking substantially *inverts*. The paper now reports this as a limitation:
  `Q` is not robust to the severity judgement. Detection is unaffected.
- **Every baseline number changed.** Naive Bayes 0.014 → **0.301**, so
  "collapses by an order of magnitude" is gone. The memory-not-weights finding
  survives: EWMA 0.644 vs sequential 0.646.
- **Manoeuvring improves association** (purity 0.992 → 0.994, merges 0.148 →
  0.093), confirming that constant velocity is the harder case for tracking.

### The headline result, measured

| | Identity keying | Track keying |
|---|---|---|
| Victim-exposed alert rate | **0.839** | **0.239** |
| Pure-honest-track alert | — | **0.000** |

Per adversary: replay 0.952→0.379, mixed-30% 0.839→0.239, mixed-50%
0.833→0.244, spoofing 0.523→0.037.

Zero false positives across **804,626** correctly specified clean pairs in 860
runs; per-seed bound < 0.058 (50 seeds) / < 0.095 (30 seeds). Highest clean
score 0.4967 against τ = 0.498 — a margin of **0.0013**, reported as marginal.

---

## Status by reviewer point

| # | Point | Status |
|---|---|---|
| 1 | Score is not a posterior | **Done.** Renamed throughout; "Bayesian" appears 0×. Calibration deferred (Route A), disclosed. |
| 2 | Decision rule inconsistent | **Done.** One variable; Algorithm 1. |
| 3 | Probability×impact unjustified | **Done.** Full DREAD rubric; sensitivity now shows the weights *do* matter, reported as a limitation. |
| 4 | STRIDE mapping circular | **Done.** Contingency table added (`tab:attribmatrix`), framed as contingency, never accuracy. |
| 5 | Zero-FP qualification | **Done.** Numerator/denominator, Clopper–Pearson bound, clean margin, and the zero holds under *every* denominator (per run, receiver, minute, million messages). |
| 6 | Run accounting | **Done.** 439 + 1040 = 1479; test = 33×30 + 1×50. Table and figure both generated from the frozen plans. |
| 7 | Evaluation unit/labels | **Done.** Formal definitions plus `fig_labels` showing the label matrix and the spoofing transition. |
| 8 | Track association | **Done** except an established-tracker baseline, deferred and disclosed. |
| 9 | Attacks not reproducible | **Done.** |
| 10 | Onset transient | **Done.** `fig_onset` shows the trajectory; guard sweep shows TPR 0.253→0.246 across g=0→1 s, while steady-state collapses to 0.000. Declared post hoc. |
| 11 | Baselines too limited | **Done.** Eight comparators with precision/recall/F1. No published detector reproduced — disclosed. |
| 12 | External validity | **Partial, disclosed.** Manoeuvring arm added; Gaussian-only noise, no urban mobility, no VeReMi. |
| 13 | Radio section | **Done by removal.** PDR explained. |
| 14 | Compute evidence | **Done.** Full percentiles plus CPU/OS/compiler/flags, with the assertions caveat. |
| 15 | Reproducibility | **Done** bar the DOI. Licence, manifest, per-figure commands, commit hash. |
| 16 | Related work | **Done.** 40 refs, all cited. |
| 17 | STRIDE/DREAD positioning | **Done.** Explicitly not an ISO/SAE 21434 TARA. |
| 18 | Means hide variation | **Mostly done.** Confusion matrix in counts, delay median + IQR, seed-block CIs throughout. **Distance stratification not reported** — disclosed. |
| 19 | "Degrades gracefully" | **Done.** |
| 20 | AUC/threshold separation | **Done.** Validation and test separated; held-out confusion matrix added. |
| 21 | Risk bands arbitrary | **Done.** |
| 22 | Figures dense/small | **Done.** Four figures were rendering at 2–4 pt because full-width designs were placed at column width and `bbox_inches="tight"` was inflating canvases. All now 1:1; sub-6 pt fonts raised. |
| 23 | Tables self-contained | **Done.** |
| 24 | Language/formatting | **Done.** Double-blind author block; 0 overfull boxes. |

**Tally: 22 done, 2 partial (12, 18), both disclosed.**

---

## Archived

DOI **10.5281/zenodo.21779178** (concept) / **10.5281/zenodo.21779179** (this
version), deposited from commit `f0b6777` under MIT. The record carries the
merged per-pair table that is too large for git. **The creator name is the
author's, so this record deanonymises a double-blind submission** — that was a
deliberate choice, not an oversight.

## Still open

- **VeReMi.** No external benchmark. This remains the largest single gap and no
  amount of internal work substitutes for it.
- **Calibration**, an established-tracker baseline, and a reproduced published
  detector — all deliberate deferrals, named in future work.

## Verified this session

- ns-3.40 rebuilt from the corrected source; build correspondence verified
  (source and scratch byte-identical, binary newer than both).
- `bash test/run_tests.sh` passes, including the new config-signature test.
- Manuscript compiles: 23 pages, 0 errors, 0 overfull boxes, 0 undefined
  citations, 0 pending cells, 9 figures, 19 tables, 40 references.
