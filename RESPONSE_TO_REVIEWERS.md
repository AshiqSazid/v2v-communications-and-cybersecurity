# Response to Reviewers

**Manuscript:** Risk-Aware V2V Misbehaviour Detection: Sequential Evidence,
Impact Prioritisation, and Track-Based Attribution
**Decision:** Major Revision

---

> **AUTHOR NOTE — read before sending.** Every `[FROZEN SWEEP]` marker below is a
> number that does not yet exist in the manuscript. Do not send this letter
> until the v9 sweep has completed, those markers are filled from
> `code/results/v9/full/manifest_v4.json`, and the Results section's
> data-integrity notice has been removed. Sending it before then would claim
> results the paper itself says are not final.

---

We thank the reviewer for a detailed and constructive report. The revision
follows the recommended sequence: we rebuilt the mathematical method first, then
the experimental description, then strengthened validation, presentation, and
finally the narrative. The unifying change is that the paper now *under-claims by
construction*: the detector statistic is no longer called a probability,
attribution is no longer called accuracy, the zero-false-alarm result is no
longer called a zero probability, and no result is claimed to generalise beyond
the single generator used. Each response below cites the section where the
change now lives. Reviewer comments are paraphrased for brevity.

---

## 1. The score is not established as a posterior probability

**Addressed.** We no longer denote the statistic `P(compromised | evidence)`.
Section IV-B ("What `S_t` is not") states the three assumptions that fail for a
posterior: the weights `w_k` are elicited rather than estimated; the checks are
correlated (most obviously the two displacement checks), so summing weights
double-counts shared evidence; and non-firing checks contribute zero rather than
a naive-Bayes negative term. The quantity is called a *sequential log-evidence
score* throughout. Every update term (`L_0`, `γ(Δt)`, `F_t`,
`w_k = log(d_k/f_k)`, clamp `B`) is defined in Section IV-B and Table II. The
initial score corresponds to a prior of 0.05, i.e. `L_0 = −2.94`, not zero; the
earlier text stated this incorrectly and has been corrected. Post-hoc calibration
(temperature scaling, reliability diagrams, Brier score) is stated as future work
in Section VII, not claimed.
**Pending:** the parameter-sensitivity arm over `h`, `L_0`, `B`, `τ` and
alternative weight sets must report its results. `[FROZEN SWEEP: sensitivity]`

## 2. The final decision rule is internally inconsistent

**Addressed.** There is now exactly one detection variable:
`ŷ = 1[S_peak > τ]`. Impact plays no part in it, so every detection number is
invariant to the DREAD weights. Algorithm 1 gives the full per-message order of
operations (checks → evidence → decay/clamp → peak snapshot → decision →
priority). The abstract, methods and captions use this one statistic
consistently, and the equality `trust == alert` is verified on every pair.

## 3. The probability–impact multiplication lacks justification

**Addressed.** `Q = S_peak · I_c` is described as an *ordinal risk-priority
index*, explicitly "not an expected loss and not a monetary or actuarial
quantity". The full DREAD rubric and all five component values per STRIDE class
are in Table III with the derivation rules. Ranking stability under four
alternative weight sets (uniform, compressed, stretched, reversed) is reported by
Kendall's τ. We disclose that the derived rows come from a single documented rule
set applied by one rater, so no inter-rater agreement can be computed.
`[FROZEN SWEEP: Kendall τ values]`

## 4. STRIDE mapping may reflect detector design, not true attribution

**Addressed, with a scoping argument.** Section IV-A gives the rationale for each
check-to-STRIDE mapping and names the plausible alternatives. An ambiguity flag
is raised when the margin between the best and second-best distinct class is
below 0.5 log-evidence units. On the request for a confusion matrix against the
*true* threat class: we do not report one, because no external threat-class
ground truth exists for these traces. The distribution of assigned classes is
reported as an *internal-consistency* check and never as accuracy. This is stated
as a deliberate limitation, not an omission.

## 5. The zero-false-alarm claim needs statistical qualification

**Addressed.** The numerator and denominator are reported explicitly. Because
clean pairs within a run are not independent, we bound at the independent unit —
the RNG seed — and give an exact one-sided 95% Clopper–Pearson upper bound on the
per-seed event probability. The wording is now "no false positives were observed,
and the per-seed false-alarm probability is below *p* with 95% confidence", not
"the rate is zero". We also expose the margin between the highest clean score and
τ, so the result is reported as *marginal* rather than comfortable. Sensor-model
misspecification is reported separately and breaks the result, as expected.
`[FROZEN SWEEP: numerator/denominator, Clopper–Pearson bound, clean margin]`

## 6. Experimental-run accounting does not reconcile (770 vs 22 × 30 = 660)

**Closed.** This was a real defect and it is fixed at the source rather than
patched in prose.

* Table VI is now the **complete** inventory — 8 validation arms and 34 test arms
  by family — with explicit `Arms` and `Runs` columns and partition totals. The
  counts are generated from the frozen `plans/validation.tsv` and
  `plans/test.tsv`, not transcribed.
* The reconciliation is stated in the text and in the table: **439 validation +
  1040 test = 1479 planned simulations**, where the test total is
  `33 arms × 30 seeds + 1 arm × 50 seeds = 1040`. It is deliberately *not* a
  single arm-by-seed product, which is precisely why the earlier "22 × 30"
  formulation could never reconcile.
* Fig. 2 no longer contains any transcribed count. `make_methodology_figure.py`
  reads `plans/*.tsv` directly and fails closed on a missing plan, a duplicate
  `experiment_id`, or a row from the wrong stage, so the figure and the table
  cannot drift apart again.
* Identity, nearest-neighbour-track and oracle-source keying are **not** separate
  arms — all three are scored inside every run — so no run is double-counted.
  The previous table implied an "association" family, which was wrong.

## 7. The evaluation unit and ground-truth labels are ambiguous

**Addressed.** Section V-C formally defines each label with numerator/denominator
logic: hostile-stream pair, non-hostile-stream pair, clean honest-owner pair,
owner attribution, victim-exposed pair, TP/FP/FN/TN, and detection delay
(right-censored at last reception, with the censored fraction reported).
Eligibility (≥ 1 message in window `W`) and the dependence structure (seed-block
resampling, never pair-level) are stated. Fig. 1 shows the identity-collision
mechanism.
A new figure states the same definitions diagrammatically: panel (A) shows that
the four labels are the product of two orthogonal binary facts rather than points
on one scale, so an impersonated identity is never counted in the clean
denominator; panel (B) shows what identity spoofing changes, including that the
labels are properties of the whole window, so the pair label does not oscillate
as the attacker starts. This closes the reviewer's request for a diagram of
labels and state transitions during spoofing.

## 8. Track association is under-specified and may introduce errors

**Method addressed; one item deferred.** Algorithm 2 gives the complete
lifecycle: expiry (`T_exp = 20 s`), gating (`G(Δt) = 4σ_gps + v_max·Δt`),
nearest-neighbour selection, tie-break by lowest index, out-of-order handling,
capacity (`K_max = 4`) and slot reuse. The expiry rule was missing entirely in
the previous version; adding it at 5 s cost 4–6 points of track-keyed detection,
so it is set to 20 s with a physical justification (a vehicle crosses the 300 m
range in ≈ 9 s, so 20 s cannot retire an in-range sender). The association
diagnostics — purity, merges/pair, fragments/pair, identity switches/pair — plus
an oracle-source upper-bound arm are instrumented and reported.
`[FROZEN SWEEP: Tables XV and XVII association rows]`
**Deferred, and disclosed as such:** we do not reproduce an established
probabilistic data-association tracker as a baseline. Section VII states this as
a limitation and names it in future work; the NN rule is presented as the
standard association baseline whose *cost* is measured, not as a new tracker.

## 9. Attack scenarios are not sufficiently reproducible

**Addressed.** Table V specifies, per attacker role, the modified BSM fields,
magnitude/distribution, beacon rate, cross-field consistency, and the checks each
should trip. Section V-B states the three generation conventions (genuine
pre-attack history, malicious-only-when-modified labelling, and non-consistent
forged fields unless stated). Onset timing, replay FIFO depth (200) and victim
selection are specified.

## 10. The attack-onset transient needs a focused experiment

**Addressed.** The design now carries three dedicated families: paired
steady-state arms (`t_a = 0`, 4 arms / 120 runs), focused activation-time
controls at 5 s and 20 s (2 arms / 60 runs), and a guard-interval sweep at 0.25,
0.5 and 1.0 s (3 arms / 90 runs), all paired on shared seeds with an extended
warm-up so both members evaluate over an identical window.
**Declared explicitly:** the activation-time and guard arms are *secondary and
post hoc* — added in response to observed switch-on sensitivity and to this
review, not pre-registered — and they are excluded from headline pooling.
`[FROZEN SWEEP: Table XIII onset→steady TPR and AUC per attack]`

## 11. Baseline comparison is too limited

**Addressed.** Eight comparators are evaluated under a common seed-level
false-alarm constraint with each rule's native threshold frozen on validation:
two-of-seven, weighted-sum, EWMA, naive Bayes, supervised logistic regression
(disclosed as in-generator and therefore circular), and the structural rules
range, sudden-appearance and identity-contested. We report TPR, clean FPR, and
threshold-free ROC-AUC and average precision. The table is factorised by
memory/weights so each row isolates one design decision — which is what shows
that memory, not the weights, does the work.
All are our reimplementations; absolute values are stated to be *not* a
comparison against published systems, and no *published* plausibility detector is
reproduced on shared traces. Both limitations are disclosed in Section VII.
`[FROZEN SWEEP: confirm baseline TPRs]`

## 12. External validity remains weak

**Addressed, including the external dataset.** A manoeuvring arm adds bounded
acceleration/braking and lateral perturbations, paired by seed. Localisation
error is no longer varied only in magnitude: heavy-tailed, biased and
temporally-correlated arms show the clean false-alarm result survives a fixed
per-vehicle bias and AR(1) correlation but **not** heavy tails, where it rises
to 0.021. It is the tail, not the correlation, that the claim depends on.

**We now evaluate on VeReMi NextGen** (Section VI, external validation), the
dataset this paper already draws its attack taxonomy from. The frozen detector,
with τ = 0.498 transferred unchanged, gives on the held-out Test split:

| Attack | VeReMi TPR | 95% CI | Clean FPR | In-generator |
|---|---|---|---|---|
| Reversed heading | 0.934 | [0.913, 0.955] | 0.000 | 0.961 |
| Data replay | 0.825 | [0.792, 0.855] | 0.000 | 0.934 |
| Constant offset | 0.025 | [0.014, 0.039] | 0.000 | 0.253 |
| Denial of service | 0.000 | — | 0.000 | 0.872 |

Three things follow. **The zero-false-alarm result transfers** to a road
geometry, density and mobility model the detector was never tuned for.
**Re-freezing τ on VeReMi's own validation split gives 0.425 and changes nothing
material**, so the operating point is not what fails. And **the two failures are
predicted by the paper's own analysis**: all 30 VeReMi constant-offset attackers
falsify from their first observed message, so there is no activation transient,
and our own steady-state arm already reports 0.000 under exactly that condition.

**What it cannot test, and why we say so.** Victim framing needs an attacker
transmitting under an honest vehicle's identity. In VeReMi NextGen every
pseudonym maps to exactly one true sender — including under the Sybil attack,
where 6964 aliases are fabricated rather than stolen — so no pair is
victim-exposed. The attribution result therefore remains in-generator only. We
report this as a property of the benchmark rather than working around it, and
note that it is informative in itself: the identity-collision threat this paper
addresses is absent from the standard corpus.

**Remaining:** urban mobility, intersections and overtaking are untested on any
corpus, and an external corpus containing genuine impersonation does not appear
to exist. Both are named in future work.

## 13. LTE Uu vs 802.11p comparison is weakly connected

**Addressed by removal.** Following the reviewer's preferred option, the
five-seed LTE Uu comparison has been removed: it was underpowered, incompletely
specified, and was a relayed uplink/core/downlink construction rather than C-V2X
sidelink. The paper makes no comparative radio claim and does not generalise to
C-V2X modes 3/4 or NR-V2X. The single 802.11p configuration is documented only to
delimit scope. PDR is defined precisely (unique honest-to-honest deliveries within
the geometric 300 m disc at true transmit time), which is what produces the low
absolute value.

## 14. Computational-performance evidence is insufficient

**Closed.** Per-message cost is reported as mean, median, P95, P99 and maximum
(a 280× median-to-worst spread that the mean previously hid), plus peak tracked
identities, live tracks and estimated payload per receiver. We make **no
real-time claim** and state these are host, not on-board-unit, measurements.
The measurement environment is now stated in full, which was the specific
omission: Intel Core i7-10610U (4 cores / 8 threads, 1.80 GHz base, 4.90 GHz
turbo), 16 GB RAM, Ubuntu 24.04.4 LTS on Linux 7.0.0 x86-64, ns-3.40 built by
GCC 13.3.0 via CMake 3.28.3 in ns-3's `default` profile
(`-O2 -g -DNDEBUG -std=c++17`, with `NS3_ASSERT_ENABLE` and `NS3_LOG_ENABLE`
retained), analysis under Python 3.12.3. We note explicitly that assertions and
logging are compiled in, so the reported cost is an **upper bound** relative to
an ns-3 `optimized` build rather than a best case, and that the timing arm runs
one process at a time so the percentiles are not contaminated by co-scheduled
simulations.
`[FROZEN SWEEP: vehicle-count scaling of the cost and state maxima]`

## 15. Reproducibility claims are incomplete

**Mostly closed.** The manifest (source/binary/plan/threshold/analysis hashes,
completed-runs = plan) and the required archive contents are defined, and the
repository is named.
* A licence is now present: **MIT**, in `LICENSE` at the repository root.
* `code/README.md` now documents **one runnable command per figure and per
  extended analysis**, which the paper previously promised but did not supply.
  The figure commands read the frozen plans and analysis outputs directly.
* `[FILL: commit hash]` — the corrected revision is committed and the exact
  commit is cited in the Data and Code Availability statement.
* **Still open:** no archival DOI or versioned release (Zenodo tag) has been
  minted. If the venue requires one, mint it before submission; if it requires
  anonymity, note that the repository URL currently identifies an author and
  must be replaced with an anonymised mirror.

## 16. The related-work section is too narrow

**Addressed.** Section II is organised into five streams (plausibility detection,
temporal/trust fusion, automotive risk assessment, pseudonyms/state association,
positioning) with Table I comparing *implemented* methods on online evidence,
fusion/state, output, consequence, collision outcome and evaluation. ETSI
misbehaviour standards, IEEE 1609.2, VeReMi and VeReMi NextGen, C-V2X/NR-V2X
security, tracking/data-association and calibration literature are cited; all
citations resolve in both directions with no orphaned entries. Absolute claims
are moderated: we make no universal claim about all published plausibility
detectors, and the gap is stated as bounded to the reviewed corpus.

## 17. STRIDE and DREAD require more careful positioning

**Addressed.** STRIDE is described as "a threat-modelling taxonomy, not a
detector", used only to label the consequence class of evidence already produced,
and the standing subjectivity critique of DREAD is cited. The pipeline is framed
as evidence extraction → compromise score → STRIDE attribution → DREAD impact →
priority, with the impact term explicitly outside the detection decision.

## 18. Means alone hide variation

**Partially addressed.** All intervals are 95% seed-block bootstraps resampling
RNG seeds. Detection delay is reported with its censoring rule; results are
stratified by attack type and prevalence, and cost is reported as a full
percentile distribution rather than a mean. Score distributions are shown rather
than summarised.
**Still thin:** IQR tables for every metric and stratification by receiver
distance are produced by `distance_analysis.py` but are not yet all surfaced in
the manuscript. `[FROZEN SWEEP: medians/IQRs and distance strata]`

## 19. "Degrades gracefully" is overstated

**Addressed.** The section is retitled "Documented blind spots". Rate-limited
flooding is described as "invisible, not merely difficult" (no check fires);
constant offset is "kinematically blind except at activation". The
absence-of-evidence versus evidence-of-innocence distinction is stated
explicitly. No graceful-degradation language remains.

## 20. AUC and threshold reporting need clearer separation

**Addressed.** Validation and test ROC/PR curves are plotted separately; the
frozen τ is chosen on validation and marked on the test curve, where it lies by
construction because the curve ranks the same statistic the operating point
thresholds. PR is reported alongside ROC because hostile pairs are a minority,
and prevalence is shown as the PR chance line.
`[FROZEN SWEEP: confirm AUC and PR-AUC values]`

## 21. Risk-band boundaries appear arbitrary

**Addressed.** The low/medium/high bands are stated to be "operational policy,
not validated safety boundaries", the response attached to each is named, and all
conclusions are also reported on the continuous `Q` so that nothing depends on
where the bands fall.

## 22. Figures are too dense and small

**Addressed in structure.** The framework and protocol are split into two panels
(Fig. 2). Captions are self-contained and state sample size and uncertainty.
Colour is redundant with position and label throughout, so the figures survive
desaturation and colour-vision deficiency.
*Caveat:* no LaTeX toolchain is installed on the machine used for this revision,
so final font and marker sizes at IEEE column width have not been visually
verified in a compiled PDF. Compile and inspect before submitting.

## 23. Tables need to be self-contained

**Addressed.** Captions state the evaluation population and sample size and
define the reported quantities; the DREAD table shows component values rather
than only the normalised impact; seed-block intervals are noted where applicable.
Every float is now referenced from the body text — five previously were not,
which would have left their placement arbitrary.

## 24. Language and IEEE formatting

**Closed.** Terminology is consistent — one term, "sequential log-evidence
score", is used throughout for the statistic, and "Bayesian" no longer appears.
The author block is no longer a placeholder: it is a correctly-formed
double-blind block, with the camera-ready author template retained as a comment
immediately below it for use on acceptance.

---

## Summary of items not yet closed

| Item | Status | Action |
|---|---|---|
| 6 | **Closed** — table and figure now generated from the frozen plans; 439 + 1040 = 1479 reconciles | verify Fig. 2 regenerates after the sweep |
| 8 | No established-tracker baseline | Deferred to future work (disclosed) |
| 12 | Gaussian noise only; no urban mobility | Deferred to future work (now explicitly disclosed) |
| 14 | **Closed** — CPU/OS/compiler/flags stated, with the assertions caveat | — |
| 15 | Licence and per-figure commands added; commit cited | Mint DOI/tag if the venue needs one; anonymise repo URL if required |
| 24 | **Closed** — deliberate double-blind block | Uncomment camera-ready block on acceptance |
| 18 | IQR/distance strata computed but not fully surfaced | Surface from the sweep outputs |
| 22 | Not visually verified at column width | Install a LaTeX toolchain and inspect the compiled PDF |
| Many | Pending tables and v7 cells | Fill from the v9 sweep; remove the data-integrity notice |
