# Legacy pre-v4 audit — superseded

> **Status:** historical diagnostic record only. This document describes the
> pre-v3 implementation, result files, and invalidated v3 attempt. Its
> numerical tables are not current paper results and must not be cited as v4
> measurements.

The current design, metric definitions, claim boundary, and next actions are in
[README.md](README.md), [project.md](project.md), and [result.md](result.md).
Where this file conflicts with any of them, those files take precedence.

This audit is retained because it records how the earlier artifact failed and
why a clean rerun was required. It does **not** establish Bayesian calibration,
published-baseline superiority, benchmark performance, or generalization.

V4 additionally corrects two blockers discovered after this audit: a genuine
`attackStart` now separates retained honest history from malicious behavior,
and threshold selection replays the exact runtime below-to-above rule via
merged half-open crossing intervals. It also adds elapsed-time forgetting,
explicit zero-reception opportunities, and a receiver-observable
identity-contested mitigation. These are implemented methods, not held-out or
external effect-size evidence; the submission is not yet A*-ready.

## Historical context

The audit examined the pre-v3 result set and traces. Several observations were
useful for redesign, but the old evaluation contract had defects in latency,
PDR, attacker/role allocation, attribution labels, aggregation keys, and
uncertainty handling. Correcting only one column would therefore not make the
old headline values publication-ready.

The v3 response is to:

- describe the runtime mechanism as an identity-keyed sequential evidence
  detector, not a calibrated Bayesian posterior;
- remove STRIDE/DREAD from the runtime decision path;
- distinguish hostile-stream detection, identity-owner attribution, and clean
  false alarms;
- count receiver–victim pairs separately from unique victim identities;
- make ever-crossed the primary decision;
- use a true-transmission registry for latency and PDR;
- randomize attacker identities independently of mobility and balance mixed
  roles;
- separate actual `gpsSigma` from assumed `detectorGpsSigma`;
- split validation from held-out testing; and
- regenerate all quantitative tables from a strict v3 schema.

## 1. Identity collision versus bad-mouthing

The pre-v3 review correctly narrowed an overbroad novelty claim.

Bad-mouthing is already established in VANET trust and reputation research. It
usually involves explicit negative testimony or ratings exchanged between
vehicles. The mechanism studied here is different: an attacker transmits under
an honest identity and a receiver-local detector accumulates evidence under
that claimed identity without any reputation exchange.

The stronger historical assertion that standard benchmarks necessarily label
ground truth only per identity was unsupported. VeReMi provides per-message
ground truth, so the artifact must not claim that published false-positive
rates are generally invalid.

The defensible design question is narrower:

> A state machine keyed only by an unauthenticated claimed identity observes an
> inconsistent stream, but cannot generally identify which physical source
> caused the inconsistency during identity collision.

V3 measures the magnitude of that ambiguity under its simulation conditions.
It does not assume that the finding already generalizes to published
detectors.

Historical sources consulted during the audit included the
[VeReMi dataset site](https://veremi-dataset.github.io/) and literature on
bad-mouthing attacks in reputation systems. Those sources motivate the
distinction; they are not a replacement for a systematic literature review.

## 2. Mixed-role density was confounded

The original `mixedhard` assignment derived role from node index modulo seven.
As attacker count changed, attack composition changed too. At the smallest
fraction, two roles were absent. Node index also influenced lane and travel
direction.

Therefore the old density slope could not be attributed to attacker density.
An intermediate rerun randomized roles and showed much wider seed-to-seed
uncertainty and a weaker trend. Those intermediate values are preserved in
legacy result files, but they are still not v3 publication results because
other evaluation defects remained.

The v3 protocol uses:

- attacker identity selected independently of node ID and mobility;
- a balanced, shuffled role list for `mixedhard`; and
- a 70-vehicle primary fleet so declared fractions can preserve seven-role
  balance.

No current density effect is claimed until the clean grid is complete.

## 3. Replay and spoofing broke the owner-TPR denominator

In the old replay model, a replayer frequently broadcast captured messages
under victims' claimed identities. Its own identity therefore appeared rarely.
Across old seeds, the number of pairs labeled positive by identity ownership
could collapse from tens to only a few. Spoofing could eliminate the attacker's
own claimed-ID stream entirely.

This was not ordinary classifier instability; it was a mismatch between the
question and the denominator. Sender-owner TPR is not sufficient for attacks
that primarily operate through victims' identities.

V3 retains owner attribution but adds hostile-stream truth. It also reports
raw denominators, receiver–victim exposure, unique victims, and source
collision fields. Impersonated pairs are not dropped from attribution
accounting.

## 4. Final and ever-crossed decisions differed

The old analysis often reported the final score/alert, while time-to-detection
bookkeeping recorded whether the threshold had ever been crossed. Score decay
allowed some pairs to cross and later return below threshold.

A deployed alerting policy acts at first crossing, so v3 makes `ever_alert` the
primary decision and reports `final_alert`, `peak_score`, and `final_score` as
secondary diagnostics. Undetected positives are right-censored in
time-to-detection analysis rather than silently omitted.

The exact old percentage differences are not repeated here as current
findings. Their enduring value is the demonstration that a paper must specify
the decision rule.

## 5. Old “contested” counts mixed evaluation units

The pre-v3 code described a state as contested using several inconsistent
notions, including hostile use and multiple sources. The result text then
described receiver/identity pair counts as numbers of honest vehicles.
Excluding those pairs from the main confusion matrix made ordinary FPR look
clean while hiding attribution failure.

V3 replaces that overloaded field with auditable labels:

- `hostile_use`;
- `owner_is_attacker`;
- `owner_seen`;
- `source_count`;
- `impersonated`; and
- the true source ID set in the evaluation-only pair output.

It reports both victim pairs and unique victim identities. Historical framing
rates are not comparable to these v3 quantities and must not be copied into
the manuscript.

The qualitative mechanism remains plausible: when forged and genuine messages
share a claimed-ID key, evidence may be charged to the honest identity. Its v3
effect size is pending.

## 6. Simulator-fit evidence weights

The old `calibrate_llr.py` replayed checks on 40 pre-v3 traces and labeled
attackers using a numeric node-ID prefix. It reported per-check firing rates
and called the result “learned” or “calibrated.”

Two corrections are now mandatory:

1. attacker status comes from an explicit
   `oracle_source_is_attacker`/`oracle_is_attacker` field because attacker IDs
   are randomized; and
2. the output is called **simulator-fit evidence weights**.

The fitted quantities are descriptive estimates:

```text
d_k = P(check k fires | hostile physical source in this simulator)
f_k = P(check k fires | honest physical source in this simulator)
weight_k = log(d_k / f_k)
```

They do not calibrate the detector's bounded score as a maliciousness
probability. Training and evaluation use the same simulation family, so the
arm is circular by construction. It may reveal sensitivity to the reference
weights, but it cannot rebut an external-validity or calibration objection.

The old audit observed that some reference and simulator-fit firing rates
differed materially while the aggregate old classifier metrics changed little.
That historical null result suggested structural blind spots dominated weight
tuning. It is a hypothesis for v3 testing, not a current effect-size claim.

## 7. Structural blind spots

Two arguments found during the audit remain useful independently of the old
numerical tables.

### Fixed position offset

A constant translation preserves displacement, implied speed, speed agreement,
heading, timing, and rate. A detector that examines only the internal
consistency of one claimed trajectory has no observation that distinguishes
the translated trajectory from the original. Detecting it requires information
outside that stream, such as cross-vehicle corroboration, trusted ranging,
infrastructure, or authenticated physical-source evidence.

### Below-threshold flooding

A rate-only check defines an admissible region beneath its threshold. An
attacker that remains inside that region is not distinguishable by that check
alone. Detecting impact below the rate limit requires a different signal, not
only retuning the same threshold.

Pre-v3 runs appeared consistent with both arguments, but their old AUC values
are not treated as v3 results.

## 8. Old baseline comparison is withdrawn as performance evidence

The legacy `baselines.py` labeled simplified local rules as ART, SAW, eMDM, and
Bayes. That was not a faithful reproduction of the named published methods.
The trace also lacked receiver true position, so range rules substituted a
receiver self-report. Those choices invalidate any superiority claim and are
too weak to establish that an attribution rate generalizes across published
detectors.

The old table is therefore preserved only in historical CSV/commit provenance,
not repeated here as a valid comparison.

The current script uses transparent names:

- range;
- sudden appearance;
- majority;
- sequential score.

It requires v3 receiver-position and explicit oracle-source fields. Each rule
is evaluated both with claimed-ID keys and with an oracle true-source key. The
oracle arm isolates the effect of perfect source disambiguation but is not
deployable under the threat model.

Until full published implementations or a standard benchmark are evaluated,
the artifact makes no published-baseline superiority or generalization claim.

## 9. Latency, PDR, and detector timing required redesign

Three old measurements were not suitable for publication:

- sender-asserted time included clock offset, causing negative raw delays that
  were clipped before averaging;
- PDR receptions were not always restricted to the exact in-range opportunity
  set used by the denominator; and
- wall-clock detector timing from a parallel sweep measured host contention.

V3 registers true transmission time and the exact in-range receiver set for
each true source/sequence. Only matched receptions contribute to true-time
latency and the PDR numerator. Detector cost is measured in a separate serial,
paired on/off arm.

The old latency, PDR, and microsecond values are retracted as current paper
results.

## 10. What was not completed in this legacy audit

The original audit could not rewrite the manuscript because only the PDF was
available, not the LaTeX or Word source. The manuscript PDF remains preserved
unchanged during the code revision.

An external VeReMi evaluation, faithful published-detector reproduction, Sybil
scenario, collusion scenario, and real OBU benchmark were not completed. Their
absence remains an explicit limitation.

## 11. Current next step

Follow [result.md](result.md), not the old numerical sections of this file:

1. pass assertion-based v3 correctness tests;
2. select the threshold using validation seeds only;
3. freeze code, configuration, and provenance;
4. run and validate the clean v3 grid;
5. run serial timing separately;
6. regenerate all tables automatically;
7. inspect pair versus unique-victim accounting; and
8. revise the manuscript only from held-out v3 artifacts.

Until those steps finish, the correct reviewer disposition is **major
revision / quantitative results pending**, not acceptance based on the legacy
headline numbers.
