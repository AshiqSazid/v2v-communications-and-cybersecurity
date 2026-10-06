# Results

> **NO CURRENT PUBLICATION RESULT — a fresh v9 sweep is required.** The source,
> schema, canonical plan, trace policy and baseline protocol changed after v7
> and the incomplete v8 attempt. Do not copy any numerical result below into
> the manuscript. V9 comprises 439 validation and 980 held-out test runs and
> must finish with a verified source snapshot and manifest before values are
> regenerated.
>
> Current threat attribution is the dominant evidence class on the observation
> defining `S_peak`; `Q = S_peak × I(class_at_S_peak)`. Baseline settings are
> fitted on validation traces and serialized before held-out test replay.
>
> **Everything after this notice is an archived v7 diagnostic retained only to
> explain why the rerun is necessary. It is not evidence for a current claim.**

## Archived v7 diagnostics — superseded


Every number here comes from ns-3.40 simulation under the v5 measurement
contract. Regenerate with `python3 aggregate.py report`; raw tables live in
`results/v5/full/analysis/`.

## Protocol

| | |
|---|---|
| Runs | 1209 = 439 validation + 770 test, 30 seeds per test arm |
| Split | disjoint seed ranges; threshold frozen on validation, never re-tuned |
| Threshold | 0.497, chosen to maximise macro-F1 subject to a bound on benign-run false alarms |
| Endpoint | `window_peak_score > threshold`, applied identically to both classes over `W = [max(warmup, attackStart), simTime]` |
| Intervals | mean ± half-width of a 95% percentile bootstrap over RNG-seed blocks |

The endpoint matters. Under the previous contract positives were decided by a
post-onset *new crossing* and negatives by *any* crossing over a longer window
— two rules, two exposures, so the confusion matrix did not belong to one
classifier, and the AUC ranked a statistic the operating point did not use.
One statistic over one window fixes both; the reported (FPR, TPR) point now
lies on the reported ROC curve by construction.

## 1. Detection by attack (30% attackers, 30 seeds)

```
arm                     TPR            clean FPR        AUC
pure_falsify         0.979 ± 0.003    0.000 ± 0.000   0.991 ± 0.001
pure_revheading      0.961 ± 0.004    0.000 ± 0.000   0.992 ± 0.001
pure_replay          0.934 ± 0.004    0.000 ± 0.000   1.000 ± 0.000
pure_dos             0.872 ± 0.006    0.000 ± 0.000   0.937 ± 0.003
mixedhard (0.3)      0.772 ± 0.016    0.000 ± 0.000   0.916 ± 0.007
pure_spoof           0.523 ± 0.029    0.000 ± 0.000   0.782 ± 0.014
pure_constoffset     0.253 ± 0.017    0.000 ± 0.000   0.634 ± 0.008
pure_slydos          0.000 ± 0.000    0.000 ± 0.000   0.500 ± 0.001
benign                    --          0.000 ± 0.000        --
```

`mixedhard` at TPR 0.772 is the headline: seven attacker roles simultaneously,
including two the checks cannot see. Clean false alarms are zero to three
decimals in every arm, including the attacker-free baseline.

`slydos` sits at AUC 0.500 ± 0.001 — a 1.6× beacon rate stays under the rate
limit, so it is not merely hard to detect but *invisible* to this check set.
Report it as a stated evasion margin, not a failure.

## 2. The onset artifact (paired, same seeds)

An attack that switches on mid-stream produces a discontinuity that is itself
an impossible displacement. Detecting that step is not the same as detecting
the attack. The `--attackStart=0` arm makes attackers adversarial from their
first transmitted message; both arms share seeds and evaluate over an
identical window, so the paired difference isolates the onset contribution.

```
attack          Δ TPR                    Δ AUC
constoffset   −0.253 [−0.271, −0.235]  −0.133 [−0.143, −0.124]
revheading    +0.000 [+0.000, +0.000]  +0.000
slydos        +0.000 [+0.000, +0.000]  −0.000
falsify       −0.002 [−0.005, −0.000]  −0.001
```

**All of `constoffset`'s apparent detection is the onset step.** Remove it and
TPR falls to zero — a constant offset preserves every kinematic invariant the
checks test. `revheading` and `falsify` are unaffected, so they are genuine
detections rather than transient artifacts. Reporting `constoffset` without
this control would have overstated the detector by 25 points.

## 3. Identity-collision framing, and the fix

Keying detector state on the claimed identity has a structural failure: under
impersonation the attacker's forged messages and the victim's genuine messages
share one state, so accumulated evidence convicts the victim.

The fix keys evidence on **kinematic track** instead. Forged and genuine
messages under one identity describe two mutually inconsistent but
individually self-consistent trajectories, which is observable from message
content alone — no source address, no PKI. Both keyings are computed in the
same run over identical random draws.

```
arm                  victim framing         victim framing      stream TPR
                     (identity-keyed)       (track-keyed)       id → track
pure_replay        0.952 [0.948,0.956]    0.007 [0.005,0.009]  0.934 → 0.934
mixedhard (0.3)    0.839 [0.822,0.855]    0.053 [0.044,0.063]  0.772 → 0.771
mixedhard (0.5)    0.833 [0.817,0.849]    0.065 [0.054,0.077]  0.783 → 0.783
pure_spoof         0.523 [0.495,0.553]    0.282 [0.258,0.309]  0.523 → 0.522
```

**Victim framing falls by 94–99% for replay and mixed adversaries at no
detection cost** — stream TPR is unchanged to three decimals, and the
intervals do not overlap.

Spoofing improves least (−46%), and the mechanism explains why: a spoofer
transmitting from a position kinematically consistent with its victim's motion
is not separable by trajectory alone. That is a boundary of the method, not an
implementation gap, and it bounds what any content-only defence can achieve.

## 4. Cost

```
                latency (ms)     PDR             detector
detector on     1.227 ± 0.010   0.458 ± 0.005   1.565 ± 0.013 µs/msg
detector off    1.227 ± 0.010   0.458 ± 0.005   --
```

Latency and PDR are identical because the detector is passive. This
*verifies* that property rather than measuring an independent one — the
detector never transmits, so it cannot affect the network. Do not present it
as "negligible overhead". Per-message cost is host CPU, not an OBU figure.

## 5. What this does not support

- **No external validation.** One simulator. Not evaluated on VeReMi or any
  public benchmark, so no claim generalises beyond this generator.
- **No published baselines.** The structural rules in `baselines.py` are
  reimplementations written here, not the original authors' code, and their
  absolute numbers must not be read as a performance comparison.
- **Evidence weights are assumptions.** `reference` weights are elicited;
  `simfit` weights were fitted on this simulator's own traces and are
  therefore circular. Neither is a calibration.
- **The score is not a probability.** It is a bounded decision statistic. No
  Bayesian, STRIDE or DREAD claim is made; those were removed from the
  runtime decision path.
- **`identity_contested` is not deployable.** It keys on the receiver-observed
  UDP source address, unspoofable only because this is a simulator. It is an
  identifiability upper bound. The track-keyed mitigation in §3 is the
  deployable result.
- **No Sybil or colluding adversary**, single highway scenario, no urban or
  SUMO-derived mobility.


---

## 6. STRIDE identification, DREAD impact, and risk

The risk layer answers the impact question the detector cannot:
`Risk = P(compromise | evidence) x Impact(STRIDE class)`. Over 1,105,880 test
pairs:

```
STRIDE class            pairs      share   impact   mean posterior   mean risk
denial_of_service      31,980       2.9%    0.74        0.999          0.740
spoofing                4,650       0.4%    0.72        0.978          0.704
tampering             138,972      12.6%    0.66        0.933          0.615
repudiation           157,905      14.3%    0.56        0.922          0.516
none                  772,373      69.8%      --          --           0.000
```

Risk tiers: 796,656 low, 151,230 medium, 157,994 high. Trust decisions:
796,656 trusted, 309,224 compromised. A stream with no firing check has no
identified threat and therefore no risk, regardless of its prior.

### What the impact term does and does not contribute

**It does not reorder threat classes.** The ranking by mean risk is identical to
the ranking by mean posterior, because the impact weights happen to be monotone
with the class posteriors in this data. A paper claiming that DREAD changes
which *class* of threat is prioritised would be unsupported here.

**It does reorder individual streams.** Over 4.46M sampled pair comparisons,
13.08% are discordant: risk and posterior disagree about which of two streams
is more serious. Roughly one comparison in eight is reordered by the impact
term. That is the defensible statement of what DREAD contributes -- per-stream
prioritisation, not class-level reprioritisation.

**Caveat.** The impact weights are expert-derived: four of six STRIDE classes
from a 60-scenario dataset via documented rules over observed CVSS values, and
two (information disclosure, elevation of privilege) elicited because that
dataset contains no scenarios for them. They order threats by severity; their
absolute magnitudes carry no calibration claim, and no detection result depends
on them.
