# What changed: old artifact → current artifact

> **Superseded working comparison.** Several “New” values below describe the
> archived v7 implementation (including OCB/WAVE wording, posterior language,
> run counts, and numerical results). They must not be cited as current. The
> table will be regenerated from the verified v9 source snapshot and manifest.

Compares [v2v.cc](v2v.cc) (185 lines, the version the reviewer saw) against
[code/](code/) (~10,000 lines across simulator, pipeline, analysis, tests), and
maps every one of the reviewer's 20 points in [kk.pdf](kk.pdf) to what now
exists.

---

## 1. The code itself

| | Old ([v2v.cc](v2v.cc)) | New ([code/v2v_cybersecurity_v2.cc](code/v2v_cybersecurity_v2.cc), 2441 lines) |
|---|---|---|
| Channel | `PointToPointHelper`, 10 Mbps wired link | IEEE 802.11p / OCB, 10 MHz, LogDistance + Nakagami fading |
| Topology | 2 nodes, fixed | 35 / 70 / 105 vehicles, highway mobility, two directions |
| Traffic | `UdpEcho`, 5 unicast packets | periodic BSM broadcast at 10 Hz, 320 B incl. 1609.2 overhead |
| Attackers | none — `suspiciousTraffic = false` literal | 7 attacker roles, actually transmitting hostile messages |
| Detection | `if (suspiciousTraffic)` on a constant | 7 physical-plausibility checks over the received BSM stream |
| Scoring | 5 hard-coded DREAD integers summed to 8 | per-message sequential log-evidence accumulation, bounded, time-decayed |
| Probability | `if (dread>=15) p=0.90; else if (>=10) p=0.60; else p=0.20;` | computed per reception from what the checks observed |
| Verdict | printed **before** `Simulator::Run()` | evolves during the run; recorded per receiver/claimed-ID pair |
| Metrics | none | TPR, FPR, precision, F1, ROC/AUC, PDR, latency, detector µs/msg |
| Runs | 1 | 1209 (439 validation + 770 test), 30 seeds per test arm |
| Tests | none | [code/test/](code/test/) — C++ detector unit tests + Python analysis and integration tests |

The old program's entire security output was determined at compile time. Nothing
it printed depended on a single packet. That is the defect underneath reviewer
points 1, 6, 7 and 8.

### Attacker roles now implemented

Four naive (`spoof`, `falsify`, `replay`, `dos`) plus three from the VeReMi
NextGen taxonomy that are specifically built to survive the checks that catch
the naive ones:

- `constoffset` — fixed position offset; steady-state trajectory is internally consistent
- `revheading` — velocity vector negated; `|v|` unchanged, invisible to a speed-magnitude check
- `slydos` — 1.6× nominal beacon rate, deliberately under the 20/s rate limit

---

## 2. Reviewer points, one by one

| # | Reviewer's point | Status | Where |
|---|---|---|---|
| 1 | Bayesian model essentially missing | **Done** | Per-check `d_k = P(fire\|compromised)`, `f_k = P(fire\|honest)`; evidence fused as `Σ log(d_k/f_k)`, clamped at ±8, with elapsed-time forgetting (`--decayHalfLife`). Risk composed as `R = P(C\|E) × Impact` exactly as requested. |
| 2 | STRIDE used as if it were an IDS | **Done** | Architecture is now precisely the one the reviewer drew: observed message → plausibility check fires → STRIDE class of the violated property → DREAD impact weight → posterior × impact → risk tier → trust decision. STRIDE never detects anything. |
| 3 | Title overclaims | **Done** | Now *"Quantitative Risk Assessment for V2V Misbehaviour: Bayesian Evidence with STRIDE-Weighted Impact."* "Comprehensive", "Mitigation Strategies" and "Connected and Autonomous Vehicles" are gone. |
| 4 | Fig. 2 (IDS accuracy 85% vs 95%) unsupported | **Done** | Replaced by a real experiment. Per-attack TPR / clean FPR / AUC with 95% bootstrap intervals over seed blocks, plus a `nullEvidence` ablation figure. `mixedhard` TPR 0.772 ± 0.016, clean FPR 0.000 in every arm. |
| 5 | Figs. 1 & 7 (DSRC vs C-V2X) have no configuration | **Done, with a stated scope limit** | [code/v2v_radio_comparison.cc](code/v2v_radio_comparison.cc) actually simulates both arms with identical mobility, vehicle count, message size and rate; raw per-run CSV in `results/radio/`. Caveat kept in the source and the paper: this is C-V2X **mode 3** (Uu, uplink+EPC+downlink), not mode 4 sidelink, which mainline ns-3 cannot model. The latency gap is therefore an access-architecture property, not a sidelink result. |
| 6 | Are the Bayesian values hard-coded? | **Done — they were, and no longer are** | Every score is produced at runtime from observed receptions. The multi-scenario table the reviewer asked for is now a 1209-run sweep across 8 attack arms. |
| 7 | NS-3 implementation too basic; run several network sizes | **Mostly done** | All missing parameters (mobility, velocity, propagation, packet size, interval, Tx power, duration, seed, attack config) are now explicit CLI options and recorded in per-run manifests. Scale sweep is N = 35 / 70 / 105 rather than the reviewer's suggested 2/10/25/50/100 — the low end was dropped because a 2-vehicle highway has no misbehaviour-detection problem to measure. |
| 8 | No real cyberattack experiments | **Done, exceeded** | Reviewer asked for 4 scenarios; 7 attacker roles are implemented, including three evasive ones. |
| 9 | DREAD needs a formal scoring procedure | **Done, with honest provenance** | Impact normalised to (0,1] as `DREAD_i / max`. Four of six STRIDE classes derived from a 60-scenario dataset (15 VeReMi NextGen attack types × 4 contexts) via documented rules over observed CVSS values; Information Disclosure and Elevation of Privilege have no scenarios in that dataset and are marked **elicited**. |
| 10 | TRUSTED/COMPROMISED threshold arbitrary | **Done** | τ = 0.497, selected on a **disjoint validation partition** (439 runs) over a preregistered 1001-point 0.001 grid, maximising macro-F1 subject to an exact one-sided Clopper–Pearson bound on seed-level false alarms (0 events in 299 benign seeds → upper bound 0.00997). Frozen before the test plan was generated; selection record with input SHA-256 hashes in `results/v6/full/analysis/selected_threshold.json`. |
| 11 | Related Work needs rewriting | **Paper-side; verify in [ieee.tex](ieee.tex)** | Section exists and is restructured; the study-by-study comparison table and recency of citations still need a read-through against this point. |
| 12 | Novelty needs reformulating | **Done — and changed** | The contribution is no longer "we combined STRIDE + DREAD + Bayesian + NS-3". It is the **attribution finding**: keying detector state on the claimed identity structurally convicts impersonation victims (victim framing 0.952 for replay), and re-keying on kinematic track drops that to 0.007 at zero detection cost. That is a result, not an integration. |
| 13 | "Mitigation strategy" contains no mitigation | **Done** | Two implemented responses: (a) **track keying** — 94–99% reduction in victim framing for replay and mixed adversaries, stream TPR unchanged to three decimals; (b) **identity-contested** flagging when one claimed identity appears from multiple observed sources. Both are measured, not asserted. Risk tiers drive an accept / monitor / reject decision. |
| 14 | Results need four quantitative experiments | **3 of 4** | Exp. 1 attack identification ✔; Exp. 3 trust decision / baseline comparison ✔ ([code/baselines.py](code/baselines.py): range, sudden-appearance, majority, sequential-score, identity-contested); Exp. 4 overhead ✔ (1.565 ± 0.013 µs/msg, serially timed). **Exp. 2 (calibration / Brier score) is deliberately not done** — the score is stated to be a bounded decision statistic, not a calibrated posterior, so a calibration metric would imply a claim the work does not make. |
| 15 | Repeated runs and statistical variability | **Done** | 30 seeds per test arm; every reported figure carries a 95% percentile-bootstrap interval resampled over RNG-seed blocks, so arms sharing a seed move together. Zero-event arms report an exact binomial upper bound instead of a meaningless 0 ± 0. |
| 16 | External references cited as evidence for own results | **Paper-side; verify in [ieee.tex](ieee.tex)** | All results now have an internal source (a table, a figure, a CSV under `results/v6/`) to point at instead. |
| 17 | Figs. 3 and 4 redundant | **Done** | One methodology figure (`fig_methodology`) following the evidence → STRIDE → impact → risk → trust → mitigation flow the reviewer sketched. |
| 18 | Terminal screenshots are not results | **Done** | All screenshots removed; 8 generated figures (detection, IDS ablation, mitigation, risk, cost, radio, scenario, methodology), each regenerable from `results/`. |
| 19 | Abstract should be rewritten last | **Done** | Abstract now runs problem → gap → method → setup → numbers → contribution, and no longer calls the framework "an effective solution". |
| 20 | Introduction needs a precise research question | **Done** | Framed around composing likelihood with impact to produce a per-stream trust decision, which the methodology then answers term by term. |

---

## 3. Added beyond what the reviewer asked for

These were not requested but close off the obvious next round of objections:

- **Onset-artifact control.** An attack that switches on mid-stream produces a discontinuity that is itself an impossible displacement — detecting the step is not detecting the attack. Paired `--attackStart=0` arms isolate it, and they show **all** of `constoffset`'s apparent detection was the onset step (ΔTPR −0.253). Reporting it without this control would have overstated the detector by 25 points.
- **Model misspecification arms.** `--gpsSigma` (noise generated) and `--detectorGpsSigma` (noise the detector assumes) are separate inputs, so the detector can be run against a channel it has wrong.
- **Evidence-weight sensitivity.** `--scoreModel=reference|simfit`, with `simfit` explicitly labelled circular (fitted on this simulator's own traces).
- **Ablations.** `--nullEvidence` (scoring non-firing checks) and `--naiveThresholds` (fixed kinematic thresholds) as contrast arms.
- **One-statistic evaluation contract.** The earlier sweep used a new-crossing rule for positives and an any-crossing rule for negatives — two rules over two windows, so the confusion matrix did not belong to a single classifier. Now one statistic (`window_peak_score`) over one window, so the reported (FPR, TPR) point lies on the reported ROC curve by construction.
- **Provenance and reproducibility.** Per-run manifests with binary and input hashes, disjoint validation/test seed ranges, `--csvHeader` as the authoritative machine-readable schema, and a test suite that compiles the detector core out of the shipped source so the tests cannot drift from the simulator.
- **A written claim boundary.** [code/result.md](code/result.md) §5 and [code/README.md](code/README.md) state what the artifact does *not* establish, so the paper cannot quietly overclaim.

---

## 4. Still open

- **No external benchmark.** Not evaluated on VeReMi or any public dataset; nothing generalises past this generator.
- **No published baselines.** [code/baselines.py](code/baselines.py) contains reimplemented structural rules, not the original authors' code — absolute numbers there are not a performance comparison.
- **`slydos` is invisible**, AUC 0.500 ± 0.001. A 1.6× beacon rate stays under the rate limit. Report as a stated evasion margin.
- **C-V2X is mode 3.** Mode 4 sidelink needs 5G-LENA, which is not installed.
- **Reviewer points 11 and 16 are paper-side** and need a pass over [ieee.tex](ieee.tex) to confirm.
- **STRIDE/DREAD is back in the paper** as an impact layer, after the earlier decision to drop it. It is defensible as written — it is additive, alters no decision, and reorders 13.08% of pairwise stream comparisons without reordering threat classes — but it re-opens the reviewer's novelty concern (#12) if it reads as the contribution rather than the attribution finding.
