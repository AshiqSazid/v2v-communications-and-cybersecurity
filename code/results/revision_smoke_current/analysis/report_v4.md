# v4 experiment report

- Mode: **smoke** — pipeline check only; not publication evidence.
- Runs: 32 (8 validation, 24 frozen-threshold test)
- Frozen threshold: `0.41199999999999998`
- Endpoint: `window_peak_score > threshold`, applied identically to malicious and non-malicious streams over the evaluation window W = [max(warmup, attack_start + onset_blank), sim_time]. Pairs with no reception inside W are excluded from every arm rather than counted as true negatives.
- Endpoint audit: every pair row was checked to satisfy `window_alert == (window_peak_score > threshold)`; timing arms suppress pair output by design.
- Because the ROC curve ranks the same statistic the operating point thresholds, the reported (FPR, TPR) point lies on the reported curve by construction.
- Victim framing uses the same window and rule as every other decision; pre-onset excursions are excluded by W, not by a label-dependent rule.
- Selection constraint and reported clean FPR are different estimands: the frozen threshold bounds P(a benign run raises any false positive), while `clean_fpr` is a per-pair rate inside attack runs. The bound does not transfer to that column.
- Bounded primary metrics: two-sided 95% percentile intervals from 5000 deterministic RNG-seed-block bootstrap replicates.
- Other scalar metrics: two-sided 95% Student-t intervals over RNG seeds.
- Time to detection: Kaplan–Meier restricted mean with explicit right censoring and one common preregistered horizon of 4 s.
- Detection-time survival is conditional on at least one valid malicious reception; malicious opportunity reception is reported separately.
- Seed RMST is undefined (not extrapolated) when follow-up ends before the common horizon while estimated survival remains above zero.
- ROC/PR table: scalar peak-score discrimination only; it is not the post-onset crossing-rule endpoint. Curves are descriptive seed means without pointwise confidence intervals.
- Compute cost: simulator-instrumented `det_us` from serial detector-on runs only. Whole-process wall durations remain manifest diagnostics and are not interpreted as detector overhead because detector-on performs additional evaluation bookkeeping.
- Zero false-event groups include an exact one-sided 95% bound on the probability that an independent RNG run has any event (not a pair-level FPR bound).

## Key arm-level metrics

| family | arm | metric | n | mean | 95% CI |
|---|---|---:|---:|---:|---:|
| benign | benign | stream_f1 | 0 | nan | [nan, nan] |
| benign | benign | owner_f1 | 0 | nan | [nan, nan] |
| benign | benign | contested_f1 | 0 | nan | [nan, nan] |
| benign | benign | clean_fpr | 1 | 0 | [nan, nan] |
| benign | benign | malicious_opportunity_reception_rate | 0 | nan | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p2 | stream_f1 | 1 | 0.8 | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p2 | owner_f1 | 1 | 0.5 | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p2 | contested_f1 | 1 | 0.5 | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p2 | clean_fpr | 1 | 0 | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p2 | malicious_opportunity_reception_rate | 1 | 0.9 | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p5 | stream_f1 | 1 | 0.666667 | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p5 | owner_f1 | 1 | 0.666667 | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p5 | contested_f1 | 1 | 0.285714 | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p5 | clean_fpr | 1 | 0 | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p5 | malicious_opportunity_reception_rate | 1 | 0.75 | [nan, nan] |
| mobility | manoeuvre | stream_f1 | 1 | 0.6 | [nan, nan] |
| mobility | manoeuvre | owner_f1 | 1 | 0.571429 | [nan, nan] |
| mobility | manoeuvre | contested_f1 | 1 | 0.25 | [nan, nan] |
| mobility | manoeuvre | clean_fpr | 1 | 0 | [nan, nan] |
| mobility | manoeuvre | malicious_opportunity_reception_rate | 1 | 0.875 | [nan, nan] |
| noise_misspecification | actual_2_assumed_4 | stream_f1 | 1 | 0.666667 | [nan, nan] |
| noise_misspecification | actual_2_assumed_4 | owner_f1 | 1 | 0.666667 | [nan, nan] |
| noise_misspecification | actual_2_assumed_4 | contested_f1 | 1 | 0.285714 | [nan, nan] |
| noise_misspecification | actual_2_assumed_4 | clean_fpr | 1 | 0 | [nan, nan] |
| noise_misspecification | actual_2_assumed_4 | malicious_opportunity_reception_rate | 1 | 0.75 | [nan, nan] |
| noise_misspecification | actual_4_assumed_2 | stream_f1 | 1 | 0.666667 | [nan, nan] |
| noise_misspecification | actual_4_assumed_2 | owner_f1 | 1 | 0.666667 | [nan, nan] |
| noise_misspecification | actual_4_assumed_2 | contested_f1 | 1 | 0.285714 | [nan, nan] |
| noise_misspecification | actual_4_assumed_2 | clean_fpr | 1 | 0 | [nan, nan] |
| noise_misspecification | actual_4_assumed_2 | malicious_opportunity_reception_rate | 1 | 0.75 | [nan, nan] |
| noise_misspecification | actual_8_assumed_2 | stream_f1 | 1 | 0.571429 | [nan, nan] |
| noise_misspecification | actual_8_assumed_2 | owner_f1 | 1 | 0.545455 | [nan, nan] |
| noise_misspecification | actual_8_assumed_2 | contested_f1 | 1 | 0.285714 | [nan, nan] |
| noise_misspecification | actual_8_assumed_2 | clean_fpr | 1 | 0.8 | [nan, nan] |
| noise_misspecification | actual_8_assumed_2 | malicious_opportunity_reception_rate | 1 | 0.75 | [nan, nan] |
| pure_attack | pure_constoffset | stream_f1 | 1 | 1 | [nan, nan] |
| pure_attack | pure_constoffset | owner_f1 | 1 | 1 | [nan, nan] |
| pure_attack | pure_constoffset | contested_f1 | 1 | 0 | [nan, nan] |
| pure_attack | pure_constoffset | clean_fpr | 1 | 0 | [nan, nan] |
| pure_attack | pure_constoffset | malicious_opportunity_reception_rate | 1 | 1 | [nan, nan] |
| pure_attack | pure_dos | stream_f1 | 1 | 1 | [nan, nan] |
| pure_attack | pure_dos | owner_f1 | 1 | 1 | [nan, nan] |
| pure_attack | pure_dos | contested_f1 | 1 | 0 | [nan, nan] |
| pure_attack | pure_dos | clean_fpr | 1 | 0 | [nan, nan] |
| pure_attack | pure_dos | malicious_opportunity_reception_rate | 1 | 1 | [nan, nan] |
| pure_attack | pure_falsify | stream_f1 | 1 | 1 | [nan, nan] |
| pure_attack | pure_falsify | owner_f1 | 1 | 1 | [nan, nan] |
| pure_attack | pure_falsify | contested_f1 | 1 | 0 | [nan, nan] |
| pure_attack | pure_falsify | clean_fpr | 1 | 0 | [nan, nan] |
| pure_attack | pure_falsify | malicious_opportunity_reception_rate | 1 | 1 | [nan, nan] |
| pure_attack | pure_replay | stream_f1 | 1 | 1 | [nan, nan] |
| pure_attack | pure_replay | owner_f1 | 1 | 0 | [nan, nan] |
| pure_attack | pure_replay | contested_f1 | 1 | 0.666667 | [nan, nan] |
| pure_attack | pure_replay | clean_fpr | 1 | 0 | [nan, nan] |
| pure_attack | pure_replay | malicious_opportunity_reception_rate | 1 | 1 | [nan, nan] |
| pure_attack | pure_revheading | stream_f1 | 1 | 1 | [nan, nan] |
| pure_attack | pure_revheading | owner_f1 | 1 | 1 | [nan, nan] |
| pure_attack | pure_revheading | contested_f1 | 1 | 0 | [nan, nan] |
| pure_attack | pure_revheading | clean_fpr | 1 | 0 | [nan, nan] |
| pure_attack | pure_revheading | malicious_opportunity_reception_rate | 1 | 1 | [nan, nan] |
| pure_attack | pure_slydos | stream_f1 | 1 | 0 | [nan, nan] |
| pure_attack | pure_slydos | owner_f1 | 1 | 0 | [nan, nan] |
| pure_attack | pure_slydos | contested_f1 | 1 | 0 | [nan, nan] |
| pure_attack | pure_slydos | clean_fpr | 1 | 0 | [nan, nan] |
| pure_attack | pure_slydos | malicious_opportunity_reception_rate | 1 | 1 | [nan, nan] |
| pure_attack | pure_spoof | stream_f1 | 1 | 0.666667 | [nan, nan] |
| pure_attack | pure_spoof | owner_f1 | 1 | 0 | [nan, nan] |
| pure_attack | pure_spoof | contested_f1 | 1 | 0.666667 | [nan, nan] |
| pure_attack | pure_spoof | clean_fpr | 1 | 0 | [nan, nan] |
| pure_attack | pure_spoof | malicious_opportunity_reception_rate | 1 | 1 | [nan, nan] |
| scale | scale_n_21 | stream_f1 | 1 | 0.909091 | [nan, nan] |
| scale | scale_n_21 | owner_f1 | 1 | 0.5 | [nan, nan] |
| scale | scale_n_21 | contested_f1 | 1 | 0.666667 | [nan, nan] |
| scale | scale_n_21 | clean_fpr | 1 | 0 | [nan, nan] |
| scale | scale_n_21 | malicious_opportunity_reception_rate | 1 | 0.75 | [nan, nan] |
| scale | scale_n_7 | stream_f1 | 1 | 0 | [nan, nan] |
| scale | scale_n_7 | owner_f1 | 0 | nan | [nan, nan] |
| scale | scale_n_7 | contested_f1 | 1 | 0 | [nan, nan] |
| scale | scale_n_7 | clean_fpr | 1 | 0 | [nan, nan] |
| scale | scale_n_7 | malicious_opportunity_reception_rate | 0 | nan | [nan, nan] |
| score_variant | reference_half_life_1p351 | stream_f1 | 1 | 0.666667 | [nan, nan] |
| score_variant | reference_half_life_1p351 | owner_f1 | 1 | 0.666667 | [nan, nan] |
| score_variant | reference_half_life_1p351 | contested_f1 | 1 | 0.285714 | [nan, nan] |
| score_variant | reference_half_life_1p351 | clean_fpr | 1 | 0 | [nan, nan] |
| score_variant | reference_half_life_1p351 | malicious_opportunity_reception_rate | 1 | 0.75 | [nan, nan] |
| score_variant | reference_no_forgetting | stream_f1 | 1 | 0.666667 | [nan, nan] |
| score_variant | reference_no_forgetting | owner_f1 | 1 | 0.666667 | [nan, nan] |
| score_variant | reference_no_forgetting | contested_f1 | 1 | 0.285714 | [nan, nan] |
| score_variant | reference_no_forgetting | clean_fpr | 1 | 0 | [nan, nan] |
| score_variant | reference_no_forgetting | malicious_opportunity_reception_rate | 1 | 0.75 | [nan, nan] |
| steady_state | pure_constoffset_steady | stream_f1 | 1 | 0 | [nan, nan] |
| steady_state | pure_constoffset_steady | owner_f1 | 1 | 0 | [nan, nan] |
| steady_state | pure_constoffset_steady | contested_f1 | 1 | 0 | [nan, nan] |
| steady_state | pure_constoffset_steady | clean_fpr | 1 | 0 | [nan, nan] |
| steady_state | pure_constoffset_steady | malicious_opportunity_reception_rate | 1 | 1 | [nan, nan] |
| steady_state | pure_falsify_steady | stream_f1 | 1 | 1 | [nan, nan] |
| steady_state | pure_falsify_steady | owner_f1 | 1 | 1 | [nan, nan] |
| steady_state | pure_falsify_steady | contested_f1 | 1 | 0 | [nan, nan] |
| steady_state | pure_falsify_steady | clean_fpr | 1 | 0 | [nan, nan] |
| steady_state | pure_falsify_steady | malicious_opportunity_reception_rate | 1 | 1 | [nan, nan] |
| steady_state | pure_revheading_steady | stream_f1 | 1 | 1 | [nan, nan] |
| steady_state | pure_revheading_steady | owner_f1 | 1 | 1 | [nan, nan] |
| steady_state | pure_revheading_steady | contested_f1 | 1 | 0 | [nan, nan] |
| steady_state | pure_revheading_steady | clean_fpr | 1 | 0 | [nan, nan] |
| steady_state | pure_revheading_steady | malicious_opportunity_reception_rate | 1 | 1 | [nan, nan] |
| steady_state | pure_slydos_steady | stream_f1 | 1 | 0 | [nan, nan] |
| steady_state | pure_slydos_steady | owner_f1 | 1 | 0 | [nan, nan] |
| steady_state | pure_slydos_steady | contested_f1 | 1 | 0 | [nan, nan] |
| steady_state | pure_slydos_steady | clean_fpr | 1 | 0 | [nan, nan] |
| steady_state | pure_slydos_steady | malicious_opportunity_reception_rate | 1 | 1 | [nan, nan] |

Machine-readable tables: `metrics_v4.csv`, `paired_differences_v4.csv`, `peak_score_discrimination_v4.csv`, and `survival_v4.csv`.
