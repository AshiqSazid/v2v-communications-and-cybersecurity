# v4 experiment report

- Mode: **full**
- Runs: 1209 (439 validation, 770 frozen-threshold test)
- Frozen threshold: `0.497`
- Endpoint: `window_peak_score > threshold`, applied identically to malicious and non-malicious streams over the evaluation window W = [max(warmup, attack_start + onset_blank), sim_time]. Pairs with no reception inside W are excluded from every arm rather than counted as true negatives.
- Endpoint audit: every pair row was checked to satisfy `window_alert == (window_peak_score > threshold)`; timing arms suppress pair output by design.
- Because the ROC curve ranks the same statistic the operating point thresholds, the reported (FPR, TPR) point lies on the reported curve by construction.
- Victim framing uses the same window and rule as every other decision; pre-onset excursions are excluded by W, not by a label-dependent rule.
- Selection constraint and reported clean FPR are different estimands: the frozen threshold bounds P(a benign run raises any false positive), while `clean_fpr` is a per-pair rate inside attack runs. The bound does not transfer to that column.
- Bounded primary metrics: two-sided 95% percentile intervals from 5000 deterministic RNG-seed-block bootstrap replicates.
- Other scalar metrics: two-sided 95% Student-t intervals over RNG seeds.
- Time to detection: Kaplan–Meier restricted mean with explicit right censoring and one common preregistered horizon of 20 s.
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
| benign | benign | clean_fpr | 50 | 0 | [0, 0] |
| benign | benign | malicious_opportunity_reception_rate | 0 | nan | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p1 | stream_f1 | 30 | 0.861104 | [0.848837, 0.87246] |
| mixedhard_prevalence | mixedhard_frac_0p1 | owner_f1 | 30 | 0.46164 | [0.43249, 0.489412] |
| mixedhard_prevalence | mixedhard_frac_0p1 | contested_f1 | 30 | 0.609014 | [0.577627, 0.638569] |
| mixedhard_prevalence | mixedhard_frac_0p1 | clean_fpr | 30 | 0 | [0, 0] |
| mixedhard_prevalence | mixedhard_frac_0p1 | malicious_opportunity_reception_rate | 30 | 0.857032 | [0.838882, 0.874284] |
| mixedhard_prevalence | mixedhard_frac_0p2 | stream_f1 | 30 | 0.865735 | [0.856327, 0.875056] |
| mixedhard_prevalence | mixedhard_frac_0p2 | owner_f1 | 30 | 0.516551 | [0.49041, 0.542134] |
| mixedhard_prevalence | mixedhard_frac_0p2 | contested_f1 | 30 | 0.615496 | [0.594465, 0.635697] |
| mixedhard_prevalence | mixedhard_frac_0p2 | clean_fpr | 30 | 0 | [0, 0] |
| mixedhard_prevalence | mixedhard_frac_0p2 | malicious_opportunity_reception_rate | 30 | 0.867138 | [0.856409, 0.877845] |
| mixedhard_prevalence | mixedhard_frac_0p3 | stream_f1 | 30 | 0.870379 | [0.860608, 0.880112] |
| mixedhard_prevalence | mixedhard_frac_0p3 | owner_f1 | 30 | 0.572743 | [0.553668, 0.592858] |
| mixedhard_prevalence | mixedhard_frac_0p3 | contested_f1 | 30 | 0.631023 | [0.609847, 0.65201] |
| mixedhard_prevalence | mixedhard_frac_0p3 | clean_fpr | 30 | 0 | [0, 0] |
| mixedhard_prevalence | mixedhard_frac_0p3 | malicious_opportunity_reception_rate | 30 | 0.879687 | [0.871288, 0.887734] |
| mixedhard_prevalence | mixedhard_frac_0p5 | stream_f1 | 30 | 0.878094 | [0.869194, 0.885807] |
| mixedhard_prevalence | mixedhard_frac_0p5 | owner_f1 | 30 | 0.667976 | [0.655389, 0.681322] |
| mixedhard_prevalence | mixedhard_frac_0p5 | contested_f1 | 30 | 0.667493 | [0.650441, 0.683185] |
| mixedhard_prevalence | mixedhard_frac_0p5 | clean_fpr | 30 | 0 | [0, 0] |
| mixedhard_prevalence | mixedhard_frac_0p5 | malicious_opportunity_reception_rate | 30 | 0.898387 | [0.891786, 0.904995] |
| noise_misspecification | actual_2_assumed_4 | stream_f1 | 30 | 0.870156 | [0.860268, 0.880352] |
| noise_misspecification | actual_2_assumed_4 | owner_f1 | 30 | 0.572363 | [0.553604, 0.592305] |
| noise_misspecification | actual_2_assumed_4 | contested_f1 | 30 | 0.631023 | [0.60927, 0.651984] |
| noise_misspecification | actual_2_assumed_4 | clean_fpr | 30 | 0 | [0, 0] |
| noise_misspecification | actual_2_assumed_4 | malicious_opportunity_reception_rate | 30 | 0.879687 | [0.871665, 0.887486] |
| noise_misspecification | actual_4_assumed_2 | stream_f1 | 30 | 0.863994 | [0.854325, 0.873479] |
| noise_misspecification | actual_4_assumed_2 | owner_f1 | 30 | 0.566555 | [0.547741, 0.585951] |
| noise_misspecification | actual_4_assumed_2 | contested_f1 | 30 | 0.631023 | [0.608824, 0.651553] |
| noise_misspecification | actual_4_assumed_2 | clean_fpr | 30 | 0.0159357 | [0.014043, 0.0178961] |
| noise_misspecification | actual_4_assumed_2 | malicious_opportunity_reception_rate | 30 | 0.879687 | [0.871263, 0.887686] |
| noise_misspecification | actual_8_assumed_2 | stream_f1 | 30 | 0.679335 | [0.667113, 0.691425] |
| noise_misspecification | actual_8_assumed_2 | owner_f1 | 30 | 0.426207 | [0.418396, 0.434442] |
| noise_misspecification | actual_8_assumed_2 | contested_f1 | 30 | 0.631023 | [0.609752, 0.651477] |
| noise_misspecification | actual_8_assumed_2 | clean_fpr | 30 | 0.673546 | [0.665892, 0.680793] |
| noise_misspecification | actual_8_assumed_2 | malicious_opportunity_reception_rate | 30 | 0.879687 | [0.871825, 0.887765] |
| pure_attack | pure_constoffset | stream_f1 | 30 | 0.40169 | [0.381801, 0.423882] |
| pure_attack | pure_constoffset | owner_f1 | 30 | 0.40169 | [0.381957, 0.424167] |
| pure_attack | pure_constoffset | contested_f1 | 30 | 0 | [0, 0] |
| pure_attack | pure_constoffset | clean_fpr | 30 | 0 | [0, 0] |
| pure_attack | pure_constoffset | malicious_opportunity_reception_rate | 30 | 0.97956 | [0.976769, 0.982447] |
| pure_attack | pure_dos | stream_f1 | 30 | 0.93165 | [0.928189, 0.93532] |
| pure_attack | pure_dos | owner_f1 | 30 | 0.93165 | [0.928331, 0.935139] |
| pure_attack | pure_dos | contested_f1 | 30 | 0 | [0, 0] |
| pure_attack | pure_dos | clean_fpr | 30 | 0 | [0, 0] |
| pure_attack | pure_dos | malicious_opportunity_reception_rate | 30 | 0.99464 | [0.992786, 0.99639] |
| pure_attack | pure_falsify | stream_f1 | 30 | 0.989453 | [0.987953, 0.99091] |
| pure_attack | pure_falsify | owner_f1 | 30 | 0.989453 | [0.987951, 0.990908] |
| pure_attack | pure_falsify | contested_f1 | 30 | 0 | [0, 0] |
| pure_attack | pure_falsify | clean_fpr | 30 | 0 | [0, 0] |
| pure_attack | pure_falsify | malicious_opportunity_reception_rate | 30 | 0.97956 | [0.976827, 0.98239] |
| pure_attack | pure_replay | stream_f1 | 30 | 0.965814 | [0.963747, 0.967878] |
| pure_attack | pure_replay | owner_f1 | 30 | 0.373421 | [0.355781, 0.392482] |
| pure_attack | pure_replay | contested_f1 | 30 | 0.922018 | [0.917921, 0.92619] |
| pure_attack | pure_replay | clean_fpr | 30 | 0 | [0, 0] |
| pure_attack | pure_replay | malicious_opportunity_reception_rate | 30 | 0.895539 | [0.889919, 0.901047] |
| pure_attack | pure_revheading | stream_f1 | 30 | 0.980012 | [0.978153, 0.981781] |
| pure_attack | pure_revheading | owner_f1 | 30 | 0.980012 | [0.978157, 0.981802] |
| pure_attack | pure_revheading | contested_f1 | 30 | 0 | [0, 0] |
| pure_attack | pure_revheading | clean_fpr | 30 | 0 | [0, 0] |
| pure_attack | pure_revheading | malicious_opportunity_reception_rate | 30 | 0.97956 | [0.976812, 0.982345] |
| pure_attack | pure_slydos | stream_f1 | 30 | 0 | [0, 0] |
| pure_attack | pure_slydos | owner_f1 | 30 | 0 | [0, 0] |
| pure_attack | pure_slydos | contested_f1 | 30 | 0 | [0, 0] |
| pure_attack | pure_slydos | clean_fpr | 30 | 0 | [0, 0] |
| pure_attack | pure_slydos | malicious_opportunity_reception_rate | 30 | 0.984417 | [0.981711, 0.987039] |
| pure_attack | pure_spoof | stream_f1 | 30 | 0.683147 | [0.659417, 0.70744] |
| pure_attack | pure_spoof | owner_f1 | 30 | 0 | [0, 0] |
| pure_attack | pure_spoof | contested_f1 | 30 | 0.720854 | [0.69979, 0.743223] |
| pure_attack | pure_spoof | clean_fpr | 30 | 0 | [0, 0] |
| pure_attack | pure_spoof | malicious_opportunity_reception_rate | 30 | 0.979949 | [0.977013, 0.983075] |
| scale | scale_n_105 | stream_f1 | 30 | 0.87499 | [0.867658, 0.881982] |
| scale | scale_n_105 | owner_f1 | 30 | 0.503159 | [0.485322, 0.52134] |
| scale | scale_n_105 | contested_f1 | 30 | 0.661185 | [0.640991, 0.678277] |
| scale | scale_n_105 | clean_fpr | 30 | 0 | [0, 0] |
| scale | scale_n_105 | malicious_opportunity_reception_rate | 30 | 0.849463 | [0.842644, 0.856269] |
| scale | scale_n_35 | stream_f1 | 30 | 0.845898 | [0.827335, 0.862759] |
| scale | scale_n_35 | owner_f1 | 30 | 0.547551 | [0.513342, 0.580874] |
| scale | scale_n_35 | contested_f1 | 30 | 0.504382 | [0.446812, 0.561395] |
| scale | scale_n_35 | clean_fpr | 30 | 0 | [0, 0] |
| scale | scale_n_35 | malicious_opportunity_reception_rate | 30 | 0.904619 | [0.889203, 0.920013] |
| score_variant | reference_half_life_1p351 | stream_f1 | 30 | 0.868323 | [0.858227, 0.877857] |
| score_variant | reference_half_life_1p351 | owner_f1 | 30 | 0.572898 | [0.553817, 0.593074] |
| score_variant | reference_half_life_1p351 | contested_f1 | 30 | 0.631023 | [0.609506, 0.651697] |
| score_variant | reference_half_life_1p351 | clean_fpr | 30 | 0 | [0, 0] |
| score_variant | reference_half_life_1p351 | malicious_opportunity_reception_rate | 30 | 0.879687 | [0.871624, 0.887696] |
| score_variant | reference_no_forgetting | stream_f1 | 30 | 0.871322 | [0.86122, 0.88096] |
| score_variant | reference_no_forgetting | owner_f1 | 30 | 0.572814 | [0.553215, 0.593658] |
| score_variant | reference_no_forgetting | contested_f1 | 30 | 0.631023 | [0.609935, 0.652356] |
| score_variant | reference_no_forgetting | clean_fpr | 30 | 0 | [0, 0] |
| score_variant | reference_no_forgetting | malicious_opportunity_reception_rate | 30 | 0.879687 | [0.871241, 0.887771] |
| steady_state | pure_constoffset_steady | stream_f1 | 30 | 0.000240674 | [0, 0.000722022] |
| steady_state | pure_constoffset_steady | owner_f1 | 30 | 0.000240674 | [0, 0.000722022] |
| steady_state | pure_constoffset_steady | contested_f1 | 30 | 0 | [0, 0] |
| steady_state | pure_constoffset_steady | clean_fpr | 30 | 0 | [0, 0] |
| steady_state | pure_constoffset_steady | malicious_opportunity_reception_rate | 30 | 0.97956 | [0.97678, 0.982315] |
| steady_state | pure_falsify_steady | stream_f1 | 30 | 0.988185 | [0.986713, 0.989661] |
| steady_state | pure_falsify_steady | owner_f1 | 30 | 0.988185 | [0.986663, 0.989634] |
| steady_state | pure_falsify_steady | contested_f1 | 30 | 0 | [0, 0] |
| steady_state | pure_falsify_steady | clean_fpr | 30 | 0 | [0, 0] |
| steady_state | pure_falsify_steady | malicious_opportunity_reception_rate | 30 | 0.97956 | [0.976807, 0.982422] |
| steady_state | pure_revheading_steady | stream_f1 | 30 | 0.980012 | [0.978151, 0.981763] |
| steady_state | pure_revheading_steady | owner_f1 | 30 | 0.980012 | [0.978159, 0.981825] |
| steady_state | pure_revheading_steady | contested_f1 | 30 | 0 | [0, 0] |
| steady_state | pure_revheading_steady | clean_fpr | 30 | 0 | [0, 0] |
| steady_state | pure_revheading_steady | malicious_opportunity_reception_rate | 30 | 0.97956 | [0.976761, 0.982353] |
| steady_state | pure_slydos_steady | stream_f1 | 30 | 0 | [0, 0] |
| steady_state | pure_slydos_steady | owner_f1 | 30 | 0 | [0, 0] |
| steady_state | pure_slydos_steady | contested_f1 | 30 | 0 | [0, 0] |
| steady_state | pure_slydos_steady | clean_fpr | 30 | 0 | [0, 0] |
| steady_state | pure_slydos_steady | malicious_opportunity_reception_rate | 30 | 0.985472 | [0.982938, 0.987883] |

Machine-readable tables: `metrics_v4.csv`, `paired_differences_v4.csv`, `peak_score_discrimination_v4.csv`, and `survival_v4.csv`.
