# v4 experiment report

- Mode: **full**
- Runs: 1479 (439 validation, 1040 frozen-threshold test)
- Frozen threshold: `0.498`
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
| benign_stress | clock_offset_sigma_0p10 | stream_f1 | 0 | nan | [nan, nan] |
| benign_stress | clock_offset_sigma_0p10 | owner_f1 | 0 | nan | [nan, nan] |
| benign_stress | clock_offset_sigma_0p10 | contested_f1 | 0 | nan | [nan, nan] |
| benign_stress | clock_offset_sigma_0p10 | clean_fpr | 30 | 0 | [0, 0] |
| benign_stress | clock_offset_sigma_0p10 | malicious_opportunity_reception_rate | 0 | nan | [nan, nan] |
| benign_stress | gnss_sigma_4_assumed_2 | stream_f1 | 30 | 0 | [0, 0] |
| benign_stress | gnss_sigma_4_assumed_2 | owner_f1 | 30 | 0 | [0, 0] |
| benign_stress | gnss_sigma_4_assumed_2 | contested_f1 | 0 | nan | [nan, nan] |
| benign_stress | gnss_sigma_4_assumed_2 | clean_fpr | 30 | 0.0180648 | [0.0162916, 0.0199079] |
| benign_stress | gnss_sigma_4_assumed_2 | malicious_opportunity_reception_rate | 0 | nan | [nan, nan] |
| benign_stress | gnss_sigma_8_assumed_2 | stream_f1 | 30 | 0 | [0, 0] |
| benign_stress | gnss_sigma_8_assumed_2 | owner_f1 | 30 | 0 | [0, 0] |
| benign_stress | gnss_sigma_8_assumed_2 | contested_f1 | 0 | nan | [nan, nan] |
| benign_stress | gnss_sigma_8_assumed_2 | clean_fpr | 30 | 0.686834 | [0.681622, 0.692148] |
| benign_stress | gnss_sigma_8_assumed_2 | malicious_opportunity_reception_rate | 0 | nan | [nan, nan] |
| mixedhard_prevalence | mixedhard_frac_0p1 | stream_f1 | 30 | 0.861104 | [0.848837, 0.87246] |
| mixedhard_prevalence | mixedhard_frac_0p1 | owner_f1 | 30 | 0.46164 | [0.43249, 0.489412] |
| mixedhard_prevalence | mixedhard_frac_0p1 | contested_f1 | 30 | 0.591482 | [0.559995, 0.62117] |
| mixedhard_prevalence | mixedhard_frac_0p1 | clean_fpr | 30 | 0 | [0, 0] |
| mixedhard_prevalence | mixedhard_frac_0p1 | malicious_opportunity_reception_rate | 30 | 0.857032 | [0.838882, 0.874284] |
| mixedhard_prevalence | mixedhard_frac_0p2 | stream_f1 | 30 | 0.865713 | [0.856318, 0.875032] |
| mixedhard_prevalence | mixedhard_frac_0p2 | owner_f1 | 30 | 0.516502 | [0.49041, 0.542087] |
| mixedhard_prevalence | mixedhard_frac_0p2 | contested_f1 | 30 | 0.594802 | [0.574762, 0.615055] |
| mixedhard_prevalence | mixedhard_frac_0p2 | clean_fpr | 30 | 0 | [0, 0] |
| mixedhard_prevalence | mixedhard_frac_0p2 | malicious_opportunity_reception_rate | 30 | 0.867138 | [0.856409, 0.877845] |
| mixedhard_prevalence | mixedhard_frac_0p3 | stream_f1 | 30 | 0.870356 | [0.860585, 0.880089] |
| mixedhard_prevalence | mixedhard_frac_0p3 | owner_f1 | 30 | 0.572701 | [0.553585, 0.592827] |
| mixedhard_prevalence | mixedhard_frac_0p3 | contested_f1 | 30 | 0.610759 | [0.589426, 0.631402] |
| mixedhard_prevalence | mixedhard_frac_0p3 | clean_fpr | 30 | 0 | [0, 0] |
| mixedhard_prevalence | mixedhard_frac_0p3 | malicious_opportunity_reception_rate | 30 | 0.879687 | [0.871288, 0.887734] |
| mixedhard_prevalence | mixedhard_frac_0p5 | stream_f1 | 30 | 0.87807 | [0.869178, 0.885781] |
| mixedhard_prevalence | mixedhard_frac_0p5 | owner_f1 | 30 | 0.66794 | [0.655281, 0.681301] |
| mixedhard_prevalence | mixedhard_frac_0p5 | contested_f1 | 30 | 0.643638 | [0.627796, 0.658341] |
| mixedhard_prevalence | mixedhard_frac_0p5 | clean_fpr | 30 | 0 | [0, 0] |
| mixedhard_prevalence | mixedhard_frac_0p5 | malicious_opportunity_reception_rate | 30 | 0.898387 | [0.891786, 0.904995] |
| mobility | manoeuvre | stream_f1 | 30 | 0.866199 | [0.856157, 0.87628] |
| mobility | manoeuvre | owner_f1 | 30 | 0.572612 | [0.556197, 0.58924] |
| mobility | manoeuvre | contested_f1 | 30 | 0.611136 | [0.587301, 0.634059] |
| mobility | manoeuvre | clean_fpr | 30 | 0 | [0, 0] |
| mobility | manoeuvre | malicious_opportunity_reception_rate | 30 | 0.875169 | [0.867605, 0.882919] |
| noise_misspecification | actual_2_assumed_4 | stream_f1 | 30 | 0.870133 | [0.860263, 0.880323] |
| noise_misspecification | actual_2_assumed_4 | owner_f1 | 30 | 0.572321 | [0.553561, 0.592279] |
| noise_misspecification | actual_2_assumed_4 | contested_f1 | 30 | 0.610759 | [0.589009, 0.63179] |
| noise_misspecification | actual_2_assumed_4 | clean_fpr | 30 | 0 | [0, 0] |
| noise_misspecification | actual_2_assumed_4 | malicious_opportunity_reception_rate | 30 | 0.879687 | [0.871665, 0.887486] |
| noise_misspecification | actual_4_assumed_2 | stream_f1 | 30 | 0.864006 | [0.854374, 0.873509] |
| noise_misspecification | actual_4_assumed_2 | owner_f1 | 30 | 0.56652 | [0.547681, 0.585983] |
| noise_misspecification | actual_4_assumed_2 | contested_f1 | 30 | 0.610759 | [0.588772, 0.631263] |
| noise_misspecification | actual_4_assumed_2 | clean_fpr | 30 | 0.0158277 | [0.0139503, 0.0177551] |
| noise_misspecification | actual_4_assumed_2 | malicious_opportunity_reception_rate | 30 | 0.879687 | [0.871263, 0.887686] |
| noise_misspecification | actual_8_assumed_2 | stream_f1 | 30 | 0.679266 | [0.667061, 0.691325] |
| noise_misspecification | actual_8_assumed_2 | owner_f1 | 30 | 0.42621 | [0.418377, 0.434446] |
| noise_misspecification | actual_8_assumed_2 | contested_f1 | 30 | 0.610759 | [0.58934, 0.631599] |
| noise_misspecification | actual_8_assumed_2 | clean_fpr | 30 | 0.673511 | [0.665879, 0.680734] |
| noise_misspecification | actual_8_assumed_2 | malicious_opportunity_reception_rate | 30 | 0.879687 | [0.871825, 0.887765] |
| onset_guard | constoffset_guard_0p25 | stream_f1 | 30 | 0.399115 | [0.380296, 0.420216] |
| onset_guard | constoffset_guard_0p25 | owner_f1 | 30 | 0.399115 | [0.380136, 0.420717] |
| onset_guard | constoffset_guard_0p25 | contested_f1 | 30 | 0 | [0, 0] |
| onset_guard | constoffset_guard_0p25 | clean_fpr | 30 | 0 | [0, 0] |
| onset_guard | constoffset_guard_0p25 | malicious_opportunity_reception_rate | 30 | 0.978609 | [0.975431, 0.981821] |
| onset_guard | constoffset_guard_0p5 | stream_f1 | 30 | 0.397506 | [0.3787, 0.418755] |
| onset_guard | constoffset_guard_0p5 | owner_f1 | 30 | 0.397506 | [0.378447, 0.418778] |
| onset_guard | constoffset_guard_0p5 | contested_f1 | 30 | 0 | [0, 0] |
| onset_guard | constoffset_guard_0p5 | clean_fpr | 30 | 0 | [0, 0] |
| onset_guard | constoffset_guard_0p5 | malicious_opportunity_reception_rate | 30 | 0.979229 | [0.97607, 0.982338] |
| onset_guard | constoffset_guard_1p0 | stream_f1 | 30 | 0.392846 | [0.374366, 0.414021] |
| onset_guard | constoffset_guard_1p0 | owner_f1 | 30 | 0.392846 | [0.374047, 0.414569] |
| onset_guard | constoffset_guard_1p0 | contested_f1 | 30 | 0 | [0, 0] |
| onset_guard | constoffset_guard_1p0 | clean_fpr | 30 | 0 | [0, 0] |
| onset_guard | constoffset_guard_1p0 | malicious_opportunity_reception_rate | 30 | 0.978876 | [0.975974, 0.981874] |
| onset_time | constoffset_onset_20s | stream_f1 | 30 | 0.471338 | [0.455689, 0.487683] |
| onset_time | constoffset_onset_20s | owner_f1 | 30 | 0.471338 | [0.45605, 0.487018] |
| onset_time | constoffset_onset_20s | contested_f1 | 30 | 0 | [0, 0] |
| onset_time | constoffset_onset_20s | clean_fpr | 30 | 0 | [0, 0] |
| onset_time | constoffset_onset_20s | malicious_opportunity_reception_rate | 30 | 0.97168 | [0.968251, 0.975173] |
| onset_time | constoffset_onset_5s | stream_f1 | 30 | 0.365377 | [0.348566, 0.383757] |
| onset_time | constoffset_onset_5s | owner_f1 | 30 | 0.365377 | [0.348035, 0.383643] |
| onset_time | constoffset_onset_5s | contested_f1 | 30 | 0 | [0, 0] |
| onset_time | constoffset_onset_5s | clean_fpr | 30 | 0 | [0, 0] |
| onset_time | constoffset_onset_5s | malicious_opportunity_reception_rate | 30 | 0.980462 | [0.97738, 0.983595] |
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
| pure_attack | pure_replay | contested_f1 | 30 | 0.904656 | [0.89953, 0.909704] |
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
| pure_attack | pure_spoof | stream_f1 | 30 | 0.683017 | [0.659227, 0.707299] |
| pure_attack | pure_spoof | owner_f1 | 30 | 0 | [0, 0] |
| pure_attack | pure_spoof | contested_f1 | 30 | 0.705893 | [0.683991, 0.729565] |
| pure_attack | pure_spoof | clean_fpr | 30 | 0 | [0, 0] |
| pure_attack | pure_spoof | malicious_opportunity_reception_rate | 30 | 0.979949 | [0.977013, 0.983075] |
| scale | scale_n_105 | stream_f1 | 30 | 0.874978 | [0.867657, 0.881966] |
| scale | scale_n_105 | owner_f1 | 30 | 0.503167 | [0.485337, 0.52134] |
| scale | scale_n_105 | contested_f1 | 30 | 0.637835 | [0.617659, 0.655096] |
| scale | scale_n_105 | clean_fpr | 30 | 0 | [0, 0] |
| scale | scale_n_105 | malicious_opportunity_reception_rate | 30 | 0.849463 | [0.842644, 0.856269] |
| scale | scale_n_35 | stream_f1 | 30 | 0.845898 | [0.827335, 0.862759] |
| scale | scale_n_35 | owner_f1 | 30 | 0.547551 | [0.513342, 0.580874] |
| scale | scale_n_35 | contested_f1 | 30 | 0.487704 | [0.430147, 0.545169] |
| scale | scale_n_35 | clean_fpr | 30 | 0 | [0, 0] |
| scale | scale_n_35 | malicious_opportunity_reception_rate | 30 | 0.904619 | [0.889203, 0.920013] |
| score_variant | reference_half_life_1p351 | stream_f1 | 30 | 0.868281 | [0.858192, 0.877834] |
| score_variant | reference_half_life_1p351 | owner_f1 | 30 | 0.572876 | [0.553827, 0.593033] |
| score_variant | reference_half_life_1p351 | contested_f1 | 30 | 0.610759 | [0.589222, 0.631467] |
| score_variant | reference_half_life_1p351 | clean_fpr | 30 | 0 | [0, 0] |
| score_variant | reference_half_life_1p351 | malicious_opportunity_reception_rate | 30 | 0.879687 | [0.871624, 0.887696] |
| score_variant | reference_no_forgetting | stream_f1 | 30 | 0.871322 | [0.86122, 0.88096] |
| score_variant | reference_no_forgetting | owner_f1 | 30 | 0.572814 | [0.553215, 0.593658] |
| score_variant | reference_no_forgetting | contested_f1 | 30 | 0.610759 | [0.589622, 0.632189] |
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
