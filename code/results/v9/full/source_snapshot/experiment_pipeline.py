#!/usr/bin/env python3
"""Strict orchestration helpers for the v4 ns-3 experiment workflow.

The shell entry point is ``run_experiments.sh``.  This module deliberately
keeps every simulation in its own directory, validates it before marking it
complete, and merges artifacts only in the deterministic order of the plan.
It never treats a partial or malformed run as data.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import shlex
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence


PLAN_FIELDS = (
    "experiment_id",
    "mode",
    "stage",
    "family",
    "arm",
    "replicate",
    "seed",
    "serial",
    "args_json",
)
META_FIELDS = PLAN_FIELDS[:-1]
MERGE_META_FIELDS = (*META_FIELDS, "wall_duration_s")
SUMMARY_REQUIRED = {
    "schema",
    "n",
    "frac",
    "n_attackers",
    "attack",
    "run",
    "sim_time",
    "interval",
    "detector",
    "score_model",
    "threshold",
    "decay",
    "decay_half_life_s",
    "warmup",
    "attack_start_s",
    "comm_range",
    "gps_sigma",
    "detector_gps_sigma",
    "spd_sigma",
    "clock_sigma",
    "bsm_bytes",
    "assigned_attacker_rx",
    "attack_active_rx",
    "malicious_rx",
    "malicious_expected_pairs",
    "malicious_expected_pairs_observed",
    "malicious_observed_pairs_any_range",
    "malicious_zero_reception_pairs",
    "stream_tp",
    "stream_fp",
    "stream_tn",
    "stream_fn",
    "clean_fp",
    "clean_tn",
    "contested_tp",
    "contested_fp",
    "contested_tn",
    "contested_fn",
    "latency_sum_s",
    "latency_n",
    "pdr_rx",
    "pdr_expected",
    "det_calls",
    "det_nanos",
    "track_capacity_dropped_messages",
}
SUMMARY_FIELDS = (
    "schema", "n", "frac", "n_attackers", "attack", "run", "sim_time",
    "interval", "detector", "score_model", "mobility", "null_ev",
    "naive_th", "prior", "threshold", "decay", "decay_half_life_s",
    "warmup", "attack_start_s", "comm_range", "gps_sigma",
    "detector_gps_sigma", "spd_sigma", "clock_sigma", "bsm_bytes", "sent",
    "received", "invalid_bsm", "assigned_attacker_rx", "attack_active_rx",
    "malicious_rx", "malicious_expected_pairs",
    "malicious_expected_pairs_observed",
    "malicious_observed_pairs_any_range", "malicious_zero_reception_pairs",
    "pairs", "stream_tp", "stream_fp", "stream_tn", "stream_fn",
    "stream_tpr", "stream_fpr", "stream_precision", "stream_f1", "owner_tp",
    "owner_fp", "owner_tn", "owner_fn", "owner_tpr", "owner_fpr",
    "owner_precision", "owner_f1", "clean_fp", "clean_tn", "clean_fpr",
    "victim_pairs", "victim_pairs_alerted", "victim_ids",
    "victim_ids_alerted", "contested_tp", "contested_fp", "contested_tn",
    "contested_fn", "contested_tpr", "contested_fpr", "contested_precision",
    "contested_f1", "victim_pairs_contested", "victim_ids_contested",
    "final_stream_tp", "final_stream_fp", "final_stream_tn",
    "final_stream_fn", "final_stream_tpr", "final_stream_fpr",
    "final_stream_precision", "final_stream_f1", "final_owner_tp",
    "final_owner_fp", "final_owner_tn", "final_owner_fn", "final_owner_tpr",
    "final_owner_fpr", "final_owner_precision", "final_owner_f1",
    "median_ttd", "ttd_detected_frac", "stream_auc", "owner_auc",
    "stream_pr_auc", "owner_pr_auc", "max_clean_score", "clean_margin",
    "latency_sum_s", "latency_n", "latency_ms", "pdr_rx", "pdr_expected",
    "pdr", "det_calls", "det_nanos", "det_us", "det_p50_us", "det_p95_us",
    "det_p99_us", "det_max_us", "det_throughput_calls_per_s",
    "peak_identity_keys_per_receiver", "peak_live_tracks_per_receiver",
    "estimated_state_payload_bytes_per_receiver", "eval_window_start_s",
    "onset_blank_s",
    "eligible_pairs", "ineligible_pairs", "track_stream_tp",
    "track_stream_fp", "track_stream_tn", "track_stream_fn",
    "track_stream_tpr", "track_stream_fpr", "victim_pairs_track_alerted",
    "victim_ids_track_alerted", "track_capacity_dropped_messages",
)
PAIR_REQUIRED = {
    "schema",
    "n",
    "frac",
    "attack",
    "run",
    "score_model",
    "threshold",
    "decay_half_life_s",
    "attack_start_s",
    "receiver_id",
    "claimed_id",
    "source_count",
    "source_ids",
    "source_roles",
    "observable_source_count",
    "observable_source_ipv4s",
    "identity_contested",
    "contested_stream_alert",
    "preexisting_contested",
    "first_contested_s",
    "first_stream_contested_s",
    "assigned_attacker_use",
    "attack_active_use",
    "malicious_use",
    "malicious_messages",
    "owner_is_attacker",
    "clean_pair",
    "owner_seen",
    "victim_exposure_pair",
    "victim_ids",
    "peak_score",
    "stream_peak_score",
    "final_score",
    "final_alert",
    "ever_alert",
    "stream_alert",
    "preexisting_alert",
    "post_onset_crossing_intervals",
    "first_seen_s",
    "first_cross_s",
    "time_to_detect_s",
    "last_seen_s",
    "observed_duration_s",
    "censor_time_s",
    "censored",
    "first_malicious_seen_s",
    "first_stream_cross_s",
    "stream_time_to_detect_s",
    "stream_observed_duration_s",
    "stream_censor_time_s",
    "stream_censored",
    "messages",
    "eval_window_start_s",
    "eligible",
    "window_msgs",
    "window_exposure_s",
    "window_peak_score",
    "window_first_exceed_s",
    "window_alert",
    "track_count",
    "max_track_peak",
    "honest_track_peak",
    "owner_track_peak",
    "track_alert",
    "honest_track_alert",
    "owner_track_alert",
    "track_capacity_dropped_messages",
    "stride_class",
    "stride_ambiguous",
    "stride_margin",
    "stride_impact",
    "priority_index",
    "priority_band",
    "trust_decision",
}
PAIR_FIELDS = (
    "schema", "n", "frac", "attack", "run", "score_model", "threshold",
    "decay_half_life_s", "attack_start_s", "receiver_id", "claimed_id",
    "source_count", "source_ids", "source_roles", "observable_source_count",
    "observable_source_ipv4s", "identity_contested",
    "contested_stream_alert", "preexisting_contested", "first_contested_s",
    "first_stream_contested_s", "owner_seen", "assigned_attacker_use",
    "attack_active_use", "malicious_use", "malicious_messages",
    "owner_is_attacker", "clean_pair", "victim_exposure_pair", "victim_ids",
    "peak_score", "stream_peak_score", "final_score", "final_alert",
    "ever_alert", "stream_alert", "preexisting_alert",
    "post_onset_crossing_intervals", "first_seen_s", "first_cross_s",
    "time_to_detect_s", "last_seen_s", "observed_duration_s",
    "censor_time_s", "censored", "first_malicious_seen_s",
    "first_stream_cross_s", "stream_time_to_detect_s",
    "stream_observed_duration_s", "stream_censor_time_s", "stream_censored",
    "messages", "eval_window_start_s", "eligible", "window_msgs",
    "window_exposure_s", "window_peak_score", "window_first_exceed_s",
    "window_alert", "track_count", "max_track_peak", "honest_track_peak",
    "owner_track_peak", "track_alert", "honest_track_alert",
    "owner_track_alert", "track_capacity_dropped_messages",
    "track_purity", "track_merges",
    "track_fragments", "track_id_switches", "oracle_track_honest_peak",
    "oracle_track_honest_alert", "stride_class", "stride_ambiguous",
    "stride_margin", "stride_impact", "priority_index", "priority_band",
    "trust_decision",
)
TRACE_FIELDS = (
    "receiver_id",
    "rx_time",
    "receiver_true_x",
    "receiver_true_y",
    "observable_source_ipv4",
    "claimed_id",
    "claimed_seq",
    "claimed_tx_time",
    "claimed_x",
    "claimed_y",
    "claimed_vx",
    "claimed_vy",
    "oracle_source_id",
    "oracle_tx_seq",
    "oracle_tx_time",
    "oracle_true_x",
    "oracle_true_y",
    "oracle_true_vx",
    "oracle_true_vy",
    "oracle_source_is_attacker",
    "oracle_assigned_role",
    "oracle_attack_active",
    "oracle_message_is_malicious",
    "oracle_victim_id",
    "oracle_owner_is_attacker",
    "oracle_expected_receiver",
)
TRACE_REQUIRED = set(TRACE_FIELDS)
# Attacks whose detectability could plausibly be an artifact of the onset
# step rather than of the attack's steady-state signature. Each gets a paired
# --attackStart=0 arm.
STEADY_STATE_ATTACKS = ("constoffset", "revheading", "slydos", "falsify")

PURE_ATTACKS = (
    "spoof",
    "falsify",
    "replay",
    "dos",
    "constoffset",
    "revheading",
    "slydos",
)

PLAN_OPTION_NAMES = {
    "nVehicles",
    "attackerFraction",
    "attack",
    "run",
    "simTime",
    "warmup",
    "attackStart",
    "onsetBlank",
    "interval",
    "detector",
    "scoreModel",
    "nullEvidence",
    "naiveThresholds",
    "prior",
    "threshold",
    "decayHalfLife",
    "commRange",
    "gpsSigma",
    "detectorGpsSigma",
    "spdSigma",
    "clockSigma",
    "bsmBytes",
    "mobility",
}
DEFAULT_DECAY_HALF_LIFE_S = -math.log(2.0) * 0.1 / math.log(0.98)
FAST_DECAY_HALF_LIFE_S = -math.log(2.0) * 0.1 / math.log(0.95)


class PipelineError(RuntimeError):
    """An invariant violation that must stop the experiment."""


@dataclass(frozen=True)
class Job:
    experiment_id: str
    mode: str
    stage: str
    family: str
    arm: str
    replicate: int
    seed: int
    serial: int
    args_json: str

    @property
    def args(self) -> list[str]:
        value = json.loads(self.args_json)
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise PipelineError(f"{self.experiment_id}: args_json is not a string list")
        return value


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def fnum(value: float) -> str:
    if not math.isfinite(value):
        raise PipelineError(f"non-finite numeric plan value: {value}")
    return f"{value:.12g}"


def make_args(
    *,
    mode: str,
    n: int,
    frac: float,
    attack: str,
    seed: int,
    threshold: float,
    detector: bool = True,
    score_model: str = "reference",
    decay_half_life_s: float = DEFAULT_DECAY_HALF_LIFE_S,
    gps_sigma: float = 2.0,
    detector_gps_sigma: float = 2.0,
    steady_state: bool = False,
    onset_blank: float = 0.0,
    attack_start_override: float | None = None,
    mobility: str = "constant",
    clock_sigma: float = 0.02,
) -> list[str]:
    sim_time, warmup, attack_start = (
        (60.0, 5.0, 10.0) if mode == "full" else (8.0, 2.0, 3.0)
    )
    if steady_state:
        # Attackers are adversarial from their first transmitted message, so
        # no onset discontinuity exists for a plausibility check to latch
        # onto. Warm-up absorbs the time the standard arm spends waiting for
        # onset, so BOTH arms evaluate over the identical calendar window
        # W = [attack_start_of_standard_arm, sim_time]. That match is what
        # makes the paired difference attributable to the onset step alone.
        warmup, attack_start = attack_start, 0.0
    if attack_start_override is not None:
        if steady_state:
            raise PipelineError(
                "attack_start_override is incompatible with steady_state"
            )
        if not math.isfinite(attack_start_override) or attack_start_override < 0.0:
            raise PipelineError("attack_start_override must be finite and nonnegative")
        attack_start = attack_start_override
        # Smoke remains a cheap plumbing check but must still instantiate the
        # exact 20-s arm. Extend only that non-inferential run enough to form W.
        if attack_start >= sim_time:
            sim_time = attack_start + 5.0
    return [
        f"--nVehicles={n}",
        f"--attackerFraction={fnum(frac)}",
        f"--attack={attack}",
        f"--run={seed}",
        f"--simTime={fnum(sim_time)}",
        f"--warmup={fnum(warmup)}",
        f"--attackStart={fnum(attack_start)}",
        f"--onsetBlank={fnum(onset_blank)}",
        "--interval=0.1",
        f"--detector={'true' if detector else 'false'}",
        f"--scoreModel={score_model}",
        "--nullEvidence=false",
        "--naiveThresholds=false",
        "--prior=0.05",
        f"--threshold={fnum(threshold)}",
        f"--decayHalfLife={fnum(decay_half_life_s)}",
        "--commRange=300",
        f"--gpsSigma={fnum(gps_sigma)}",
        f"--detectorGpsSigma={fnum(detector_gps_sigma)}",
        f"--mobility={mobility}",
        "--spdSigma=0.5",
        f"--clockSigma={fnum(clock_sigma)}",
        "--bsmBytes=320",
    ]


def build_plan(
    mode: str,
    phase: str,
    threshold: float | None,
) -> list[Job]:
    if mode not in {"smoke", "full"}:
        raise PipelineError(f"unsupported mode: {mode}")
    if phase not in {"validation", "test"}:
        raise PipelineError(f"unsupported phase: {phase}")
    if phase == "test" and (threshold is None or not math.isfinite(threshold)):
        raise PipelineError("test plan requires a finite frozen threshold")

    jobs: list[Job] = []

    def add(
        *,
        stage: str,
        family: str,
        arm: str,
        replicate: int,
        seed: int,
        serial: bool,
        n: int,
        frac: float,
        attack: str,
        detector: bool = True,
        score_model: str = "reference",
        decay_half_life_s: float = DEFAULT_DECAY_HALF_LIFE_S,
        gps_sigma: float = 2.0,
        detector_gps_sigma: float = 2.0,
        steady_state: bool = False,
        onset_blank: float = 0.0,
        attack_start_override: float | None = None,
        mobility: str = "constant",
        clock_sigma: float = 0.02,
    ) -> None:
        decision_threshold = 0.0 if stage == "validation" else float(threshold)
        experiment_id = (
            f"{stage}__{family}__{arm}__seed_{seed:04d}"
        )
        args = make_args(
            mode=mode,
            n=n,
            frac=frac,
            attack=attack,
            seed=seed,
            threshold=decision_threshold,
            detector=detector,
            score_model=score_model,
            decay_half_life_s=decay_half_life_s,
            gps_sigma=gps_sigma,
            detector_gps_sigma=detector_gps_sigma,
            steady_state=steady_state,
            onset_blank=onset_blank,
            attack_start_override=attack_start_override,
            mobility=mobility,
            clock_sigma=clock_sigma,
        )
        jobs.append(
            Job(
                experiment_id=experiment_id,
                mode=mode,
                stage=stage,
                family=family,
                arm=arm,
                replicate=replicate,
                seed=seed,
                serial=int(serial),
                args_json=json.dumps(args, separators=(",", ":")),
            )
        )

    if phase == "validation":
        if mode == "full":
            # 299 independent benign seeds are the minimum needed for a
            # zero-event exact one-sided 95% upper bound below 1%:
            # 1 - 0.05**(1/299) ~= 0.00997. Attack validation remains 20
            # independent seed blocks per attack family.
            validation_groups = (
                ("none", range(10001, 10300)),
                *((attack, range(1001, 1021)) for attack in PURE_ATTACKS),
            )
        else:
            # Smoke is explicitly non-inferential; the shell runner relaxes
            # the clean constraint to 1.0 for this one-seed pipeline check.
            validation_groups = tuple(
                (attack, (9001,)) for attack in ("none",) + PURE_ATTACKS
            )
        for attack, seeds in validation_groups:
            for replicate, seed in enumerate(seeds, 1):
                add(
                    stage="validation",
                    family="threshold_selection",
                    arm=f"validation_{attack}",
                    replicate=replicate,
                    seed=seed,
                    serial=False,
                    n=(70 if attack == "none" else 50)
                    if mode == "full"
                    else (14 if attack == "none" else 10),
                    frac=0.0 if attack == "none" else 0.30,
                    attack=attack,
                )
    else:
        assert threshold is not None
        seeds30: Iterable[int] = range(1, 31) if mode == "full" else (9101,)

        # Seven pure attacks at the paper's 50-vehicle, 30% condition.
        for attack in PURE_ATTACKS:
            for replicate, seed in enumerate(seeds30, 1):
                add(
                    stage="test",
                    family="pure_attack",
                    arm=f"pure_{attack}",
                    replicate=replicate,
                    seed=seed,
                    serial=False,
                    n=50 if mode == "full" else 10,
                    frac=0.30,
                    attack=attack,
                )

        # Paired steady-state arms. Identical seeds, identical evaluation
        # window; the ONLY difference is that attackers are adversarial from
        # their first transmitted message, so there is no onset discontinuity.
        #
        # This exists because a mid-stream onset is itself an impossible
        # displacement: CONST_OFFSET's offset step trips the position checks
        # once, at the switch, and that single artifact was being credited as
        # detection of a stealthy attack. The paired difference between these
        # arms and pure_attack isolates the onset contribution, so the paper
        # can report steady-state detectability rather than an artifact.
        for attack in STEADY_STATE_ATTACKS:
            for replicate, seed in enumerate(seeds30, 1):
                add(
                    stage="test",
                    family="steady_state",
                    arm=f"pure_{attack}_steady",
                    replicate=replicate,
                    seed=seed,
                    serial=False,
                    n=50 if mode == "full" else 10,
                    frac=0.30,
                    attack=attack,
                    steady_state=True,
                )

        # At n=70 all four fractions yield a multiple of seven attackers, so
        # every mixedhard role is represented without changing composition.
        fractions = (0.10, 0.20, 0.30, 0.50) if mode == "full" else (0.20, 0.50)
        for frac in fractions:
            for replicate, seed in enumerate(seeds30, 1):
                tag = str(frac).replace(".", "p")
                add(
                    stage="test",
                    family="mixedhard_prevalence",
                    arm=f"mixedhard_frac_{tag}",
                    replicate=replicate,
                    seed=seed,
                    serial=False,
                    n=70 if mode == "full" else 14,
                    frac=frac,
                    attack="mixedhard",
                )

        # Two reference-model forgetting variants. The default half-life is the
        # real-time equivalent of the legacy 0.98-per-0.1-s retention and is
        # already the 30% prevalence arm, so it is not duplicated.
        variants = (
            ("reference_half_life_1p351", "reference", FAST_DECAY_HALF_LIFE_S),
            ("reference_no_forgetting", "reference", -1.0),
        )
        for arm, score_model, decay_half_life_s in variants:
            for replicate, seed in enumerate(seeds30, 1):
                add(
                    stage="test",
                    family="score_variant",
                    arm=arm,
                    replicate=replicate,
                    seed=seed,
                    serial=False,
                    n=70 if mode == "full" else 14,
                    frac=0.30 if mode == "full" else 0.50,
                    attack="mixedhard",
                    score_model=score_model,
                    decay_half_life_s=decay_half_life_s,
                )

        # Actual GNSS noise and detector-assumed noise are independently varied.
        noise_arms = (
            ("actual_4_assumed_2", 4.0, 2.0),
            ("actual_8_assumed_2", 8.0, 2.0),
            ("actual_2_assumed_4", 2.0, 4.0),
        )
        for arm, actual, assumed in noise_arms:
            for replicate, seed in enumerate(seeds30, 1):
                add(
                    stage="test",
                    family="noise_misspecification",
                    arm=arm,
                    replicate=replicate,
                    seed=seed,
                    serial=False,
                    n=70 if mode == "full" else 14,
                    frac=0.30 if mode == "full" else 0.50,
                    attack="mixedhard",
                    gps_sigma=actual,
                    detector_gps_sigma=assumed,
                )

        # Manoeuvring mobility. Paired with mixedhard_frac_0p3 on the same
        # seeds and otherwise identical settings, so the difference isolates
        # the effect of acceleration, braking and one-tick lateral
        # perturbations on both the
        # kinematic checks and track association. Constant velocity is the
        # favourable case; this arm measures how much of the result it buys.
        for replicate, seed in enumerate(seeds30, 1):
            add(
                stage="test",
                family="mobility",
                arm="manoeuvre",
                replicate=replicate,
                seed=seed,
                serial=False,
                n=70 if mode == "full" else 14,
                frac=0.30 if mode == "full" else 0.50,
                attack="mixedhard",
                mobility="manoeuvre",
            )

        # Onset-guard sensitivity for the transient under study. These are
        # paired with pure_constoffset by RNG seed and settings and differ only
        # in how much post-activation evidence is excluded. They test whether
        # apparent constant-offset detection is sustained after its onset step.
        for guard in (0.25, 0.50, 1.00):
            tag = str(guard).replace(".", "p")
            for replicate, seed in enumerate(seeds30, 1):
                add(
                    stage="test",
                    family="onset_guard",
                    arm=f"constoffset_guard_{tag}",
                    replicate=replicate,
                    seed=seed,
                    serial=False,
                    n=50 if mode == "full" else 10,
                    frac=0.30,
                    attack="constoffset",
                    onset_blank=guard,
                )

        # Focused activation-time sensitivity.  These held-out constoffset
        # controls are paired with pure_constoffset by seed and differ only in
        # attackStart (5 s or 20 s versus the canonical 10 s).  They are
        # secondary/post-hoc controls and are excluded from headline pooling.
        for activation_time in (5.0, 20.0):
            tag = str(int(activation_time))
            for replicate, seed in enumerate(seeds30, 1):
                add(
                    stage="test",
                    family="onset_time",
                    arm=f"constoffset_onset_{tag}s",
                    replicate=replicate,
                    seed=seed,
                    serial=False,
                    n=50 if mode == "full" else 10,
                    frac=0.30,
                    attack="constoffset",
                    attack_start_override=activation_time,
                )

        # Honest-only stress arms. GNSS generation and detector assumptions
        # are separated; clockSigma is a fixed per-vehicle clock-offset sigma,
        # not drift. Each arm is paired with benign on the same seeds.
        benign_stresses = (
            ("gnss_sigma_4_assumed_2", 4.0, 2.0, 0.02),
            ("gnss_sigma_8_assumed_2", 8.0, 2.0, 0.02),
            ("clock_offset_sigma_0p10", 2.0, 2.0, 0.10),
        )
        stress_seeds: Iterable[int] = range(1, 31) if mode == "full" else (9201,)
        for arm, actual_gps, assumed_gps, clock_sigma in benign_stresses:
            for replicate, seed in enumerate(stress_seeds, 1):
                add(
                    stage="test",
                    family="benign_stress",
                    arm=arm,
                    replicate=replicate,
                    seed=seed,
                    serial=False,
                    n=70 if mode == "full" else 14,
                    frac=0.0,
                    attack="none",
                    gps_sigma=actual_gps,
                    detector_gps_sigma=assumed_gps,
                    clock_sigma=clock_sigma,
                )

        # The n=70 scaling point is shared with mixedhard_frac_0p2.
        for n in ((35, 105) if mode == "full" else (7, 21)):
            for replicate, seed in enumerate(seeds30, 1):
                add(
                    stage="test",
                    family="scale",
                    arm=f"scale_n_{n}",
                    replicate=replicate,
                    seed=seed,
                    serial=False,
                    n=n,
                    frac=0.20,
                    attack="mixedhard",
                )

        benign_seeds: Iterable[int] = range(1, 51) if mode == "full" else (9201,)
        for replicate, seed in enumerate(benign_seeds, 1):
            add(
                stage="test",
                family="benign",
                arm="benign",
                replicate=replicate,
                seed=seed,
                serial=False,
                n=70 if mode == "full" else 14,
                frac=0.0,
                attack="none",
            )

        # Wall-clock detector timing is run without CPU contention, paired by
        # seed, and kept out of the parallel worker pool.
        timing_seeds: Iterable[int] = range(3001, 3031) if mode == "full" else (9301,)
        for replicate, seed in enumerate(timing_seeds, 1):
            # Alternate AB/BA order across paired seeds to reduce systematic
            # drift from temperature, frequency scaling, and background load.
            order = (
                ((True, "detector_on"), (False, "detector_off"))
                if replicate % 2
                else ((False, "detector_off"), (True, "detector_on"))
            )
            for detector, label in order:
                add(
                    stage="test",
                    family="serial_timing",
                    arm=label,
                    replicate=replicate,
                    seed=seed,
                    serial=True,
                    n=70 if mode == "full" else 14,
                    frac=0.30 if mode == "full" else 0.50,
                    attack="mixedhard",
                    detector=detector,
                )

    validate_jobs(jobs)
    expected = {
        ("full", "validation"): 439,
        # 800 core + 90 onset-guard + 60 onset-time + 90 honest stress.
        ("full", "test"): 1040,
        ("smoke", "validation"): 8,
        ("smoke", "test"): 32,
    }[(mode, phase)]
    if len(jobs) != expected:
        raise PipelineError(
            f"internal grid error: {mode}/{phase} has {len(jobs)}, expected {expected}"
        )
    return jobs


def validate_canonical_plan(jobs: Sequence[Job]) -> None:
    """Require a plan to match the preregistered grid one row for one row."""

    modes = {job.mode for job in jobs}
    stages = {job.stage for job in jobs}
    if len(modes) != 1 or len(stages) != 1:
        raise PipelineError("each plan file must contain exactly one mode and stage")
    mode, stage = next(iter(modes)), next(iter(stages))
    threshold: float | None = None
    if stage == "test":
        threshold_values = {
            as_float(option_map(job)["threshold"], f"{job.experiment_id}/threshold")
            for job in jobs
        }
        if len(threshold_values) != 1:
            raise PipelineError("test plan does not contain one frozen threshold")
        threshold = next(iter(threshold_values))
    expected = build_plan(mode, stage, threshold)
    observed_rows = [asdict(job) for job in jobs]
    expected_rows = [asdict(job) for job in expected]
    if observed_rows != expected_rows:
        mismatch = next(
            (
                index
                for index, (observed, wanted) in enumerate(
                    zip(observed_rows, expected_rows)
                )
                if observed != wanted
            ),
            min(len(observed_rows), len(expected_rows)),
        )
        raise PipelineError(
            f"plan differs from canonical preregistration at row {mismatch + 2}"
        )


def validate_jobs(jobs: Sequence[Job]) -> None:
    if not jobs:
        raise PipelineError("empty experiment plan")
    ids: set[str] = set()
    configs: set[tuple[str, ...]] = set()
    for job in jobs:
        if job.experiment_id in ids:
            raise PipelineError(f"duplicate experiment_id: {job.experiment_id}")
        ids.add(job.experiment_id)
        if job.mode not in {"smoke", "full"}:
            raise PipelineError(f"{job.experiment_id}: invalid mode")
        if job.stage not in {"validation", "test"}:
            raise PipelineError(f"{job.experiment_id}: invalid stage")
        if job.serial not in {0, 1}:
            raise PipelineError(f"{job.experiment_id}: serial must be 0/1")
        if job.replicate < 1 or job.seed < 1:
            raise PipelineError(f"{job.experiment_id}: replicate/seed must be positive")
        expected_id = f"{job.stage}__{job.family}__{job.arm}__seed_{job.seed:04d}"
        if job.experiment_id != expected_id:
            raise PipelineError(
                f"{job.experiment_id}: ID does not exactly encode plan metadata"
            )
        if bool(job.serial) != (job.family == "serial_timing"):
            raise PipelineError(
                f"{job.experiment_id}: only serial_timing jobs may be serial"
            )
        args = job.args
        option_names = [
            value[2:].split("=", 1)[0]
            for value in args
            if value.startswith("--") and "=" in value
        ]
        if len(option_names) != len(args):
            raise PipelineError(f"{job.experiment_id}: malformed simulator option")
        if len(option_names) != len(set(option_names)):
            raise PipelineError(f"{job.experiment_id}: duplicate CLI option")
        if set(option_names) != PLAN_OPTION_NAMES:
            raise PipelineError(
                f"{job.experiment_id}: simulator option set mismatch; "
                f"missing={sorted(PLAN_OPTION_NAMES - set(option_names))}, "
                f"extra={sorted(set(option_names) - PLAN_OPTION_NAMES)}"
            )
        options = dict(zip(option_names, (value.split("=", 1)[1] for value in args)))
        run_value = as_float(options["run"], f"{job.experiment_id}/run")
        if not run_value.is_integer() or int(run_value) != job.seed:
            raise PipelineError(f"{job.experiment_id}: --run differs from plan seed")
        warmup = as_float(options["warmup"], f"{job.experiment_id}/warmup")
        attack_start = as_float(
            options["attackStart"], f"{job.experiment_id}/attackStart"
        )
        sim_time = as_float(options["simTime"], f"{job.experiment_id}/simTime")
        # attackStart == 0 is the steady-state arm, where attackers are
        # adversarial from their first message. Only the evaluation window
        # must be well formed.
        onset_blank = as_float(
            options["onsetBlank"], f"{job.experiment_id}/onsetBlank"
        )
        eval_start = max(warmup, attack_start + onset_blank)
        if not (
            0.0 <= attack_start < sim_time
            and 0.0 <= warmup < sim_time
            and onset_blank >= 0.0
            and eval_start < sim_time
        ):
            raise PipelineError(
                f"{job.experiment_id}: require 0<=attackStart<simTime, "
                f"0<=warmup<simTime, onsetBlank>=0, "
                f"max(warmup, attackStart+onsetBlank)<simTime"
            )
        for bool_option in ("detector", "nullEvidence", "naiveThresholds"):
            if options[bool_option] not in {"true", "false"}:
                raise PipelineError(
                    f"{job.experiment_id}: {bool_option} must be true/false"
                )
        half_life = as_float(
            options["decayHalfLife"], f"{job.experiment_id}/decayHalfLife"
        )
        if half_life != -1.0 and half_life <= 0.0:
            raise PipelineError(
                f"{job.experiment_id}: decayHalfLife must be positive or -1"
            )
        config = tuple(args)
        if config in configs:
            raise PipelineError(
                f"{job.experiment_id}: duplicate simulator configuration in plan"
            )
        configs.add(config)


def write_plan(path: Path, jobs: Sequence[Job]) -> None:
    lines: list[str] = []
    from io import StringIO

    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=PLAN_FIELDS, dialect="excel-tab")
    writer.writeheader()
    for job in jobs:
        writer.writerow(asdict(job))
    atomic_text(path, buffer.getvalue())


def read_plan(path: Path) -> list[Job]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle, dialect="excel-tab")
            if tuple(reader.fieldnames or ()) != PLAN_FIELDS:
                raise PipelineError(
                    f"{path}: plan header mismatch; expected {PLAN_FIELDS}, "
                    f"got {reader.fieldnames}"
                )
            jobs = [
                Job(
                    experiment_id=row["experiment_id"],
                    mode=row["mode"],
                    stage=row["stage"],
                    family=row["family"],
                    arm=row["arm"],
                    replicate=int(row["replicate"]),
                    seed=int(row["seed"]),
                    serial=int(row["serial"]),
                    args_json=row["args_json"],
                )
                for row in reader
            ]
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(f"cannot read plan {path}: {exc}") from exc
    validate_jobs(jobs)
    validate_canonical_plan(jobs)
    return jobs


def read_header(path: Path) -> list[str]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.reader(handle))
    except OSError as exc:
        raise PipelineError(f"cannot read schema {path}: {exc}") from exc
    if len(rows) != 1 or not rows[0]:
        raise PipelineError(f"{path}: schema file must contain exactly one CSV row")
    if len(rows[0]) != len(set(rows[0])):
        raise PipelineError(f"{path}: duplicate field in schema")
    missing = SUMMARY_REQUIRED.difference(rows[0])
    if missing:
        raise PipelineError(f"{path}: v4 summary schema missing {sorted(missing)}")
    if tuple(rows[0]) != SUMMARY_FIELDS:
        raise PipelineError(f"{path}: v4 summary header order/content drift")
    return rows[0]


def read_single_summary(path: Path, expected_header: Sequence[str]) -> dict[str, str]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.reader(handle))
    except OSError as exc:
        raise PipelineError(f"cannot read run summary {path}: {exc}") from exc
    if len(rows) != 2:
        raise PipelineError(f"{path}: expected header plus exactly one data row")
    if rows[0] != list(expected_header):
        raise PipelineError(f"{path}: summary header differs from binary schema")
    if len(rows[1]) != len(rows[0]):
        raise PipelineError(f"{path}: summary data width mismatch")
    row = dict(zip(rows[0], rows[1]))
    if row["schema"] != "v6":
        raise PipelineError(f"{path}: expected schema=v6, got {row['schema']!r}")
    return row


def parse_pairs(path: Path) -> tuple[list[str], Iterable[dict[str, str]]]:
    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError as exc:
        raise PipelineError(f"cannot read pair file {path}: {exc}") from exc
    reader = csv.DictReader(handle)
    header = reader.fieldnames or []
    if not header:
        handle.close()
        raise PipelineError(f"{path}: missing pair header")
    if len(header) != len(set(header)):
        handle.close()
        raise PipelineError(f"{path}: duplicate pair field")
    missing = PAIR_REQUIRED.difference(header)
    if missing:
        handle.close()
        raise PipelineError(f"{path}: pair schema missing {sorted(missing)}")
    if tuple(header) != PAIR_FIELDS:
        handle.close()
        raise PipelineError(f"{path}: v4 pair header order/content drift")

    def rows() -> Iterable[dict[str, str]]:
        try:
            for line_no, row in enumerate(reader, 2):
                if None in row or any(value is None for value in row.values()):
                    raise PipelineError(f"{path}:{line_no}: pair row width mismatch")
                yield row
        finally:
            handle.close()

    return header, rows()


def as_float(value: str, context: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise PipelineError(f"{context}: not numeric: {value!r}") from exc
    if not math.isfinite(result):
        raise PipelineError(f"{context}: non-finite value: {value!r}")
    return result


def validate_crossing_intervals(value: str, context: str) -> None:
    if value in {"", "-"}:
        return
    previous_hi = -1.0
    for item in value.split("|"):
        pieces = item.split(":")
        if len(pieces) != 2:
            raise PipelineError(f"{context}: malformed crossing interval {item!r}")
        lo, hi = as_float(pieces[0], context), as_float(pieces[1], context)
        if lo < 0.0 or hi > 1.0 or not lo < hi or lo <= previous_hi:
            raise PipelineError(
                f"{context}: intervals must be sorted merged half-open [lo,hi)"
            )
        previous_hi = hi


def option_map(job: Job) -> dict[str, str]:
    result: dict[str, str] = {}
    for arg in job.args:
        if not arg.startswith("--") or "=" not in arg:
            raise PipelineError(f"{job.experiment_id}: malformed CLI argument {arg!r}")
        key, value = arg[2:].split("=", 1)
        result[key] = value
    return result


def needs_trace(job: Job) -> bool:
    """Select preregistered traces for baseline fitting and trajectory audits.

    Validation traces fit/freeze baseline parameters. Test traces evaluate
    those frozen parameters and provide the paired onset trajectories. Truth
    labels are written by the evaluation harness but never read by deployment
    code.
    """
    if job.mode == "full":
        if job.stage == "validation":
            # Every validation job is traced. Baseline thresholds use the
            # same exact 299 benign-seed false-alarm bound as the primary
            # detector, so sampling only 30 benign traces would invalidate the
            # advertised selection protocol.
            return job.family == "threshold_selection"
        if job.stage != "test":
            return False
        return (
            (job.family == "pure_attack" and 1 <= job.seed <= 30)
            or (job.family == "benign" and 1 <= job.seed <= 30)
            or (
                job.family == "steady_state"
                and job.arm == "pure_constoffset_steady"
                and 1 <= job.seed <= 30
            )
            or (job.family == "onset_guard" and 1 <= job.seed <= 30)
            or (job.family == "onset_time" and 1 <= job.seed <= 30)
        )
    if job.stage == "validation":
        return job.family == "threshold_selection"
    if job.stage == "test":
        return (
            job.family in {
                "pure_attack", "benign", "onset_guard", "onset_time"
            }
            or (
                job.family == "steady_state"
                and job.arm == "pure_constoffset_steady"
            )
        )
    return False


def writes_pairs(job: Job) -> bool:
    """Timing jobs suppress evaluation CSV I/O for both paired states."""

    return job.family != "serial_timing"


def verify_trace(job: Job, path: Path) -> int:
    if not needs_trace(job):
        if path.exists():
            raise PipelineError(
                f"{job.experiment_id}: unexpected trace outside deterministic subset"
            )
        return 0
    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError as exc:
        raise PipelineError(f"{job.experiment_id}: missing trace: {exc}") from exc
    count = 0
    with handle:
        reader = csv.DictReader(handle)
        header = reader.fieldnames or []
        missing = TRACE_REQUIRED.difference(header)
        if missing:
            raise PipelineError(
                f"{job.experiment_id}: trace schema missing {sorted(missing)}"
            )
        if len(header) != len(set(header)):
            raise PipelineError(f"{job.experiment_id}: duplicate trace field")
        if tuple(header) != TRACE_FIELDS:
            raise PipelineError(
                f"{job.experiment_id}: v4 trace header order/content drift"
            )
        for line_no, row in enumerate(reader, 2):
            if None in row or any(value is None for value in row.values()):
                raise PipelineError(
                    f"{job.experiment_id}: trace width mismatch at line {line_no}"
                )
            count += 1
            for field in (
                "rx_time",
                "receiver_true_x",
                "receiver_true_y",
                "claimed_tx_time",
                "claimed_x",
                "claimed_y",
                "claimed_vx",
                "claimed_vy",
                "oracle_tx_time",
                "oracle_true_x",
                "oracle_true_y",
                "oracle_true_vx",
                "oracle_true_vy",
            ):
                as_float(row[field], f"{job.experiment_id}/trace/{field}")
            for field in (
                "oracle_source_is_attacker",
                "oracle_attack_active",
                "oracle_message_is_malicious",
                "oracle_owner_is_attacker",
                "oracle_expected_receiver",
            ):
                if row[field] not in {"0", "1"}:
                    raise PipelineError(
                        f"{job.experiment_id}: trace {field} must be 0/1"
                    )
            if not row["observable_source_ipv4"] or not row["oracle_assigned_role"]:
                raise PipelineError(
                    f"{job.experiment_id}: trace source/role labels must be non-empty"
                )
    if count == 0:
        raise PipelineError(f"{job.experiment_id}: selected trace contains no receptions")
    return count


def verify_run(
    job: Job,
    run_dir: Path,
    expected_header: Sequence[str],
) -> tuple[dict[str, str], int, int]:
    summary = read_single_summary(run_dir / "summary.csv", expected_header)
    options = option_map(job)
    exact_checks = {
        "attack": options["attack"],
        "run": options["run"],
        "score_model": options["scoreModel"],
        "detector": "1" if options["detector"] == "true" else "0",
        "null_ev": "1" if options["nullEvidence"] == "true" else "0",
        "naive_th": "1" if options["naiveThresholds"] == "true" else "0",
    }
    for field, expected in exact_checks.items():
        if summary[field] != expected:
            raise PipelineError(
                f"{job.experiment_id}: summary {field}={summary[field]!r}, "
                f"expected {expected!r}"
            )
    numeric_checks = {
        "n": options["nVehicles"],
        "frac": options["attackerFraction"],
        "sim_time": options["simTime"],
        "warmup": options["warmup"],
        "attack_start_s": options["attackStart"],
        "interval": options["interval"],
        "prior": options["prior"],
        "threshold": options["threshold"],
        "decay_half_life_s": options["decayHalfLife"],
        "comm_range": options["commRange"],
        "gps_sigma": options["gpsSigma"],
        "detector_gps_sigma": options["detectorGpsSigma"],
        "spd_sigma": options["spdSigma"],
        "clock_sigma": options["clockSigma"],
        "bsm_bytes": options["bsmBytes"],
    }
    for field, expected in numeric_checks.items():
        actual_value = as_float(summary[field], f"{job.experiment_id}/{field}")
        expected_value = as_float(expected, f"{job.experiment_id}/option/{field}")
        if not math.isclose(actual_value, expected_value, rel_tol=1e-9, abs_tol=1e-9):
            raise PipelineError(
                f"{job.experiment_id}: summary {field}={actual_value}, "
                f"expected {expected_value}"
            )
    summary_warmup = as_float(summary["warmup"], f"{job.experiment_id}/warmup")
    summary_attack_start = as_float(
        summary["attack_start_s"], f"{job.experiment_id}/attack_start_s"
    )
    summary_sim_time = as_float(
        summary["sim_time"], f"{job.experiment_id}/sim_time"
    )
    summary_eval_start = as_float(
        summary["eval_window_start_s"], f"{job.experiment_id}/eval_window_start_s"
    )
    summary_onset_blank = as_float(
        summary["onset_blank_s"], f"{job.experiment_id}/onset_blank_s"
    )
    if not (
        0.0 <= summary_attack_start < summary_sim_time
        and 0.0 <= summary_warmup < summary_sim_time
        and summary_onset_blank >= 0.0
        and summary_eval_start < summary_sim_time
    ):
        raise PipelineError(
            f"{job.experiment_id}: summary violates the evaluation-window "
            f"constraints"
        )
    # The reported window must be exactly the one the contract defines; a
    # mismatch means positives and negatives were not judged over the same
    # interval, which is the defect this schema exists to prevent.
    expected_eval_start = max(summary_warmup, summary_attack_start + summary_onset_blank)
    if abs(summary_eval_start - expected_eval_start) > 1e-9:
        raise PipelineError(
            f"{job.experiment_id}: eval_window_start_s={summary_eval_start} "
            f"but max(warmup, attackStart+onsetBlank)={expected_eval_start}"
        )
    opportunity_fields = (
        "malicious_expected_pairs",
        "malicious_expected_pairs_observed",
        "malicious_observed_pairs_any_range",
        "malicious_zero_reception_pairs",
    )
    opportunity = {}
    for field in opportunity_fields:
        value = as_float(summary[field], f"{job.experiment_id}/{field}")
        if value < 0 or not value.is_integer():
            raise PipelineError(f"{job.experiment_id}: {field} is not a count")
        opportunity[field] = int(value)
    if opportunity["malicious_expected_pairs"] != (
        opportunity["malicious_expected_pairs_observed"]
        + opportunity["malicious_zero_reception_pairs"]
    ):
        raise PipelineError(
            f"{job.experiment_id}: opportunity counts do not satisfy expected=observed+zero"
        )
    if opportunity["malicious_expected_pairs_observed"] > opportunity[
        "malicious_observed_pairs_any_range"
    ]:
        raise PipelineError(
            f"{job.experiment_id}: in-range observed opportunities exceed any-range pairs"
        )

    if not writes_pairs(job):
        if (run_dir / "pairs.csv").exists():
            raise PipelineError(
                f"{job.experiment_id}: serial timing run unexpectedly wrote pairs"
            )
        trace_count = verify_trace(job, run_dir / "trace.csv")
        return summary, 0, trace_count

    pair_header, pair_rows = parse_pairs(run_dir / "pairs.csv")
    pair_count = 0
    pair_capacity_drops = 0
    seen_pair_keys: set[tuple[str, str]] = set()
    for row in pair_rows:
        pair_count += 1
        if row["schema"] != "v6_pair":
            raise PipelineError(
                f"{job.experiment_id}: pair schema is {row['schema']!r}"
            )
        for field in ("attack", "run", "score_model"):
            if row[field] != summary[field]:
                raise PipelineError(
                    f"{job.experiment_id}: pair {field} differs from summary"
                )
        for field in (
            "n", "frac", "threshold", "decay_half_life_s", "attack_start_s"
        ):
            if not math.isclose(
                as_float(row[field], f"{job.experiment_id}/pair/{field}"),
                as_float(summary[field], f"{job.experiment_id}/summary/{field}"),
                rel_tol=1e-9,
                abs_tol=1e-9,
            ):
                raise PipelineError(
                    f"{job.experiment_id}: pair {field} differs from summary"
                )
        key = (row["receiver_id"], row["claimed_id"])
        if key in seen_pair_keys:
            raise PipelineError(
                f"{job.experiment_id}: duplicate receiver/claimed pair {key}"
            )
        seen_pair_keys.add(key)
        for field in (
            "assigned_attacker_use",
            "attack_active_use",
            "malicious_use",
            "owner_is_attacker",
            "clean_pair",
            "censored",
            "owner_seen",
            "victim_exposure_pair",
            "identity_contested",
            "contested_stream_alert",
            "preexisting_contested",
            "final_alert",
            "ever_alert",
            "stream_alert",
            "preexisting_alert",
            "eligible",
            "window_alert",
            "track_alert",
            "honest_track_alert",
            "owner_track_alert",
            "oracle_track_honest_alert",
            "stride_ambiguous",
        ):
            if row[field] not in {"0", "1"}:
                raise PipelineError(
                    f"{job.experiment_id}: {field} must be 0/1, got {row[field]!r}"
                )
        malicious_messages = as_float(
            row["malicious_messages"], f"{job.experiment_id}/malicious_messages"
        )
        if malicious_messages < 0 or not malicious_messages.is_integer():
            raise PipelineError(
                f"{job.experiment_id}: malicious_messages must be a nonnegative integer"
            )
        if (malicious_messages > 0) != (row["malicious_use"] == "1"):
            raise PipelineError(
                f"{job.experiment_id}: malicious_messages disagrees with malicious_use"
            )
        window_messages = as_float(
            row["window_msgs"], f"{job.experiment_id}/window_msgs"
        )
        if (
            window_messages < 0
            or not window_messages.is_integer()
            or malicious_messages > window_messages
        ):
            raise PipelineError(
                f"{job.experiment_id}: malicious/window message counts are invalid"
            )
        capacity_drops = as_float(
            row["track_capacity_dropped_messages"],
            f"{job.experiment_id}/track_capacity_dropped_messages",
        )
        if capacity_drops < 0 or not capacity_drops.is_integer():
            raise PipelineError(
                f"{job.experiment_id}: track capacity drops must be a "
                "nonnegative integer"
            )
        pair_capacity_drops += int(capacity_drops)
        if int(row["malicious_use"]) > int(row["attack_active_use"]) or int(
            row["attack_active_use"]
        ) > int(row["assigned_attacker_use"]):
            raise PipelineError(
                f"{job.experiment_id}: malicious/active/assigned labels are inconsistent"
            )
        if int(row["clean_pair"]) != int(
            row["owner_is_attacker"] == "0" and row["malicious_use"] == "0"
        ):
            raise PipelineError(f"{job.experiment_id}: inconsistent clean_pair")
        if int(row["victim_exposure_pair"]) != int(
            row["owner_is_attacker"] == "0" and row["malicious_use"] == "1"
        ):
            raise PipelineError(
                f"{job.experiment_id}: inconsistent victim_exposure_pair"
            )
        validate_crossing_intervals(
            row["post_onset_crossing_intervals"],
            f"{job.experiment_id}/post_onset_crossing_intervals",
        )
        if row["malicious_use"] == "1":
            if row["stream_censored"] not in {"0", "1"}:
                raise PipelineError(
                    f"{job.experiment_id}: malicious stream_censored must be 0/1"
                )
            stream_ttd = as_float(
                row["stream_time_to_detect_s"],
                f"{job.experiment_id}/pair/stream_time_to_detect_s",
            )
            expected_censored = "0" if stream_ttd >= 0.0 else "1"
            if row["stream_censored"] != expected_censored:
                raise PipelineError(
                    f"{job.experiment_id}: stream event/censor flag mismatch"
                )
            if stream_ttd >= 0.0 and row["window_alert"] != "1":
                raise PipelineError(
                    f"{job.experiment_id}: stream event without primary window alert"
                )
            first_malicious = as_float(
                row["first_malicious_seen_s"],
                f"{job.experiment_id}/pair/first_malicious_seen_s",
            )
            if first_malicious < summary_eval_start:
                raise PipelineError(
                    f"{job.experiment_id}: malicious truth begins before W"
                )
        elif row["stream_censored"] != "-1":
            raise PipelineError(
                f"{job.experiment_id}: non-malicious stream_censored must be -1"
            )
        elif as_float(
            row["stream_time_to_detect_s"],
            f"{job.experiment_id}/pair/stream_time_to_detect_s",
        ) != -1.0:
            raise PipelineError(
                f"{job.experiment_id}: non-malicious stream delay must use sentinel -1"
            )
        for field in (
            "peak_score",
            "stream_peak_score",
            "final_score",
            "first_seen_s",
            "last_seen_s",
            "observed_duration_s",
            "censor_time_s",
            "first_malicious_seen_s",
            "first_contested_s",
            "first_stream_contested_s",
            "first_stream_cross_s",
            "stream_time_to_detect_s",
            "stream_observed_duration_s",
            "stream_censor_time_s",
        ):
            as_float(row[field], f"{job.experiment_id}/pair/{field}")
    if len(pair_header) != len(set(pair_header)):
        raise PipelineError(f"{job.experiment_id}: duplicate pair header")
    if int(as_float(summary["pairs"], f"{job.experiment_id}/pairs")) != pair_count:
        raise PipelineError(
            f"{job.experiment_id}: summary pairs={summary['pairs']} but "
            f"pair file contains {pair_count}"
        )
    summary_capacity_drops = as_float(
        summary["track_capacity_dropped_messages"],
        f"{job.experiment_id}/track_capacity_dropped_messages",
    )
    if (
        summary_capacity_drops < 0
        or not summary_capacity_drops.is_integer()
        or int(summary_capacity_drops) != pair_capacity_drops
    ):
        raise PipelineError(
            f"{job.experiment_id}: summary/pair track-capacity drops disagree"
        )
    trace_count = verify_trace(job, run_dir / "trace.csv")
    return summary, pair_count, trace_count


def verify_status_files(job: Job, run_dir: Path, status: dict) -> None:
    if status.get("status") != "complete":
        raise PipelineError(f"{job.experiment_id}: run status is not complete")
    required_hashes = {
        "summary_sha256": run_dir / "summary.csv",
        "stdout_sha256": run_dir / "stdout.log",
        "stderr_sha256": run_dir / "stderr.log",
    }
    if writes_pairs(job):
        required_hashes["pairs_sha256"] = run_dir / "pairs.csv"
    if needs_trace(job):
        required_hashes["trace_sha256"] = run_dir / "trace.csv"
    for field, path in required_hashes.items():
        expected = status.get(field)
        if not isinstance(expected, str) or len(expected) != 64:
            raise PipelineError(f"{job.experiment_id}: status missing {field}")
        if not path.is_file() or sha256(path) != expected:
            raise PipelineError(f"{job.experiment_id}: hash mismatch for {path.name}")
    try:
        command = json.loads((run_dir / "command.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"{job.experiment_id}: invalid command.json: {exc}") from exc
    if (
        command.get("experiment_id") != job.experiment_id
        or command.get("seed") != job.seed
        or command.get("returncode") != 0
    ):
        raise PipelineError(f"{job.experiment_id}: command provenance mismatch")
    expected_prefix = [*job.args]
    command_argv = command.get("command_argv")
    if not isinstance(command_argv, list) or command_argv[1 : 1 + len(job.args)] != expected_prefix:
        raise PipelineError(f"{job.experiment_id}: command argv differs from exact plan")
    extras = command_argv[1 + len(job.args) :]
    expected_extra_names = []
    if writes_pairs(job):
        expected_extra_names.append("--pairOutput=")
    if needs_trace(job):
        expected_extra_names.append("--trace=")
    if len(extras) != len(expected_extra_names) or any(
        not value.startswith(prefix)
        for value, prefix in zip(extras, expected_extra_names)
    ):
        raise PipelineError(
            f"{job.experiment_id}: command output options differ from plan policy"
        )
    for value in extras:
        output_path = Path(value.split("=", 1)[1])
        if output_path.parent.resolve() != run_dir.resolve() or not output_path.name.startswith("."):
            raise PipelineError(
                f"{job.experiment_id}: command output path escaped private run directory"
            )
    planned_hash = hashlib.sha256(
        json.dumps(job.args, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if command.get("planned_args_sha256") != planned_hash:
        raise PipelineError(f"{job.experiment_id}: command plan-argument hash mismatch")


def run_one(args: argparse.Namespace) -> None:
    plan = read_plan(args.plan)
    matches = [job for job in plan if job.experiment_id == args.experiment_id]
    if len(matches) != 1:
        raise PipelineError(
            f"{args.experiment_id}: expected exactly one matching plan row"
        )
    job = matches[0]
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise PipelineError(f"binary is not executable: {binary}")
    expected_header = read_header(args.schema)
    run_dir = args.runs_dir.resolve() / job.stage / job.experiment_id
    run_dir.mkdir(parents=True, exist_ok=True)

    status_path = run_dir / "status.json"
    binary_hash = sha256(binary)
    if args.resume and status_path.exists():
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
            if (
                status.get("status") == "complete"
                and status.get("binary_sha256") == binary_hash
            ):
                _, pair_count, _ = verify_run(job, run_dir, expected_header)
                verify_status_files(job, run_dir, status)
                print(f"[{job.experiment_id}] verified/resumed ({pair_count} pairs)")
                return
        except (OSError, json.JSONDecodeError, PipelineError):
            pass

    pid = os.getpid()
    pair_tmp = run_dir / f".pairs.{pid}.tmp.csv"
    trace_tmp = run_dir / f".trace.{pid}.tmp.csv"
    stdout_tmp = run_dir / f".stdout.{pid}.tmp.log"
    stderr_tmp = run_dir / f".stderr.{pid}.tmp.log"
    for path in (pair_tmp, trace_tmp, stdout_tmp, stderr_tmp):
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    command = [str(binary), *job.args]
    if writes_pairs(job):
        command.append(f"--pairOutput={pair_tmp}")
    if needs_trace(job):
        command.append(f"--trace={trace_tmp}")
    started = utc_now()
    start_clock = time.monotonic()
    with stdout_tmp.open("w", encoding="utf-8") as stdout_handle, stderr_tmp.open(
        "w", encoding="utf-8"
    ) as stderr_handle:
        completed = subprocess.run(
            command,
            stdout=stdout_handle,
            stderr=stderr_handle,
            text=True,
            check=False,
        )
    elapsed = time.monotonic() - start_clock
    if completed.returncode != 0:
        os.replace(stdout_tmp, run_dir / "stdout.failed.log")
        os.replace(stderr_tmp, run_dir / "stderr.failed.log")
        if pair_tmp.exists():
            os.replace(pair_tmp, run_dir / "pairs.failed.csv")
        if trace_tmp.exists():
            os.replace(trace_tmp, run_dir / "trace.failed.csv")
        atomic_text(
            status_path,
            json.dumps(
                {
                    "status": "failed",
                    "experiment_id": job.experiment_id,
                    "returncode": completed.returncode,
                    "started_utc": started,
                    "finished_utc": utc_now(),
                    "duration_s": elapsed,
                    "command": command,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
        raise PipelineError(
            f"{job.experiment_id}: simulator exited {completed.returncode}; "
            f"see {run_dir / 'stderr.failed.log'}"
        )
    if writes_pairs(job) and not pair_tmp.exists():
        raise PipelineError(f"{job.experiment_id}: simulator did not create pairOutput")
    if not writes_pairs(job) and pair_tmp.exists():
        raise PipelineError(f"{job.experiment_id}: timing run unexpectedly created pairs")

    stdout_text = stdout_tmp.read_text(encoding="utf-8")
    csv_lines = [line[4:] for line in stdout_text.splitlines() if line.startswith("CSV,")]
    if len(csv_lines) != 1:
        raise PipelineError(
            f"{job.experiment_id}: expected exactly one CSV, line, got {len(csv_lines)}"
        )
    summary_tmp = run_dir / f".summary.{pid}.tmp.csv"
    with summary_tmp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(expected_header)
        parsed = next(csv.reader([csv_lines[0]]))
        if len(parsed) != len(expected_header):
            raise PipelineError(
                f"{job.experiment_id}: CSV row has {len(parsed)} fields; "
                f"schema has {len(expected_header)}"
            )
        writer.writerow(parsed)

    os.replace(summary_tmp, run_dir / "summary.csv")
    if writes_pairs(job):
        os.replace(pair_tmp, run_dir / "pairs.csv")
    else:
        try:
            (run_dir / "pairs.csv").unlink()
        except FileNotFoundError:
            pass
    if needs_trace(job):
        if not trace_tmp.exists():
            raise PipelineError(
                f"{job.experiment_id}: selected run did not create its trace"
            )
        os.replace(trace_tmp, run_dir / "trace.csv")
    else:
        try:
            (run_dir / "trace.csv").unlink()
        except FileNotFoundError:
            pass
    os.replace(stdout_tmp, run_dir / "stdout.log")
    os.replace(stderr_tmp, run_dir / "stderr.log")
    summary, pair_count, trace_count = verify_run(job, run_dir, expected_header)
    command_record = {
        "experiment_id": job.experiment_id,
        "command_argv": command,
        "command_shell": shlex.join(command),
        "seed": job.seed,
        "started_utc": started,
        "finished_utc": utc_now(),
        "duration_s": elapsed,
        "returncode": completed.returncode,
        "planned_args": job.args,
        "planned_args_sha256": hashlib.sha256(
            json.dumps(job.args, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    atomic_text(
        run_dir / "command.json",
        json.dumps(command_record, indent=2, sort_keys=True) + "\n",
    )
    status = {
        "status": "complete",
        "experiment_id": job.experiment_id,
        "schema": summary["schema"],
        "binary_sha256": binary_hash,
        "summary_sha256": sha256(run_dir / "summary.csv"),
        "stdout_sha256": sha256(run_dir / "stdout.log"),
        "stderr_sha256": sha256(run_dir / "stderr.log"),
        "pair_rows": pair_count,
        "trace_rows": trace_count,
        "duration_s": elapsed,
        "finished_utc": utc_now(),
    }
    if writes_pairs(job):
        status["pairs_sha256"] = sha256(run_dir / "pairs.csv")
    if needs_trace(job):
        status["trace_sha256"] = sha256(run_dir / "trace.csv")
    atomic_text(status_path, json.dumps(status, indent=2, sort_keys=True) + "\n")
    print(f"[{job.experiment_id}] complete ({pair_count} pairs, {elapsed:.1f}s)")


def merge(args: argparse.Namespace) -> None:
    jobs: list[Job] = []
    for path in args.plan:
        jobs.extend(read_plan(path))
    validate_jobs(jobs)
    runs_dir = args.runs_dir.resolve()
    missing: list[str] = []
    extra: list[str] = []
    expected_stages = {job.stage for job in jobs}
    actual_stages = (
        {
            path.name
            for path in runs_dir.iterdir()
            if path.is_dir() and not path.name.startswith(".")
        }
        if runs_dir.is_dir()
        else set()
    )
    # Only complain about stage directories the caller did not ask about.
    # The workflow merges validation alone before the threshold is frozen, so
    # by the time a resumed run reaches this point runs/test/ already exists.
    # Rejecting it made --resume unusable for exactly the long runs it exists
    # to protect: the merge died with extra=['unexpected-stage/test'].
    known_stages = {"training", "validation", "test"}
    extra.extend(
        f"unexpected-stage/{value}"
        for value in sorted(actual_stages - expected_stages - known_stages)
    )
    for stage in sorted(expected_stages):
        expected_ids = {
            job.experiment_id for job in jobs if job.stage == stage
        }
        stage_dir = runs_dir / stage
        actual_ids = (
            {
                path.name
                for path in stage_dir.iterdir()
                if path.is_dir() and not path.name.startswith(".")
            }
            if stage_dir.is_dir()
            else set()
        )
        missing.extend(f"{stage}/{value}" for value in sorted(expected_ids - actual_ids))
        extra.extend(f"{stage}/{value}" for value in sorted(actual_ids - expected_ids))
    if missing or extra:
        raise PipelineError(
            f"run directory grid mismatch: missing={missing[:10]} "
            f"extra={extra[:10]}"
        )

    expected_header = read_header(args.schema)
    summary_rows: list[tuple[Job, dict[str, str], float]] = []
    duration_by_id: dict[str, float] = {}
    pair_header: list[str] | None = None
    config_signatures: set[tuple[str, ...]] = set()
    binary_hashes: set[str] = set()
    for job in jobs:
        run_dir = runs_dir / job.stage / job.experiment_id
        status_path = run_dir / "status.json"
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PipelineError(f"{job.experiment_id}: invalid status.json: {exc}") from exc
        if status.get("status") != "complete":
            raise PipelineError(f"{job.experiment_id}: run is not complete")
        binary_hash = status.get("binary_sha256")
        if not isinstance(binary_hash, str) or len(binary_hash) != 64:
            raise PipelineError(f"{job.experiment_id}: missing binary hash")
        binary_hashes.add(binary_hash)
        summary, _, _ = verify_run(job, run_dir, expected_header)
        verify_status_files(job, run_dir, status)
        try:
            wall_duration = float(status["duration_s"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PipelineError(
                f"{job.experiment_id}: invalid duration_s in status"
            ) from exc
        if not math.isfinite(wall_duration) or wall_duration < 0.0:
            raise PipelineError(f"{job.experiment_id}: invalid wall duration")
        duration_by_id[job.experiment_id] = wall_duration
        signature = tuple(job.args)
        if signature in config_signatures:
            raise PipelineError(
                f"{job.experiment_id}: duplicate simulator configuration at merge"
            )
        config_signatures.add(signature)
        if writes_pairs(job):
            header, rows = parse_pairs(run_dir / "pairs.csv")
            # Exhaust once here so malformed late rows cannot enter the merge.
            for _ in rows:
                pass
            if pair_header is None:
                pair_header = header
            elif pair_header != header:
                raise PipelineError(f"{job.experiment_id}: pair header drift")
        summary_rows.append((job, summary, wall_duration))

    if len(binary_hashes) != 1:
        raise PipelineError(f"merged runs used multiple binaries: {sorted(binary_hashes)}")
    if pair_header is None:
        raise PipelineError("no pair schemas found")

    args.summary_out.parent.mkdir(parents=True, exist_ok=True)
    args.pairs_out.parent.mkdir(parents=True, exist_ok=True)
    summary_tmp = args.summary_out.with_name(f".{args.summary_out.name}.{os.getpid()}.tmp")
    pairs_tmp = args.pairs_out.with_name(f".{args.pairs_out.name}.{os.getpid()}.tmp")
    try:
        with summary_tmp.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[*MERGE_META_FIELDS, *expected_header],
                extrasaction="raise",
            )
            writer.writeheader()
            for job, summary, wall_duration in summary_rows:
                meta = {field: getattr(job, field) for field in META_FIELDS}
                meta["wall_duration_s"] = f"{wall_duration:.9g}"
                writer.writerow({**meta, **summary})

        pair_rows_written = 0
        with pairs_tmp.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[*MERGE_META_FIELDS, *pair_header],
                extrasaction="raise",
            )
            writer.writeheader()
            for job in jobs:
                if not writes_pairs(job):
                    continue
                meta = {field: getattr(job, field) for field in META_FIELDS}
                meta["wall_duration_s"] = f"{duration_by_id[job.experiment_id]:.9g}"
                header, rows = parse_pairs(
                    runs_dir / job.stage / job.experiment_id / "pairs.csv"
                )
                if header != pair_header:
                    raise PipelineError(f"{job.experiment_id}: pair header drift")
                for row in rows:
                    writer.writerow({**meta, **row})
                    pair_rows_written += 1
        os.replace(summary_tmp, args.summary_out)
        os.replace(pairs_tmp, args.pairs_out)
    except BaseException:
        for path in (summary_tmp, pairs_tmp):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    print(
        f"merged {len(summary_rows)} summaries and {pair_rows_written} pairs "
        f"into {args.summary_out.parent}"
    )


def command_output(command: Sequence[str], cwd: Path | None = None) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as exc:
        return f"unavailable: {exc}"
    value = completed.stdout.strip()
    if completed.returncode:
        return f"exit {completed.returncode}: {value}"
    return value


def verify_source_snapshot(
    snapshot_dir: Path,
) -> tuple[Path, dict[str, dict[str, int | str]]]:
    """Verify and describe the frozen source/workflow reconstruction bundle."""

    snapshot_dir = snapshot_dir.resolve()
    checksum_path = snapshot_dir / "SHA256SUMS"
    if not checksum_path.is_file():
        raise PipelineError(f"source snapshot lacks SHA256SUMS: {snapshot_dir}")
    snapshot_files: dict[str, dict[str, int | str]] = {}
    try:
        checksum_lines = checksum_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PipelineError(f"cannot read source snapshot checksums: {exc}") from exc
    for line in checksum_lines:
        pieces = line.split(maxsplit=1)
        if len(pieces) != 2:
            raise PipelineError(f"malformed source snapshot checksum line: {line!r}")
        expected_hash, name = pieces[0], pieces[1].lstrip("*")
        if Path(name).name != name or len(expected_hash) != 64:
            raise PipelineError(f"unsafe source snapshot entry: {line!r}")
        path = snapshot_dir / name
        if not path.is_file() or sha256(path) != expected_hash:
            raise PipelineError(f"source snapshot hash mismatch: {name}")
        snapshot_files[name] = {
            "sha256": expected_hash,
            "bytes": path.stat().st_size,
        }
    if not snapshot_files:
        raise PipelineError("source snapshot is empty")
    return checksum_path, snapshot_files


def verify_build_provenance(
    local_source: Path,
    scratch_source: Path,
    binary: Path,
    allow_unverified: bool = False,
) -> dict[str, object]:
    """Bind the executed binary to the exact reviewed C++ source."""
    local_source = local_source.resolve()
    scratch_source = scratch_source.resolve()
    binary = binary.resolve()
    missing = [
        str(path)
        for path in (local_source, scratch_source, binary)
        if not path.is_file()
    ]
    if missing and not allow_unverified:
        raise PipelineError(f"build provenance input missing: {missing}")

    local_hash = sha256(local_source) if local_source.is_file() else None
    scratch_hash = sha256(scratch_source) if scratch_source.is_file() else None
    binary_hash = sha256(binary) if binary.is_file() else None
    source_match = local_hash is not None and local_hash == scratch_hash
    scratch_mtime_ns = (
        scratch_source.stat().st_mtime_ns if scratch_source.is_file() else None
    )
    binary_mtime_ns = binary.stat().st_mtime_ns if binary.is_file() else None
    binary_current = (
        scratch_mtime_ns is not None
        and binary_mtime_ns is not None
        and binary_mtime_ns >= scratch_mtime_ns
    )
    if not allow_unverified and not source_match:
        raise PipelineError(
            "reviewed source differs from ns-3 scratch source: "
            f"{local_source} != {scratch_source}"
        )
    if not allow_unverified and not binary_current:
        raise PipelineError(
            f"simulator binary is older than scratch source: {binary} < {scratch_source}"
        )
    return {
        "verification_mode": "override" if allow_unverified else "strict",
        "verified": bool(source_match and binary_current and not missing),
        "local_source": str(local_source),
        "local_source_sha256": local_hash,
        "scratch_source": str(scratch_source),
        "scratch_source_sha256": scratch_hash,
        "scratch_source_mtime_ns": scratch_mtime_ns,
        "source_byte_identical": source_match,
        "binary": str(binary),
        "binary_sha256": binary_hash,
        "binary_mtime_ns": binary_mtime_ns,
        "binary_not_older_than_source": binary_current,
        "missing": missing,
    }


def check_build(args: argparse.Namespace) -> None:
    provenance = verify_build_provenance(
        args.local_source,
        args.scratch_source,
        args.binary,
        args.allow_unverified_build,
    )
    print(json.dumps(provenance, sort_keys=True))


def manifest(args: argparse.Namespace) -> None:
    jobs: list[Job] = []
    for path in args.plan:
        jobs.extend(read_plan(path))
    validate_jobs(jobs)
    binary = args.binary.resolve()
    ns3_root = args.ns3_root.resolve()
    repo = Path(__file__).resolve().parent
    snapshot_dir = args.source_snapshot.resolve()
    checksum_path, snapshot_files = verify_source_snapshot(snapshot_dir)
    build_provenance = verify_build_provenance(
        repo / "v2v_cybersecurity_v2.cc",
        args.scratch_source,
        binary,
        args.allow_unverified_build,
    )
    run_records = []
    current_binary_hash = sha256(binary)
    for job in jobs:
        run_dir = args.runs_dir.resolve() / job.stage / job.experiment_id
        try:
            command = json.loads((run_dir / "command.json").read_text(encoding="utf-8"))
            status = json.loads((run_dir / "status.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PipelineError(f"{job.experiment_id}: cannot build manifest: {exc}") from exc
        if status.get("status") != "complete":
            raise PipelineError(f"{job.experiment_id}: incomplete during manifest")
        if status.get("binary_sha256") != current_binary_hash:
            raise PipelineError(
                f"{job.experiment_id}: run binary differs from manifest binary"
            )
        verify_status_files(job, run_dir, status)
        run_records.append(
            {
                **{field: getattr(job, field) for field in META_FIELDS},
                "args": job.args,
                "command_argv": command["command_argv"],
                "command_shell": command["command_shell"],
                "duration_s": status["duration_s"],
                "pair_rows": status["pair_rows"],
                "summary_sha256": status["summary_sha256"],
                "pair_output_enabled": writes_pairs(job),
                "trace_output_enabled": needs_trace(job),
            }
        )
        if writes_pairs(job):
            run_records[-1]["pairs_sha256"] = status["pairs_sha256"]
        if needs_trace(job):
            if "trace_sha256" not in status or "trace_rows" not in status:
                raise PipelineError(
                    f"{job.experiment_id}: trace provenance missing from status"
                )
            trace_path = run_dir / "trace.csv"
            try:
                trace_label = str(trace_path.relative_to(repo))
            except ValueError:
                trace_label = str(trace_path)
            run_records[-1]["trace_schema"] = "v6_trace"
            run_records[-1]["trace_path"] = trace_label
            run_records[-1]["trace_rows"] = status["trace_rows"]
            run_records[-1]["trace_sha256"] = status["trace_sha256"]

    artifact_paths = [
        *args.plan,
        args.schema,
        *args.artifact,
        checksum_path,
        *(snapshot_dir / name for name in snapshot_files),
    ]
    artifacts = {}
    for path in artifact_paths:
        resolved = path.resolve()
        if not resolved.is_file():
            raise PipelineError(f"manifest artifact missing: {resolved}")
        try:
            label = str(resolved.relative_to(repo))
        except ValueError:
            label = str(resolved)
        artifacts[label] = {
            "sha256": sha256(resolved),
            "bytes": resolved.stat().st_size,
        }

    version_path = ns3_root / "VERSION"
    threshold_data = None
    if args.threshold_json:
        threshold_data = json.loads(args.threshold_json.read_text(encoding="utf-8"))
    git_status = command_output(["git", "status", "--porcelain=v1"], cwd=repo)
    manifest_data = {
        "manifest_schema": "v6_manifest",
        "created_utc": utc_now(),
        "mode": jobs[0].mode,
        "stage_counts": {
            stage: sum(job.stage == stage for job in jobs)
            for stage in sorted({job.stage for job in jobs})
        },
        "total_runs": len(jobs),
        "runner_invocation": args.invocation,
        "source_snapshot": {
            "path": str(snapshot_dir),
            "files": snapshot_files,
            "checksums_sha256": sha256(checksum_path),
        },
        "frozen_threshold": threshold_data,
        "evaluation_policy": {
            "timing_family": "serial_timing",
            "timing_order": "paired AB/BA by RNG seed",
            "timing_pair_output": False,
            "timing_trace_output": False,
            "process_wall_times": (
                "manifest diagnostics only; excluded from scientific overhead "
                "because detector-on performs additional evaluation bookkeeping"
            ),
            "compute_cost_metric": (
                "simulator-instrumented per-call latency distribution and derived "
                "call throughput from serial detector-on runs"
            ),
            "state_metric": (
                "peak live keys/tracks and estimated deployable payload bytes per "
                "receiver; not process RSS and excludes allocator/STL overhead"
            ),
            "trace_sampling": (
                "full validation: all 439 jobs, including all 299 independent "
                "benign seeds, used only to fit/freeze baseline settings under "
                "the same exact seed-level false-alarm constraint; full test: "
                "all 30 seeds for every pure attack and benign, all 30 constoffset "
                "steady-state seeds, and all 90 onset-guard runs; smoke mirrors "
                "these families with one seed"
            ),
            "reference_model_primary": True,
            "simfit_role": (
                "CLI diagnostic only; excluded from publication plans because "
                "no disjoint v4 training provenance is bound"
            ),
        },
        "repository": {
            "root": str(repo),
            "git_sha": command_output(["git", "rev-parse", "HEAD"], cwd=repo),
            "git_status_porcelain": git_status.splitlines() if git_status else [],
            "source_sha256": sha256(repo / "v2v_cybersecurity_v2.cc"),
            "workflow_file_sha256": {
                name: sha256(repo / name)
                for name in (
                    "v2v_cybersecurity_v2.cc",
                    "run_experiments.sh",
                    "experiment_pipeline.py",
                    "aggregate.py",
                    "baselines.py",
                    "calibrate_llr.py",
                )
            },
            "git_diff_sha256": hashlib.sha256(
                command_output(["git", "diff", "--binary"], cwd=repo).encode("utf-8")
            ).hexdigest(),
        },
        "runtime": {
            "binary": str(binary),
            "binary_sha256": current_binary_hash,
            "build_provenance": build_provenance,
            "ns3_root": str(ns3_root),
            "ns3_version": version_path.read_text(encoding="utf-8").strip()
            if version_path.is_file()
            else "unknown",
            "compiler": command_output(["c++", "--version"]).splitlines()[0],
            "cmake": command_output(["cmake", "--version"]).splitlines()[0],
            "python": sys.version,
            "analysis_dependencies": {
                package: importlib.metadata.version(package)
                for package in ("numpy", "scipy", "matplotlib")
            },
        },
        "host": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "logical_cpus": os.cpu_count(),
            "process_cpu_affinity": sorted(os.sched_getaffinity(0))
            if hasattr(os, "sched_getaffinity")
            else "unavailable",
        },
        "artifacts": artifacts,
        "runs": run_records,
    }
    atomic_text(args.output, json.dumps(manifest_data, indent=2, sort_keys=True) + "\n")
    print(f"wrote provenance manifest: {args.output}")


def list_ids(args: argparse.Namespace) -> None:
    wanted = int(args.serial)
    for job in read_plan(args.plan):
        if job.serial == wanted:
            print(job.experiment_id)


def check_schema(args: argparse.Namespace) -> None:
    header = read_header(args.schema)
    print(f"validated v6 summary schema ({len(header)} fields): {args.schema}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    plan_parser = sub.add_parser("plan", help="write a deterministic experiment plan")
    plan_parser.add_argument("--mode", choices=("smoke", "full"), required=True)
    plan_parser.add_argument(
        "--phase", choices=("validation", "test"), required=True
    )
    plan_parser.add_argument("--threshold", type=float)
    plan_parser.add_argument("--output", type=Path, required=True)

    ids_parser = sub.add_parser("list-ids", help="emit plan IDs by serial flag")
    ids_parser.add_argument("--plan", type=Path, required=True)
    ids_parser.add_argument("--serial", choices=("0", "1"), required=True)

    schema_parser = sub.add_parser(
        "check-schema", help="validate the binary's discovered v6 schema"
    )
    schema_parser.add_argument("--schema", type=Path, required=True)

    run_parser = sub.add_parser("run-one", help="execute and validate one plan row")
    run_parser.add_argument("--plan", type=Path, required=True)
    run_parser.add_argument("--experiment-id", required=True)
    run_parser.add_argument("--binary", type=Path, required=True)
    run_parser.add_argument("--runs-dir", type=Path, required=True)
    run_parser.add_argument("--schema", type=Path, required=True)
    run_parser.add_argument("--resume", action="store_true")

    merge_parser = sub.add_parser("merge", help="strictly validate and merge runs")
    merge_parser.add_argument("--plan", type=Path, action="append", required=True)
    merge_parser.add_argument("--runs-dir", type=Path, required=True)
    merge_parser.add_argument("--schema", type=Path, required=True)
    merge_parser.add_argument("--summary-out", type=Path, required=True)
    merge_parser.add_argument("--pairs-out", type=Path, required=True)

    manifest_parser = sub.add_parser("manifest", help="write reproducibility manifest")
    manifest_parser.add_argument("--plan", type=Path, action="append", required=True)
    manifest_parser.add_argument("--runs-dir", type=Path, required=True)
    manifest_parser.add_argument("--binary", type=Path, required=True)
    manifest_parser.add_argument("--ns3-root", type=Path, required=True)
    manifest_parser.add_argument("--schema", type=Path, required=True)
    manifest_parser.add_argument("--threshold-json", type=Path)
    manifest_parser.add_argument("--source-snapshot", type=Path, required=True)
    manifest_parser.add_argument("--scratch-source", type=Path, required=True)
    manifest_parser.add_argument("--allow-unverified-build", action="store_true")
    manifest_parser.add_argument("--artifact", type=Path, action="append", default=[])
    manifest_parser.add_argument("--invocation", required=True)
    manifest_parser.add_argument("--output", type=Path, required=True)

    build_parser = sub.add_parser(
        "check-build", help="verify reviewed source, ns-3 scratch source and binary"
    )
    build_parser.add_argument("--local-source", type=Path, required=True)
    build_parser.add_argument("--scratch-source", type=Path, required=True)
    build_parser.add_argument("--binary", type=Path, required=True)
    build_parser.add_argument("--allow-unverified-build", action="store_true")

    args = parser.parse_args()
    try:
        if args.command == "plan":
            jobs = build_plan(args.mode, args.phase, args.threshold)
            write_plan(args.output, jobs)
            print(f"wrote {len(jobs)} {args.mode}/{args.phase} jobs: {args.output}")
        elif args.command == "list-ids":
            list_ids(args)
        elif args.command == "check-schema":
            check_schema(args)
        elif args.command == "run-one":
            run_one(args)
        elif args.command == "merge":
            merge(args)
        elif args.command == "manifest":
            manifest(args)
        elif args.command == "check-build":
            check_build(args)
        else:
            parser.error(f"unhandled command: {args.command}")
    except PipelineError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
