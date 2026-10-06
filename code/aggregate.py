#!/usr/bin/env python3
"""Strict v4 threshold selection and seed-clustered analysis.

Examples
--------
Select once on the validation partition::

    python3 aggregate.py select-threshold \
      --summary validation_summary_v4.csv \
      --pairs validation_pairs_v4.csv \
      --output analysis/selected_threshold.json

Analyze the combined validation/test artifact with that threshold frozen::

    python3 aggregate.py report --summary summary_v4.csv --pairs pairs_v4.csv \
      --threshold-json analysis/selected_threshold.json --output-dir analysis
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import os
import tempfile
from array import array
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

try:
    import numpy as np
    from scipy import stats
except ImportError as exc:  # fail explicitly; never substitute weaker statistics
    raise SystemExit(f"aggregate.py requires numpy and scipy: {exc}") from exc


META = {
    "experiment_id",
    "mode",
    "stage",
    "family",
    "arm",
    "replicate",
    "seed",
    "serial",
    "wall_duration_s",
}
SUMMARY_REQUIRED = META | {
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
    "null_ev",
    "naive_th",
    "prior",
    "threshold",
    "decay",
    "warmup",
    "decay_half_life_s",
    "attack_start_s",
    "comm_range",
    "gps_sigma",
    "detector_gps_sigma",
    "spd_sigma",
    "clock_sigma",
    "bsm_bytes",
    "pairs",
    "stream_tp",
    "stream_fp",
    "stream_tn",
    "stream_fn",
    "owner_tp",
    "owner_fp",
    "owner_tn",
    "owner_fn",
    "clean_fp",
    "clean_tn",
    "victim_pairs",
    "victim_pairs_alerted",
    "victim_ids",
    "victim_ids_alerted",
    "contested_tp",
    "contested_fp",
    "contested_tn",
    "contested_fn",
    "victim_pairs_contested",
    "victim_ids_contested",
    "malicious_expected_pairs",
    "malicious_expected_pairs_observed",
    "malicious_observed_pairs_any_range",
    "malicious_zero_reception_pairs",
    "latency_sum_s",
    "latency_n",
    "pdr_rx",
    "pdr_expected",
    "det_calls",
    "det_nanos",
    "stream_auc",
    "owner_auc",
    "ttd_detected_frac",
    "track_stream_tp",
    "track_stream_fp",
    "track_stream_tn",
    "track_stream_fn",
    "victim_pairs_track_alerted",
    "victim_ids_track_alerted",
    "track_capacity_dropped_messages",
}
PAIR_REQUIRED = META | {
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
    "assigned_attacker_use",
    "attack_active_use",
    "malicious_use",
    "malicious_messages",
    "owner_is_attacker",
    "clean_pair",
    "owner_seen",
    "victim_exposure_pair",
    "victim_ids",
    "identity_contested",
    "contested_stream_alert",
    "preexisting_contested",
    "first_contested_s",
    "first_stream_contested_s",
    "peak_score",
    "stream_peak_score",
    "final_alert",
    "ever_alert",
    "stream_alert",
    "preexisting_alert",
    "post_onset_crossing_intervals",
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
    "window_peak_score",
    "window_alert",
    "track_alert",
    "honest_track_alert",
    "owner_track_peak",
    "owner_track_alert",
    "track_capacity_dropped_messages",
}
COUNT_FIELDS = (
    "pairs",
    "stream_tp",
    "stream_fp",
    "stream_tn",
    "stream_fn",
    "owner_tp",
    "owner_fp",
    "owner_tn",
    "owner_fn",
    "clean_fp",
    "clean_tn",
    "victim_pairs",
    "victim_pairs_alerted",
    "victim_ids",
    "victim_ids_alerted",
    "contested_tp",
    "contested_fp",
    "contested_tn",
    "contested_fn",
    "victim_pairs_contested",
    "victim_ids_contested",
    "latency_n",
    "pdr_rx",
    "pdr_expected",
    "malicious_expected_pairs",
    "malicious_expected_pairs_observed",
    "malicious_observed_pairs_any_range",
    "malicious_zero_reception_pairs",
    "det_calls",
    "track_stream_tp",
    "track_stream_fp",
    "track_stream_tn",
    "track_stream_fn",
    "victim_pairs_track_alerted",
    "victim_ids_track_alerted",
    "track_capacity_dropped_messages",
)


class AnalysisError(RuntimeError):
    pass


# Crossing telemetry uses a compact, language-neutral union of half-open
# threshold intervals: ``lo:hi|lo:hi``.  A rising score transition from
# ``previous`` to ``current`` crosses every threshold t satisfying
# previous <= t < current.  The simulator merges overlapping/adjacent
# intervals before writing them; retaining the intervals, rather than only a
# peak, lets validation replay exactly the same transition rule at every
# candidate threshold.
def parse_crossing_intervals(value: str) -> tuple[tuple[float, float], ...]:
    """Parse and strictly validate merged ``[lo, hi)`` score intervals.

    The empty string and ``-`` both denote an empty union.  This function is
    intentionally public so selector/runtime equivalence tests can import the
    production parser instead of duplicating its semantics.
    """

    text = value.strip()
    if text in {"", "-"}:
        return ()
    intervals: list[tuple[float, float]] = []
    for item in text.split("|"):
        pieces = item.split(":")
        if len(pieces) != 2:
            raise AnalysisError(
                f"invalid crossing interval {item!r}; expected lo:hi"
            )
        lo = finite(pieces[0], "crossing interval lower endpoint")
        hi = finite(pieces[1], "crossing interval upper endpoint")
        if lo < 0.0 or hi > 1.0 or not lo < hi:
            raise AnalysisError(
                f"invalid crossing interval [{lo}, {hi}); require 0<=lo<hi<=1"
            )
        if intervals and lo <= intervals[-1][1]:
            raise AnalysisError(
                "crossing intervals must be sorted, disjoint, and already merged"
            )
        intervals.append((lo, hi))
    return tuple(intervals)


def crossing_alert(
    intervals: Sequence[tuple[float, float]], threshold: float
) -> bool:
    """Return the simulator's exact strict post-onset crossing decision."""

    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise AnalysisError(f"invalid decision threshold {threshold!r}")
    return any(lo <= threshold < hi for lo, hi in intervals)


def stream_prediction(row: dict[str, str], threshold: float) -> bool:
    """Replay the v5 primary endpoint from one pair row.

    One statistic, one window, no dependence on the label. v4 applied a
    post-onset new-crossing rule to positives and a full-window any-crossing
    rule to negatives, so its confusion matrix did not belong to a single
    classifier and its AUC (which ranked peaks) did not correspond to the
    reported operating point.
    """

    return finite(row["window_peak_score"], "pair/window_peak_score") > threshold


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def finite(value: str, context: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise AnalysisError(f"{context}: expected numeric value, got {value!r}") from exc
    if not math.isfinite(result):
        raise AnalysisError(f"{context}: non-finite value {value!r}")
    return result


def integer(value: str, context: str) -> int:
    result = finite(value, context)
    rounded = round(result)
    if result < 0 or not math.isclose(result, rounded, abs_tol=1e-9):
        raise AnalysisError(f"{context}: expected nonnegative integer, got {value!r}")
    return int(rounded)


def strict_csv(path: Path, required: set[str]) -> tuple[list[str], Iterable[dict[str, str]]]:
    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError as exc:
        raise AnalysisError(f"cannot open {path}: {exc}") from exc
    reader = csv.reader(handle)
    try:
        header = next(reader)
    except StopIteration:
        handle.close()
        raise AnalysisError(f"{path}: empty CSV")
    if len(header) != len(set(header)):
        handle.close()
        raise AnalysisError(f"{path}: duplicate header field")
    missing = required.difference(header)
    if missing:
        handle.close()
        raise AnalysisError(f"{path}: missing required fields {sorted(missing)}")

    def rows() -> Iterable[dict[str, str]]:
        try:
            for line_no, record in enumerate(reader, 2):
                if record == header:
                    raise AnalysisError(f"{path}:{line_no}: repeated header")
                if len(record) != len(header):
                    raise AnalysisError(
                        f"{path}:{line_no}: {len(record)} fields, expected {len(header)}"
                    )
                yield dict(zip(header, record))
        finally:
            handle.close()

    return header, rows()


def load_summary(path: Path) -> list[dict[str, str]]:
    _, source = strict_csv(path, SUMMARY_REQUIRED)
    rows: list[dict[str, str]] = []
    ids: set[str] = set()
    signatures: set[tuple[str, ...]] = set()
    config_fields = (
        "n",
        "frac",
        "n_attackers",
        "attack",
        "run",
        "sim_time",
        "interval",
        "detector",
        "score_model",
        "mobility",
        "null_ev",
        "naive_th",
        "prior",
        "threshold",
        "decay",
        "decay_half_life_s",
        "warmup",
        "attack_start_s",
        # The guard interval is a configuration axis: the onset_guard arms vary
        # only onsetBlank and share seeds with pure_constoffset, so omitting it
        # made three legitimate arms look like duplicates of a fourth.
        "onset_blank_s",
        "comm_range",
        "gps_sigma",
        "detector_gps_sigma",
        "spd_sigma",
        "clock_sigma",
        "bsm_bytes",
    )
    for line_no, row in enumerate(source, 2):
        eid = row["experiment_id"]
        if not eid or eid in ids:
            raise AnalysisError(f"{path}:{line_no}: duplicate/empty experiment_id {eid!r}")
        ids.add(eid)
        if row["schema"] != "v6":
            raise AnalysisError(f"{eid}: expected summary schema v4")
        if row["mode"] not in {"smoke", "full"}:
            raise AnalysisError(f"{eid}: invalid mode {row['mode']!r}")
        if row["stage"] not in {"validation", "test"}:
            raise AnalysisError(f"{eid}: invalid stage {row['stage']!r}")
        if row["score_model"] not in {"reference", "simfit"}:
            raise AnalysisError(f"{eid}: invalid score_model {row['score_model']!r}")
        if row["detector"] not in {"0", "1"}:
            raise AnalysisError(f"{eid}: detector must be 0/1")
        if row["null_ev"] not in {"0", "1"} or row["naive_th"] not in {"0", "1"}:
            raise AnalysisError(f"{eid}: ablation flags must be 0/1")
        if integer(row["seed"], f"{eid}/seed") != integer(row["run"], f"{eid}/run"):
            raise AnalysisError(f"{eid}: metadata seed differs from simulator run")
        for field in COUNT_FIELDS:
            integer(row[field], f"{eid}/{field}")
        for field in (
            "n",
            "n_attackers",
            "detector",
            "null_ev",
            "naive_th",
            "bsm_bytes",
        ):
            integer(row[field], f"{eid}/{field}")
        for field in (
            "frac",
            "sim_time",
            "interval",
            "threshold",
            "decay",
            "decay_half_life_s",
            "warmup",
            "attack_start_s",
            "comm_range",
            "gps_sigma",
            "detector_gps_sigma",
            "prior",
            "spd_sigma",
            "clock_sigma",
            "latency_sum_s",
            "det_nanos",
            "wall_duration_s",
        ):
            finite(row[field], f"{eid}/{field}")
        # attack_start_s == 0 is the steady-state arm, where attackers are
        # adversarial from their first message. What must hold for every arm
        # is that the evaluation window is well formed and reported exactly.
        row_warmup = finite(row["warmup"], f"{eid}/warmup")
        row_attack_start = finite(row["attack_start_s"], f"{eid}/attack_start_s")
        row_sim_time = finite(row["sim_time"], f"{eid}/sim_time")
        row_onset_blank = finite(row["onset_blank_s"], f"{eid}/onset_blank_s")
        row_eval_start = finite(
            row["eval_window_start_s"], f"{eid}/eval_window_start_s"
        )
        if not (
            0.0 <= row_attack_start < row_sim_time
            and 0.0 <= row_warmup < row_sim_time
            and row_onset_blank >= 0.0
            and row_eval_start < row_sim_time
        ):
            raise AnalysisError(
                f"{eid}: evaluation window is not well formed"
            )
        if abs(row_eval_start - max(row_warmup, row_attack_start + row_onset_blank)) > 1e-9:
            raise AnalysisError(
                f"{eid}: eval_window_start_s is not "
                f"max(warmup, attack_start_s + onset_blank_s)"
            )
        half_life = finite(
            row["decay_half_life_s"], f"{eid}/decay_half_life_s"
        )
        if half_life != -1.0 and half_life <= 0.0:
            raise AnalysisError(
                f"{eid}: decay_half_life_s must be positive or -1"
            )
        signature = tuple(row[field] for field in config_fields)
        if signature in signatures:
            raise AnalysisError(f"{eid}: duplicate simulator configuration")
        signatures.add(signature)
        rows.append(row)
    if not rows:
        raise AnalysisError(f"{path}: no summary rows")
    modes = {row["mode"] for row in rows}
    if len(modes) != 1:
        raise AnalysisError(f"{path}: mixed smoke/full data")
    validate_grid(rows)
    return rows


def validate_grid(rows: Sequence[dict[str, str]]) -> None:
    mode = rows[0]["mode"]
    stages = Counter(row["stage"] for row in rows)
    families = Counter((row["stage"], row["family"]) for row in rows)
    if set(stages) == {"validation"}:
        expected = 439 if mode == "full" else 8
        if stages["validation"] != expected:
            raise AnalysisError(
                f"{mode} validation grid has {stages['validation']} rows, expected {expected}"
            )
        return
    # Keep the canonical held-out grid in sync with experiment_pipeline.plan(),
    # including steady-state controls, onset guards and benign stress arms.
    expected_stages = (
        {"validation": 439, "test": 1040}
        if mode == "full"
        else {"validation": 8, "test": 32}
    )
    if dict(stages) != expected_stages:
        raise AnalysisError(f"{mode} stage counts {dict(stages)}, expected {expected_stages}")
    validation_runs = {
        integer(row["run"], f"{row['experiment_id']}/run")
        for row in rows
        if row["stage"] == "validation"
    }
    test_runs = {
        integer(row["run"], f"{row['experiment_id']}/run")
        for row in rows
        if row["stage"] == "test"
    }
    overlap = sorted(validation_runs & test_runs)
    if overlap:
        raise AnalysisError(
            f"validation/test RNG run IDs are not disjoint: {overlap}"
        )
    test_expected = (
        {
            "pure_attack": 210,
            # Paired steady-state arms: 4 attacks x 30 seeds.
            "steady_state": 120,
            "mixedhard_prevalence": 120,
            "score_variant": 60,
            "noise_misspecification": 90,
            # Manoeuvring mobility, paired with mixedhard_frac_0p3 on the
            # same seeds.
            "mobility": 30,
            "scale": 60,
            "benign": 50,
            "serial_timing": 60,
            "onset_guard": 90,
            "onset_time": 60,
            "benign_stress": 90,
        }
        if mode == "full"
        else {
            "pure_attack": 7,
            "steady_state": 4,
            "mixedhard_prevalence": 2,
            "score_variant": 2,
            "noise_misspecification": 3,
            "mobility": 1,
            "scale": 2,
            "benign": 1,
            "serial_timing": 2,
            "onset_guard": 3,
            "onset_time": 2,
            "benign_stress": 3,
        }
    )
    observed = {
        family: count
        for (stage, family), count in families.items()
        if stage == "test"
    }
    if observed != test_expected:
        raise AnalysisError(f"{mode} test grid {observed}, expected {test_expected}")


@dataclass
class PairArrays:
    scores: array = field(default_factory=lambda: array("d"))
    truth: bytearray = field(default_factory=bytearray)
    owner_scores: array = field(default_factory=lambda: array("d"))
    owner_truth: bytearray = field(default_factory=bytearray)
    clean: bytearray = field(default_factory=bytearray)
    run_codes: array = field(default_factory=lambda: array("I"))
    run_ids: list[str] = field(default_factory=list)
    run_index: dict[str, int] = field(default_factory=dict)
    seed_codes: array = field(default_factory=lambda: array("I"))
    seed_ids: list[int] = field(default_factory=list)
    seed_index: dict[int, int] = field(default_factory=dict)
    benign_validation: bytearray = field(default_factory=bytearray)
    crossings: list[tuple[tuple[float, float], ...]] = field(default_factory=list)
    survival_time: array = field(default_factory=lambda: array("d"))
    survival_event: bytearray = field(default_factory=bytearray)
    survival_run: array = field(default_factory=lambda: array("I"))

    def code(self, eid: str) -> int:
        if eid not in self.run_index:
            self.run_index[eid] = len(self.run_ids)
            self.run_ids.append(eid)
        return self.run_index[eid]

    def seed_code(self, seed: int) -> int:
        if seed not in self.seed_index:
            self.seed_index[seed] = len(self.seed_ids)
            self.seed_ids.append(seed)
        return self.seed_index[seed]


def scan_pairs(
    path: Path,
    summaries: Sequence[dict[str, str]],
    *,
    collect_by_arm: bool,
) -> tuple[PairArrays, dict[tuple[str, str], PairArrays]]:
    _, source = strict_csv(path, PAIR_REQUIRED)
    by_id = {row["experiment_id"]: row for row in summaries}
    counts = Counter()
    recomputed: dict[str, Counter] = defaultdict(Counter)
    victim_ids: dict[str, set[str]] = defaultdict(set)
    alerted_victim_ids: dict[str, set[str]] = defaultdict(set)
    contested_victim_ids: dict[str, set[str]] = defaultdict(set)
    track_alerted_victim_ids: dict[str, set[str]] = defaultdict(set)
    all_data = PairArrays()
    arms: dict[tuple[str, str], PairArrays] = defaultdict(PairArrays)
    current: str | None = None
    completed_ids: set[str] = set()
    current_keys: set[tuple[str, str]] = set()
    for line_no, row in enumerate(source, 2):
        eid = row["experiment_id"]
        summary = by_id.get(eid)
        if summary is None:
            raise AnalysisError(f"{path}:{line_no}: pair references unknown run {eid}")
        if row["schema"] != "v6_pair":
            raise AnalysisError(f"{eid}: expected pair schema v4_pair")
        for field in (
            "mode",
            "stage",
            "family",
            "arm",
            "seed",
            "attack",
            "run",
            "score_model",
        ):
            if row[field] != summary[field]:
                raise AnalysisError(f"{eid}: pair {field} differs from summary")
        for field in (
            "n",
            "frac",
            "threshold",
            "decay_half_life_s",
            "attack_start_s",
        ):
            if not math.isclose(
                finite(row[field], f"{eid}/pair/{field}"),
                finite(summary[field], f"{eid}/summary/{field}"),
                rel_tol=1e-9,
                abs_tol=1e-9,
            ):
                raise AnalysisError(f"{eid}: pair {field} differs from summary")
        if eid != current:
            if current is not None:
                completed_ids.add(current)
            if eid in completed_ids:
                raise AnalysisError(f"{eid}: non-contiguous pair block")
            current = eid
            current_keys = set()
        key = (row["receiver_id"], row["claimed_id"])
        if key in current_keys:
            raise AnalysisError(f"{eid}: duplicate receiver/claimed-id pair {key}")
        current_keys.add(key)
        counts[eid] += 1
        truth = integer(row["malicious_use"], f"{eid}/malicious_use")
        assigned_use = integer(
            row["assigned_attacker_use"], f"{eid}/assigned_attacker_use"
        )
        active_use = integer(row["attack_active_use"], f"{eid}/attack_active_use")
        malicious_messages = integer(
            row["malicious_messages"], f"{eid}/malicious_messages"
        )
        window_messages = integer(row["window_msgs"], f"{eid}/window_msgs")
        if malicious_messages > window_messages:
            raise AnalysisError(f"{eid}: malicious messages exceed W messages")
        capacity_drops = integer(
            row["track_capacity_dropped_messages"],
            f"{eid}/track_capacity_dropped_messages",
        )
        recomputed[eid]["track_capacity_dropped_messages"] += capacity_drops
        owner_truth = integer(row["owner_is_attacker"], f"{eid}/owner_is_attacker")
        clean = integer(row["clean_pair"], f"{eid}/clean_pair")
        victim_exposure = integer(
            row["victim_exposure_pair"], f"{eid}/victim_exposure_pair"
        )
        ever_alert = integer(row["ever_alert"], f"{eid}/ever_alert")
        stream_alert = integer(row["stream_alert"], f"{eid}/stream_alert")
        owner_seen = integer(row["owner_seen"], f"{eid}/owner_seen")
        final_alert = integer(row["final_alert"], f"{eid}/final_alert")
        preexisting_alert = integer(row["preexisting_alert"], f"{eid}/preexisting_alert")
        identity_contested = integer(
            row["identity_contested"], f"{eid}/identity_contested"
        )
        contested_stream_alert = integer(
            row["contested_stream_alert"], f"{eid}/contested_stream_alert"
        )
        preexisting_contested = integer(
            row["preexisting_contested"], f"{eid}/preexisting_contested"
        )
        for field, value in (
            ("assigned_attacker_use", assigned_use),
            ("attack_active_use", active_use),
            ("malicious_use", truth),
            ("owner_is_attacker", owner_truth),
            ("clean_pair", clean),
            ("victim_exposure_pair", victim_exposure),
            ("ever_alert", ever_alert),
            ("stream_alert", stream_alert),
            ("owner_seen", owner_seen),
            ("final_alert", final_alert),
            ("preexisting_alert", preexisting_alert),
            ("identity_contested", identity_contested),
            ("contested_stream_alert", contested_stream_alert),
            ("preexisting_contested", preexisting_contested),
        ):
            if value not in {0, 1}:
                raise AnalysisError(f"{eid}: {field} must be 0/1")
        if clean != int(not owner_truth and not truth):
            raise AnalysisError(f"{eid}: inconsistent clean_pair label")
        if victim_exposure != int(not owner_truth and truth):
            raise AnalysisError(f"{eid}: inconsistent victim exposure label")
        if truth > active_use or active_use > assigned_use:
            raise AnalysisError(
                f"{eid}: malicious/active/assigned truth fields are inconsistent"
            )
        if bool(malicious_messages) != bool(truth):
            raise AnalysisError(
                f"{eid}: malicious_messages disagrees with malicious_use"
            )
        configured_threshold = finite(summary["threshold"], f"{eid}/threshold")
        crossings = parse_crossing_intervals(
            row["post_onset_crossing_intervals"]
        )
        eligible = integer(row["eligible"], f"{eid}/eligible")
        if eligible not in {0, 1}:
            raise AnalysisError(f"{eid}: eligible must be 0/1")
        window_alert = integer(row["window_alert"], f"{eid}/window_alert")
        if window_alert not in {0, 1}:
            raise AnalysisError(f"{eid}: window_alert must be 0/1")
        window_peak = finite(row["window_peak_score"], f"{eid}/window_peak_score")
        window_exposure = finite(
            row["window_exposure_s"], f"{eid}/window_exposure_s"
        )
        track_alert = integer(row["track_alert"], f"{eid}/track_alert")
        owner_track_alert = integer(
            row["owner_track_alert"], f"{eid}/owner_track_alert"
        )
        honest_track_alert = integer(
            row["honest_track_alert"], f"{eid}/honest_track_alert"
        )
        for field, value in (
            ("track_alert", track_alert),
            ("owner_track_alert", owner_track_alert),
            ("honest_track_alert", honest_track_alert),
        ):
            if value not in {0, 1}:
                raise AnalysisError(f"{eid}: {field} must be 0/1")

        # A pair with no exposure inside the evaluation window has no decision
        # to contribute. In v4 such pairs were counted as free true negatives
        # against a true-positive rate measured over a strictly later window.
        if not eligible:
            recomputed[eid]["ineligible_pairs"] += 1
            continue
        recomputed[eid]["eligible_pairs"] += 1

        # THE regression check for the v4 defect: the stored decision must be
        # exactly the statistic the ROC curve ranks, thresholded.
        exact_prediction = stream_prediction(row, configured_threshold)
        if bool(window_alert) != exact_prediction:
            raise AnalysisError(
                f"{eid}/{key}: stored window_alert disagrees with "
                f"window_peak_score > {configured_threshold}"
            )
        stream_prediction_value = int(exact_prediction)
        owner_prediction = stream_prediction_value
        recomputed[eid][
            "stream_tp"
            if truth and stream_prediction_value
            else "stream_fn"
            if truth
            else "stream_fp"
            if stream_prediction_value
            else "stream_tn"
        ] += 1
        recomputed[eid][
            "track_stream_tp"
            if truth and track_alert
            else "track_stream_fn"
            if truth
            else "track_stream_fp"
            if track_alert
            else "track_stream_tn"
        ] += 1
        contested_prediction = identity_contested
        recomputed[eid][
            "contested_tp"
            if truth and contested_prediction
            else "contested_fn"
            if truth
            else "contested_fp"
            if contested_prediction
            else "contested_tn"
        ] += 1
        if truth:
            recomputed[eid]["malicious_observed_pairs_any_range"] += 1
        recomputed[eid][
            "owner_tp"
            if owner_truth and owner_prediction
            else "owner_fn"
            if owner_truth
            else "owner_fp"
            if owner_prediction
            else "owner_tn"
        ] += 1
        if clean:
            recomputed[eid][
                "clean_fp" if stream_prediction_value else "clean_tn"
            ] += 1
        if victim_exposure:
            recomputed[eid]["victim_pairs"] += 1
            victim_ids[eid].add(row["claimed_id"])
            if stream_prediction_value:
                recomputed[eid]["victim_pairs_alerted"] += 1
                alerted_victim_ids[eid].add(row["claimed_id"])
            if contested_stream_alert:
                recomputed[eid]["victim_pairs_contested"] += 1
                contested_victim_ids[eid].add(row["claimed_id"])
            if owner_track_alert:
                recomputed[eid]["victim_pairs_track_alerted"] += 1
                track_alerted_victim_ids[eid].add(row["claimed_id"])
        # Both AUC targets rank the statistic the operating point thresholds,
        # so the reported (FPR, TPR) point lies on the reported curve.
        score = window_peak
        owner_score = window_peak
        if truth:
            # Derive survival from the PRIMARY columns rather than trusting the
            # emitted ones. Simulator builds before the survival-origin fix
            # gated the event on the legacy crossing flag while timing from the
            # v5 window exceedance; when those disagreed the emitted follow-up
            # went negative. Recomputing here keeps one definition -- same
            # origin, same event -- and makes older pair files usable.
            ttd = finite(
                row["stream_time_to_detect_s"], f"{eid}/stream_time_to_detect_s"
            )
            if ttd >= 0.0 and not stream_prediction_value:
                raise AnalysisError(
                    f"{eid}: stream latency event without primary window alert"
                )
            onset = max(
                finite(row["eval_window_start_s"], f"{eid}/eval_window_start_s"),
                finite(row["first_malicious_seen_s"], f"{eid}/first_malicious_seen_s"),
            )
            if finite(
                row["first_malicious_seen_s"],
                f"{eid}/first_malicious_seen_s",
            ) < finite(
                row["eval_window_start_s"], f"{eid}/eval_window_start_s"
            ):
                raise AnalysisError(f"{eid}: malicious truth begins before W")
            last_seen = finite(row["last_seen_s"], f"{eid}/last_seen_s")
            stream_censored = 0 if ttd >= 0.0 else 1
            if row["stream_censored"] != str(stream_censored):
                raise AnalysisError(
                    f"{eid}: emitted stream censor flag disagrees with latency event"
                )
            stream_duration = ttd if ttd >= 0.0 else max(0.0, last_seen - onset)
            if stream_duration < 0:
                raise AnalysisError(f"{eid}: negative stream follow-up")
        else:
            if row["stream_censored"] != "-1":
                raise AnalysisError(
                    f"{eid}: non-malicious stream_censored must use sentinel -1"
                )
            stream_censored = -1
            stream_duration = -1.0
        data = all_data
        code = data.code(eid)
        seed_code = data.seed_code(integer(row["seed"], f"{eid}/seed"))
        data.scores.append(score)
        data.truth.append(truth)
        data.owner_scores.append(owner_score)
        data.owner_truth.append(owner_truth)
        data.clean.append(clean)
        data.run_codes.append(code)
        data.seed_codes.append(seed_code)
        data.benign_validation.append(
            int(row["stage"] == "validation" and row["attack"] == "none")
        )
        data.crossings.append(crossings)
        if collect_by_arm and row["stage"] == "test" and summary["detector"] == "1":
            arm_data = arms[(row["family"], row["arm"])]
            arm_code = arm_data.code(eid)
            arm_data.scores.append(score)
            arm_data.truth.append(truth)
            arm_data.owner_scores.append(owner_score)
            arm_data.owner_truth.append(owner_truth)
            arm_data.clean.append(clean)
            arm_data.run_codes.append(arm_code)
            if truth:
                arm_data.survival_time.append(stream_duration)
                arm_data.survival_event.append(1 - stream_censored)
                arm_data.survival_run.append(arm_code)
    for eid, summary in by_id.items():
        # Serial timing intentionally suppresses pair output for both detector
        # states. Its internal pair count is not part of the scientific pair
        # artifact and cannot be reconstructed from that artifact.
        if summary["family"] == "serial_timing":
            if counts[eid]:
                raise AnalysisError(f"{eid}: timing run unexpectedly has pair rows")
            continue
        expected = integer(summary["pairs"], f"{eid}/pairs")
        if counts[eid] != expected:
            raise AnalysisError(
                f"{eid}: merged pair count {counts[eid]}, summary reports {expected}"
            )
        recomputed[eid]["victim_ids"] = len(victim_ids[eid])
        recomputed[eid]["victim_ids_alerted"] = len(alerted_victim_ids[eid])
        recomputed[eid]["victim_ids_contested"] = len(contested_victim_ids[eid])
        recomputed[eid]["victim_ids_track_alerted"] = len(
            track_alerted_victim_ids[eid]
        )
        expected_opportunities = integer(
            summary["malicious_expected_pairs"], f"{eid}/malicious_expected_pairs"
        )
        zero_opportunities = integer(
            summary["malicious_zero_reception_pairs"],
            f"{eid}/malicious_zero_reception_pairs",
        )
        observed_opportunities = integer(
            summary["malicious_expected_pairs_observed"],
            f"{eid}/malicious_expected_pairs_observed",
        )
        if expected_opportunities != (
            observed_opportunities + zero_opportunities
        ):
            raise AnalysisError(
                f"{eid}: malicious opportunity accounting is not expected=observed+zero"
            )
        for field in (
            "stream_tp",
            "stream_fp",
            "stream_tn",
            "stream_fn",
            "owner_tp",
            "owner_fp",
            "owner_tn",
            "owner_fn",
            "clean_fp",
            "clean_tn",
            "victim_pairs",
            "victim_pairs_alerted",
            "victim_ids",
            "victim_ids_alerted",
            "contested_tp",
            "contested_fp",
            "contested_tn",
            "contested_fn",
            "victim_pairs_contested",
            "victim_ids_contested",
            "malicious_observed_pairs_any_range",
            "track_stream_tp",
            "track_stream_fp",
            "track_stream_tn",
            "track_stream_fn",
            "victim_pairs_track_alerted",
            "victim_ids_track_alerted",
            "track_capacity_dropped_messages",
        ):
            reported = integer(summary[field], f"{eid}/{field}")
            if recomputed[eid][field] != reported:
                raise AnalysisError(
                    f"{eid}: recomputed {field}={recomputed[eid][field]}, "
                    f"summary reports {reported}"
                )
    return all_data, dict(arms)


def f1(tp: int, fp: int, fn: int) -> float:
    denominator = 2 * tp + fp + fn
    return 2.0 * tp / denominator if denominator else math.nan


def deterministic_threshold_grid(step: float) -> np.ndarray:
    """Return the preregistered inclusive grid 0, step, ..., 1."""

    if not math.isfinite(step) or not 0.0 < step <= 1.0:
        raise AnalysisError("threshold-grid step must be finite and in (0,1]")
    count = round(1.0 / step)
    if count < 1 or not math.isclose(count * step, 1.0, abs_tol=1e-12):
        raise AnalysisError("threshold-grid step must divide [0,1] exactly")
    grid = np.arange(count + 1, dtype=np.float64) / count
    grid[-1] = 1.0
    return grid


def _add_threshold_range(
    difference: np.ndarray,
    block: int,
    grid: np.ndarray,
    lo: float,
    hi: float,
) -> None:
    """Add one half-open threshold interval to a difference-count matrix."""

    start = int(np.searchsorted(grid, lo, side="left"))
    stop = int(np.searchsorted(grid, hi, side="left"))
    if start < stop:
        difference[block, start] += 1
        difference[block, stop] -= 1


def threshold_count_matrices(
    data: PairArrays, grid: np.ndarray
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Replay v5 predictions on every grid point, blocked by RNG seed.

    Returns ``(tp, fp, positives, benign_clean_fpr)``.  This public helper is
    used by synthetic tests to prove the selector and runtime endpoint agree.

    Both classes take the same path: alert iff window_peak_score > threshold.
    v4 walked crossing intervals for positives and peaks for negatives, which
    is what allowed the selector's curve to disagree with the endpoint it was
    selecting a threshold for.
    """

    seed_codes = np.frombuffer(data.seed_codes, dtype=np.uint32)
    truths = np.frombuffer(data.truth, dtype=np.uint8).astype(bool)
    peaks = np.frombuffer(data.owner_scores, dtype=np.float64)
    benign = np.frombuffer(data.benign_validation, dtype=np.uint8).astype(bool)
    if not (len(seed_codes) == len(truths) == len(peaks)):
        raise AnalysisError("internal pair-array length mismatch")
    seed_count, grid_count = len(data.seed_ids), len(grid)
    positive_difference = np.zeros((seed_count, grid_count + 1), dtype=np.int64)
    negative_difference = np.zeros_like(positive_difference)
    clean_difference = np.zeros_like(positive_difference)
    positives = np.bincount(seed_codes[truths], minlength=seed_count).astype(np.int64)
    clean_n = np.bincount(seed_codes[benign], minlength=seed_count).astype(np.int64)
    for index, block_value in enumerate(seed_codes):
        block = int(block_value)
        # Strict score > threshold means every grid value below the peak.
        stop = int(np.searchsorted(grid, peaks[index], side="left"))
        target = positive_difference if truths[index] else negative_difference
        if stop:
            target[block, 0] += 1
            target[block, stop] -= 1
        if benign[index]:
            if truths[index]:
                raise AnalysisError("benign validation pair is labelled malicious")
            stop = int(np.searchsorted(grid, peaks[index], side="left"))
            if stop:
                clean_difference[block, 0] += 1
                clean_difference[block, stop] -= 1
    tp = np.cumsum(positive_difference[:, :-1], axis=1)
    fp = np.cumsum(negative_difference[:, :-1], axis=1)
    clean_fp = np.cumsum(clean_difference[:, :-1], axis=1)
    clean_fpr = np.divide(
        clean_fp,
        clean_n[:, None],
        out=np.full(clean_fp.shape, np.nan, dtype=np.float64),
        where=clean_n[:, None] > 0,
    )
    return tp, fp, positives, clean_fpr


def seed_any_event_upper(
    events: np.ndarray, trials: int, *, confidence: float
) -> np.ndarray:
    """Exact one-sided Clopper--Pearson bounds for seed-level events.

    A seed's clean-pair FPR is at most the indicator that the seed has any
    clean false positive. Therefore this seed-level bound is conservative for
    mean per-seed clean-pair FPR without treating dependent pairs as trials.
    """

    if trials <= 0 or events.ndim != 1 or np.any((events < 0) | (events > trials)):
        raise AnalysisError("invalid seed-level event counts")
    if not 0.5 < confidence < 1.0:
        raise AnalysisError("confidence must be in (0.5,1)")
    upper = np.ones(events.shape, dtype=np.float64)
    mask = events < trials
    upper[mask] = stats.beta.ppf(
        confidence, events[mask] + 1, trials - events[mask]
    )
    return upper


def choose_threshold(
    data: PairArrays,
    *,
    grid_step: float,
    max_clean_fpr_upper: float,
    confidence: float,
) -> dict[str, float | int]:
    """Choose a threshold using the exact v4 primary endpoint."""

    grid = deterministic_threshold_grid(grid_step)
    tp, fp, positives, clean_fpr = threshold_count_matrices(data, grid)
    valid_positive = positives > 0
    if not valid_positive.any():
        raise AnalysisError("validation partition has no positive RNG-seed blocks")
    fn = positives[:, None] - tp
    denominator = 2 * tp + fp + fn
    per_seed_f1 = np.divide(
        2 * tp,
        denominator,
        out=np.full(denominator.shape, np.nan, dtype=np.float64),
        where=denominator > 0,
    )
    macro_f1 = np.nanmean(per_seed_f1[valid_positive], axis=0)
    clean_rows = ~np.isnan(clean_fpr).all(axis=1)
    if not clean_rows.any():
        raise AnalysisError("validation partition has no benign seed blocks")
    clean_values = clean_fpr[clean_rows]
    clean_mean = clean_values.mean(axis=0)
    clean_seed_events = np.count_nonzero(clean_values > 0.0, axis=0)
    clean_upper = seed_any_event_upper(
        clean_seed_events, len(clean_values), confidence=confidence
    )
    feasible = clean_upper <= max_clean_fpr_upper + 1e-15
    if not feasible.any():
        raise AnalysisError("no grid threshold met the clean-FPR upper-bound constraint")
    # Deterministic lexicographic rule: highest macro F1, lowest clean upper
    # bound, lowest empirical clean FPR, then highest threshold.
    candidates = np.flatnonzero(feasible)
    best_index = max(
        (int(index) for index in candidates),
        key=lambda index: (
            float(macro_f1[index]),
            -float(clean_upper[index]),
            -float(clean_mean[index]),
            float(grid[index]),
        ),
    )
    return {
        "threshold": float(grid[best_index]),
        "validation_macro_f1": float(macro_f1[best_index]),
        "validation_macro_clean_fpr": float(clean_mean[best_index]),
        "validation_clean_fpr_upper": float(clean_upper[best_index]),
        "validation_clean_seed_any_fp_events": int(clean_seed_events[best_index]),
        "validation_positive_seed_blocks": int(valid_positive.sum()),
        "validation_clean_seed_blocks": int(clean_rows.sum()),
        "candidate_thresholds": int(len(grid)),
        "feasible_thresholds": int(feasible.sum()),
    }


def select_threshold(args: argparse.Namespace) -> None:
    summaries = load_summary(args.summary)
    if {row["stage"] for row in summaries} != {"validation"}:
        raise AnalysisError("threshold selection input must contain validation rows only")
    data, _ = scan_pairs(args.pairs, summaries, collect_by_arm=False)
    if not data.scores:
        raise AnalysisError("validation pair file has no pairs")
    scores = np.frombuffer(data.scores, dtype=np.float64)
    owner_scores = np.frombuffer(data.owner_scores, dtype=np.float64)
    if np.any((scores < 0.0) | (scores > 1.0)) or np.any(
        (owner_scores < 0.0) | (owner_scores > 1.0)
    ):
        raise AnalysisError("validation pair scores must be in [0,1]")
    best_detail = choose_threshold(
        data,
        grid_step=args.grid_step,
        max_clean_fpr_upper=args.max_clean_fpr_upper,
        confidence=args.clean_fpr_confidence,
    )
    result = {
        "schema": "v6_threshold_selection",
        "created_utc": utc_now(),
        "selection_partition": "validation only",
        "selection_rule": (
            "maximize macro F1 across RNG-seed blocks subject to the exact "
            "one-sided seed-level upper confidence bound on P(a benign "
            "validation seed has any clean false positive); ties choose lower "
            "upper bound, lower "
            "empirical FPR, then higher threshold"
        ),
        "prediction_rule": (
            "window_peak_score > threshold, applied identically to malicious "
            "and non-malicious streams over the evaluation window "
            "W = [max(warmup, attack_start + onset_blank), sim_time]; pairs "
            "with no reception inside W are excluded from every arm"
        ),
        "endpoint_statistic": "window_peak_score",
        # The selection constraint and the reported clean_fpr are DIFFERENT
        # estimands and must not be conflated. The constraint below bounds the
        # probability that a fully benign run raises any false positive. The
        # clean_fpr column in the results table is a per-pair rate measured on
        # clean pairs inside ATTACK runs, where a receiver may simultaneously
        # hear an impersonator and the genuine owner. The bound does not
        # transfer to that number.
        "constraint_estimand": (
            "P(benign validation run has >=1 clean-pair false positive)"
        ),
        "reported_clean_fpr_estimand": (
            "per-clean-pair false-positive rate within attack runs"
        ),
        "threshold_grid": {
            "minimum": 0.0,
            "maximum": 1.0,
            "step": args.grid_step,
            "endpoints_included": True,
        },
        "clean_fpr_constraint": {
            "estimand": "P(a benign validation RNG seed has >=1 clean false positive)",
            "relation_to_pair_fpr": (
                "the seed any-FP indicator upper-bounds that seed's clean-pair "
                "FPR, so its population mean is a conservative proxy"
            ),
            "maximum_one_sided_upper": args.max_clean_fpr_upper,
            "confidence": args.clean_fpr_confidence,
            "method": "exact one-sided Clopper-Pearson binomial bound",
            "independence_unit": "RNG seed",
        },
        "validation_runs": len(summaries),
        "validation_pairs": len(scores),
        "configured_threshold_summary_recomputation": (
            "verified from pair crossing intervals/full-window peaks for every "
            "validation run before selection"
        ),
        "summary_sha256": sha256(args.summary),
        "pairs_sha256": sha256(args.pairs),
        **best_detail,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    atomic_text(args.output, json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        f"selected threshold {result['threshold']:.17g}: "
        f"macro-F1={result['validation_macro_f1']:.6f}, "
        f"clean FPR={result['validation_macro_clean_fpr']:.6f}, "
        f"one-sided upper={result['validation_clean_fpr_upper']:.6f}"
    )


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise


def atomic_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="raise")
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise


def load_threshold(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisError(f"cannot read threshold JSON {path}: {exc}") from exc
    if data.get("schema") != "v6_threshold_selection":
        raise AnalysisError(f"{path}: wrong threshold schema")
    value = data.get("threshold")
    if not isinstance(value, (int, float)) or not math.isfinite(value):
        raise AnalysisError(f"{path}: invalid threshold")
    if data.get("selection_partition") != "validation only":
        raise AnalysisError(f"{path}: threshold was not marked validation-only")
    # A v4 selection file describes a different endpoint; refusing it here is
    # what stops a stale threshold being silently reused against v5 counts.
    if data.get("endpoint_statistic") != "window_peak_score":
        raise AnalysisError(f"{path}: wrong crossing endpoint contract")
    grid_info = data.get("threshold_grid")
    if not isinstance(grid_info, dict):
        raise AnalysisError(f"{path}: missing deterministic threshold grid")
    try:
        step = float(grid_info["step"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AnalysisError(f"{path}: invalid threshold grid") from exc
    grid = deterministic_threshold_grid(step)
    if not np.any(np.isclose(grid, float(value), rtol=0.0, atol=1e-15)):
        raise AnalysisError(f"{path}: selected threshold is outside its declared grid")
    constraint = data.get("clean_fpr_constraint")
    if not isinstance(constraint, dict) or constraint.get("method") != (
        "exact one-sided Clopper-Pearson binomial bound"
    ):
        raise AnalysisError(f"{path}: missing exact seed-level clean-FP constraint")
    return data


def ratio(row: dict[str, str], numerator: str, denominator_fields: Sequence[str]) -> float:
    top = integer(row[numerator], f"{row['experiment_id']}/{numerator}")
    denominator = sum(
        integer(row[field], f"{row['experiment_id']}/{field}")
        for field in denominator_fields
    )
    return top / denominator if denominator else math.nan


def derived(row: dict[str, str], metric: str) -> float:
    if metric == "stream_tpr":
        return ratio(row, "stream_tp", ("stream_tp", "stream_fn"))
    if metric == "stream_fpr":
        return ratio(row, "stream_fp", ("stream_fp", "stream_tn"))
    if metric == "stream_precision":
        return ratio(row, "stream_tp", ("stream_tp", "stream_fp"))
    if metric == "stream_f1":
        return f1(
            integer(row["stream_tp"], "stream_tp"),
            integer(row["stream_fp"], "stream_fp"),
            integer(row["stream_fn"], "stream_fn"),
        )
    if metric == "owner_tpr":
        return ratio(row, "owner_tp", ("owner_tp", "owner_fn"))
    if metric == "owner_fpr":
        return ratio(row, "owner_fp", ("owner_fp", "owner_tn"))
    if metric == "owner_f1":
        return f1(
            integer(row["owner_tp"], "owner_tp"),
            integer(row["owner_fp"], "owner_fp"),
            integer(row["owner_fn"], "owner_fn"),
        )
    if metric == "contested_tpr":
        return ratio(row, "contested_tp", ("contested_tp", "contested_fn"))
    if metric == "contested_fpr":
        return ratio(row, "contested_fp", ("contested_fp", "contested_tn"))
    if metric == "contested_f1":
        return f1(
            integer(row["contested_tp"], "contested_tp"),
            integer(row["contested_fp"], "contested_fp"),
            integer(row["contested_fn"], "contested_fn"),
        )
    if metric == "clean_fpr":
        return ratio(row, "clean_fp", ("clean_fp", "clean_tn"))
    if metric == "latency_ms":
        n = integer(row["latency_n"], "latency_n")
        return finite(row["latency_sum_s"], "latency_sum_s") * 1000.0 / n if n else math.nan
    if metric == "pdr":
        n = integer(row["pdr_expected"], "pdr_expected")
        return integer(row["pdr_rx"], "pdr_rx") / n if n else math.nan
    if metric == "det_us":
        n = integer(row["det_calls"], "det_calls")
        return finite(row["det_nanos"], "det_nanos") / n / 1000.0 if n else math.nan
    if metric == "wall_duration_s":
        return finite(row["wall_duration_s"], "wall_duration_s")
    if metric == "victim_pair_post_onset_alert_rate":
        return ratio(row, "victim_pairs_alerted", ("victim_pairs",))
    if metric == "victim_id_post_onset_alert_rate":
        return ratio(row, "victim_ids_alerted", ("victim_ids",))
    # --- mitigation arm: evidence keyed by kinematic track ---------------
    # victim_pair_track_alert_rate is the headline: the share of impersonated
    # identities whose OWN trajectory is convicted. Compare it against
    # victim_pair_post_onset_alert_rate (identity keying) on the same runs.
    if metric == "victim_pair_track_alert_rate":
        return ratio(row, "victim_pairs_track_alerted", ("victim_pairs",))
    if metric == "victim_id_track_alert_rate":
        return ratio(row, "victim_ids_track_alerted", ("victim_ids",))
    if metric == "track_stream_tpr":
        return ratio(row, "track_stream_tp", ("track_stream_tp", "track_stream_fn"))
    if metric == "track_stream_fpr":
        return ratio(row, "track_stream_fp", ("track_stream_fp", "track_stream_tn"))
    if metric == "victim_pair_contested_rate":
        return ratio(row, "victim_pairs_contested", ("victim_pairs",))
    if metric == "victim_id_contested_rate":
        return ratio(row, "victim_ids_contested", ("victim_ids",))
    if metric == "malicious_opportunity_reception_rate":
        return ratio(
            row,
            "malicious_expected_pairs_observed",
            ("malicious_expected_pairs",),
        )
    if metric in {"stream_peak_auc", "owner_peak_auc", "ttd_detected_frac",
                  "stream_peak_pr_auc", "owner_peak_pr_auc",
                  "max_clean_score", "clean_margin",
                  "det_p50_us", "det_p95_us", "det_p99_us", "det_max_us",
                  "det_throughput_calls_per_s",
                  "peak_identity_keys_per_receiver",
                  "peak_live_tracks_per_receiver",
                  "estimated_state_payload_bytes_per_receiver"}:
        try:
            source = {
                "stream_peak_auc": "stream_auc",
                "owner_peak_auc": "owner_auc",
                "stream_peak_pr_auc": "stream_pr_auc",
                "owner_peak_pr_auc": "owner_pr_auc",
            }.get(metric, metric)
            value = float(row[source])
        except ValueError:
            return math.nan
        return value if math.isfinite(value) else math.nan
    raise AnalysisError(f"unknown metric {metric}")


def _labelled_seed(base_seed: int, label: str) -> int:
    digest = hashlib.sha256(f"{base_seed}:{label}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=False)


def interval(
    values: Sequence[float],
    bounded: bool,
    *,
    bootstrap_replicates: int = 0,
    bootstrap_seed: int = 0,
    label: str = "",
) -> tuple[int, float, float, float, float]:
    clean = np.asarray([v for v in values if math.isfinite(v)], dtype=float)
    n = len(clean)
    if not n:
        return 0, math.nan, math.nan, math.nan, math.nan
    mean = float(clean.mean())
    sd = float(clean.std(ddof=1)) if n > 1 else 0.0
    if n < 2:
        return n, mean, math.nan, math.nan, sd
    if bounded and bootstrap_replicates:
        if bootstrap_replicates < 1000:
            raise AnalysisError("seed-cluster bootstrap requires at least 1000 replicates")
        rng = np.random.default_rng(_labelled_seed(bootstrap_seed, label))
        draws = rng.integers(0, n, size=(bootstrap_replicates, n), endpoint=False)
        means = clean[draws].mean(axis=1)
        low, high = (float(value) for value in np.quantile(means, (0.025, 0.975)))
    else:
        half = float(stats.t.ppf(0.975, n - 1) * sd / math.sqrt(n))
        low, high = mean - half, mean + half
    if bounded:
        low, high = max(0.0, low), min(1.0, high)
    return n, mean, low, high, sd


def zero_upper(events: int, trials: int, alpha: float = 0.05) -> float:
    return 1.0 - alpha ** (1.0 / trials) if events == 0 and trials > 0 else math.nan


def metric_rows(
    summaries: Sequence[dict[str, str]],
    *,
    bootstrap_replicates: int,
    bootstrap_seed: int,
) -> list[dict]:
    metrics = (
        "stream_tpr",
        "stream_fpr",
        "stream_precision",
        "stream_f1",
        "owner_tpr",
        "owner_fpr",
        "owner_f1",
        "contested_tpr",
        "contested_fpr",
        "contested_f1",
        "clean_fpr",
        "victim_pair_post_onset_alert_rate",
        "victim_id_post_onset_alert_rate",
        # mitigation arm, same runs, same draws
        "victim_pair_track_alert_rate",
        "victim_id_track_alert_rate",
        "track_stream_tpr",
        "track_stream_fpr",
        "victim_pair_contested_rate",
        "victim_id_contested_rate",
        "malicious_opportunity_reception_rate",
        "stream_peak_auc",
        "owner_peak_auc",
        # PR-AUC is the honest companion under class imbalance; the clean
        # margin says how close the zero-FP result came to a false alarm.
        "stream_peak_pr_auc",
        "owner_peak_pr_auc",
        "max_clean_score",
        "clean_margin",
        # Cost is a tail property, not an average one.
        "det_p50_us",
        "det_p95_us",
        "det_p99_us",
        "det_max_us",
        "det_throughput_calls_per_s",
        "peak_identity_keys_per_receiver",
        "peak_live_tracks_per_receiver",
        "estimated_state_payload_bytes_per_receiver",
        "ttd_detected_frac",
        "latency_ms",
        "pdr",
        "det_us",
    )
    unbounded_metrics = {
        "latency_ms",
        "det_us",
        "det_p50_us",
        "det_p95_us",
        "det_p99_us",
        "det_max_us",
        "det_throughput_calls_per_s",
        "peak_identity_keys_per_receiver",
        "peak_live_tracks_per_receiver",
        "estimated_state_payload_bytes_per_receiver",
    }
    bounded_metrics = set(metrics) - unbounded_metrics
    groups: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in summaries:
        if row["stage"] == "test":
            groups[(row["stage"], row["family"], row["arm"])].append(row)
    output = []
    event_fields = {
        "stream_fpr": ("stream_fp", ("stream_fp", "stream_tn")),
        "owner_fpr": ("owner_fp", ("owner_fp", "owner_tn")),
        "contested_fpr": ("contested_fp", ("contested_fp", "contested_tn")),
        "clean_fpr": ("clean_fp", ("clean_fp", "clean_tn")),
    }
    for (stage, family, arm), rows in sorted(groups.items()):
        seeds = [integer(row["seed"], f"{row['experiment_id']}/seed") for row in rows]
        if len(seeds) != len(set(seeds)):
            raise AnalysisError(f"{family}/{arm}: repeated RNG seed within analysis arm")
        for metric in metrics:
            compute_metrics = {
                "det_us",
                "det_p50_us",
                "det_p95_us",
                "det_p99_us",
                "det_max_us",
                "det_throughput_calls_per_s",
            }
            if family == "serial_timing" and metric not in compute_metrics | {
                "latency_ms", "pdr",
            }:
                continue
            if metric in compute_metrics and not (
                family == "serial_timing" and arm == "detector_on"
            ):
                continue
            values = [derived(row, metric) for row in rows]
            bounded = metric in bounded_metrics
            n, mean, low, high, sd = interval(
                values,
                bounded,
                bootstrap_replicates=bootstrap_replicates if bounded else 0,
                bootstrap_seed=bootstrap_seed,
                label=f"metric:{stage}:{family}:{arm}:{metric}",
            )
            events = trials = 0
            upper = math.nan
            seed_events = seed_trials = 0
            if metric in event_fields:
                event_field, denominator_fields = event_fields[metric]
                events = sum(integer(row[event_field], event_field) for row in rows)
                trials = sum(
                    sum(integer(row[field], field) for field in denominator_fields)
                    for row in rows
                )
                for row in rows:
                    denominator = sum(
                        integer(row[field], field) for field in denominator_fields
                    )
                    if denominator:
                        seed_trials += 1
                        seed_events += integer(row[event_field], event_field) > 0
                # Pairs in one run are dependent.  The zero-event bound is
                # therefore over independent RNG seeds (probability a run has
                # any event), not a falsely precise pair-level binomial bound.
                upper = zero_upper(seed_events, seed_trials)
            output.append(
                {
                    "stage": stage,
                    "family": family,
                    "arm": arm,
                    "metric": metric,
                    "metric_n": n,
                    "mean": mean,
                    "ci95_low": low,
                    "ci95_high": high,
                    "sd": sd,
                    "event_count": events if metric in event_fields else "",
                    "trial_count": trials if metric in event_fields else "",
                    "zero_event_seed_events": seed_events
                    if metric in event_fields
                    else "",
                    "zero_event_seed_trials": seed_trials
                    if metric in event_fields
                    else "",
                    "zero_event_upper95": upper,
                    "zero_event_bound_unit": "RNG seed with any event"
                    if metric in event_fields
                    else "",
                    "ci_unit": "independent RNG seeds",
                    "ci_method": (
                        "percentile bootstrap resampling RNG seeds"
                        if bounded
                        else "Student-t over RNG seeds"
                    ),
                }
            )
    return output


def paired_rows(summaries: Sequence[dict[str, str]]) -> list[dict]:
    test = [row for row in summaries if row["stage"] == "test"]
    by_arm = defaultdict(dict)
    for row in test:
        by_arm[row["arm"]][integer(row["seed"], "seed")] = row
    mode = test[0]["mode"]
    reference_arm = "mixedhard_frac_0p3" if mode == "full" else "mixedhard_frac_0p5"
    comparisons = [
        ("timing_network_parity_on_minus_off", "detector_on", "detector_off",
         ("latency_ms", "pdr")),
        ("half_life1p351_minus_default3p431", "reference_half_life_1p351", reference_arm,
         ("stream_f1", "clean_fpr", "stream_peak_auc")),
        ("no_forgetting_minus_default3p431", "reference_no_forgetting", reference_arm,
         ("stream_f1", "clean_fpr", "stream_peak_auc")),
        ("actual4_assumed2_minus_matched", "actual_4_assumed_2", reference_arm,
         ("stream_f1", "clean_fpr", "stream_peak_auc")),
        ("actual8_assumed2_minus_matched", "actual_8_assumed_2", reference_arm,
         ("stream_f1", "clean_fpr", "stream_peak_auc")),
        ("actual2_assumed4_minus_matched", "actual_2_assumed_4", reference_arm,
         ("stream_f1", "clean_fpr", "stream_peak_auc")),
    ]
    # Onset-artifact isolation. Both arms share seeds and evaluate over the
    # identical window; the only difference is that the steady-state arm's
    # attackers are adversarial from their first transmitted message. A large
    # negative difference means the standard arm's apparent detection was the
    # onset discontinuity rather than the attack's steady-state signature.
    for attack in ("constoffset", "revheading", "slydos", "falsify"):
        comparisons.append(
            (
                f"steady_minus_onset_{attack}",
                f"pure_{attack}_steady",
                f"pure_{attack}",
                ("stream_tpr", "stream_f1", "stream_peak_auc"),
            )
        )
    output = []
    for label, left, right, metrics in comparisons:
        if left not in by_arm or right not in by_arm:
            raise AnalysisError(f"paired comparison missing arm: {left} or {right}")
        left_seeds, right_seeds = set(by_arm[left]), set(by_arm[right])
        if left_seeds != right_seeds:
            raise AnalysisError(
                f"paired comparison {label} has unmatched seeds: "
                f"{sorted(left_seeds ^ right_seeds)}"
            )
        for metric in metrics:
            diffs = []
            for seed in sorted(left_seeds):
                lv, rv = derived(by_arm[left][seed], metric), derived(by_arm[right][seed], metric)
                if math.isfinite(lv) and math.isfinite(rv):
                    diffs.append(lv - rv)
            bounded = False
            n, mean, low, high, sd = interval(diffs, bounded)
            output.append(
                {
                    "comparison": label,
                    "left_arm": left,
                    "right_arm": right,
                    "difference": "left-minus-right",
                    "metric": metric,
                    "metric_n": n,
                    "mean_difference": mean,
                    "ci95_low": low,
                    "ci95_high": high,
                    "sd_difference": sd,
                    "pairing_key": "RNG seed",
                }
            )
    return output


def curve_rows(arms: dict[tuple[str, str], PairArrays]) -> list[dict]:
    output = []
    for (family, arm), data in sorted(arms.items()):
        if not data.scores:
            continue
        code = np.frombuffer(data.run_codes, dtype=np.uint32)
        run_n = len(data.run_ids)
        targets = (
            (
                "malicious_stream",
                np.frombuffer(data.scores, dtype=np.float64),
                np.frombuffer(data.truth, dtype=np.uint8).astype(bool),
            ),
            (
                "attacker_owner",
                np.frombuffer(data.owner_scores, dtype=np.float64),
                np.frombuffer(data.owner_truth, dtype=np.uint8).astype(bool),
            ),
        )
        for target, score, truth in targets:
            p = np.bincount(code[truth], minlength=run_n)
            nneg = np.bincount(code[~truth], minlength=run_n)
            quantiles = np.quantile(score, np.linspace(0.0, 1.0, 101))
            thresholds = np.unique(
                np.concatenate(
                    (
                        [float(score.max())],
                        quantiles,
                        [math.nextafter(float(score.min()), -math.inf)],
                    )
                )
            )[::-1]
            for threshold in thresholds:
                pred = score > threshold
                tp = np.bincount(code[pred & truth], minlength=run_n)
                fp = np.bincount(code[pred & ~truth], minlength=run_n)
                tpr = np.divide(tp, p, out=np.full(run_n, np.nan), where=p > 0)
                fpr = np.divide(fp, nneg, out=np.full(run_n, np.nan), where=nneg > 0)
                precision = np.divide(
                    tp, tp + fp, out=np.full(run_n, np.nan), where=(tp + fp) > 0
                )
                valid_tpr = tpr[np.isfinite(tpr)]
                valid_fpr = fpr[np.isfinite(fpr)]
                valid_precision = precision[np.isfinite(precision)]
                nt, nf, np_ = len(valid_tpr), len(valid_fpr), len(valid_precision)
                mt = float(valid_tpr.mean()) if nt else math.nan
                mf = float(valid_fpr.mean()) if nf else math.nan
                mp = float(valid_precision.mean()) if np_ else math.nan
                output.append(
                    {
                        "family": family,
                        "arm": arm,
                        "truth_target": target,
                        "curve_semantics": (
                            "scalar peak-score discrimination; not the "
                            "post-onset crossing endpoint"
                        ),
                        "threshold": threshold,
                        "tpr": mt,
                        "tpr_metric_n": nt,
                        "fpr": mf,
                        "fpr_metric_n": nf,
                        "precision": mp,
                        "precision_metric_n": np_,
                        "cluster_unit": "RNG seed",
                        "uncertainty": "descriptive means; no pointwise confidence intervals",
                    }
                )
    return output


def km_rmst(times: np.ndarray, events: np.ndarray, tau: float) -> float:
    if not len(times) or tau < 0:
        return math.nan
    order = np.argsort(times, kind="stable")
    times, events = times[order], events[order]
    survival, area, previous = 1.0, 0.0, 0.0
    at_risk = len(times)
    i = 0
    while i < len(times) and previous < tau:
        when = min(float(times[i]), tau)
        area += survival * max(0.0, when - previous)
        if float(times[i]) > tau:
            previous = tau
            break
        j = i + 1
        while j < len(times) and times[j] == times[i]:
            j += 1
        deaths = int(events[i:j].sum())
        if at_risk:
            survival *= 1.0 - deaths / at_risk
        at_risk -= j - i
        previous = float(times[i])
        i = j
    if previous < tau:
        area += survival * (tau - previous)
    return area


def survival_rows(
    arms: dict[tuple[str, str], PairArrays],
    *,
    rmst_horizon: float,
    bootstrap_replicates: int,
    bootstrap_seed: int,
) -> list[dict]:
    output = []
    for (family, arm), data in sorted(arms.items()):
        if not data.survival_time:
            continue
        times = np.frombuffer(data.survival_time, dtype=np.float64)
        events = np.frombuffer(data.survival_event, dtype=np.uint8)
        codes = np.frombuffer(data.survival_run, dtype=np.uint32)
        tau = rmst_horizon
        rmst, fractions = [], []
        unsupported_runs = 0
        for run in np.unique(codes):
            mask = codes == run
            support = float(times[mask].max())
            at_support = mask & np.isclose(times, support, rtol=0.0, atol=1e-12)
            survival_reaches_zero = bool(np.all(events[at_support] == 1))
            if support + 1e-12 < tau and not survival_reaches_zero:
                unsupported_runs += 1
            else:
                rmst.append(km_rmst(times[mask], events[mask], tau))
            fractions.append(float(events[mask].mean()))
        nr, mr, lr, hr, _ = interval(rmst, False)
        nd, md, ld, hd, _ = interval(
            fractions,
            True,
            bootstrap_replicates=bootstrap_replicates,
            bootstrap_seed=bootstrap_seed,
            label=f"survival:{family}:{arm}:detected_fraction",
        )
        output.append(
            {
                "family": family,
                "arm": arm,
                "tau_s": tau,
                "rmst_s": mr,
                "rmst_ci95_low": lr,
                "rmst_ci95_high": hr,
                "rmst_metric_n": nr,
                "detected_fraction": md,
                "detected_fraction_ci95_low": ld,
                "detected_fraction_ci95_high": hd,
                "detected_fraction_metric_n": nd,
                "positive_pairs": len(times),
                "events": int(events.sum()),
                "censored": int(len(events) - events.sum()),
                "cluster_unit": "RNG seed",
                "rmst_horizon_rule": "common preregistered horizon",
                "rmst_unsupported_seed_runs": unsupported_runs,
                "rmst_support_requirement": (
                    "follow-up reaches tau or KM survival reaches zero; "
                    "otherwise seed RMST is undefined and excluded"
                ),
            }
        )
    return output


def report(args: argparse.Namespace) -> None:
    summaries = load_summary(args.summary)
    threshold_info = load_threshold(args.threshold_json)
    threshold = float(threshold_info["threshold"])
    for row in summaries:
        if row["stage"] == "test":
            actual = finite(row["threshold"], f"{row['experiment_id']}/threshold")
            if not math.isclose(actual, threshold, rel_tol=1e-9, abs_tol=1e-9):
                raise AnalysisError(
                    f"{row['experiment_id']}: test threshold {actual} was not frozen "
                    f"validation threshold {threshold}"
                )
    _, arms = scan_pairs(args.pairs, summaries, collect_by_arm=True)
    metrics = metric_rows(
        summaries,
        bootstrap_replicates=args.bootstrap_replicates,
        bootstrap_seed=args.bootstrap_seed,
    )
    paired = paired_rows(summaries)
    curves = curve_rows(arms)
    survival = survival_rows(
        arms,
        rmst_horizon=args.rmst_horizon,
        bootstrap_replicates=args.bootstrap_replicates,
        bootstrap_seed=args.bootstrap_seed,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    metric_fields = (
        "stage", "family", "arm", "metric", "metric_n", "mean", "ci95_low",
        "ci95_high", "sd", "event_count", "trial_count", "zero_event_upper95",
        "zero_event_seed_events", "zero_event_seed_trials",
        "zero_event_bound_unit", "ci_unit", "ci_method",
    )
    paired_fields = (
        "comparison", "left_arm", "right_arm", "difference", "metric", "metric_n",
        "mean_difference", "ci95_low", "ci95_high", "sd_difference", "pairing_key",
    )
    curve_fields = (
        "family", "arm", "truth_target", "curve_semantics", "threshold", "tpr",
        "tpr_metric_n", "fpr", "fpr_metric_n", "precision",
        "precision_metric_n", "cluster_unit", "uncertainty",
    )
    survival_fields = (
        "family", "arm", "tau_s", "rmst_s", "rmst_ci95_low", "rmst_ci95_high",
        "rmst_metric_n", "detected_fraction", "detected_fraction_ci95_low",
        "detected_fraction_ci95_high", "detected_fraction_metric_n",
        "positive_pairs", "events", "censored", "cluster_unit", "rmst_horizon_rule",
        "rmst_unsupported_seed_runs", "rmst_support_requirement",
    )
    atomic_csv(args.output_dir / "metrics_v4.csv", metric_fields, metrics)
    atomic_csv(args.output_dir / "paired_differences_v4.csv", paired_fields, paired)
    atomic_csv(
        args.output_dir / "peak_score_discrimination_v4.csv", curve_fields, curves
    )
    atomic_csv(args.output_dir / "survival_v4.csv", survival_fields, survival)
    mode = summaries[0]["mode"]
    key_metrics = [
        row for row in metrics
        if row["metric"] in {
            "stream_f1",
            "clean_fpr",
            "owner_f1",
            "contested_f1",
            "malicious_opportunity_reception_rate",
        }
    ]
    lines = [
        "# v4 experiment report",
        "",
        f"- Mode: **{mode}**"
        + (" — pipeline check only; not publication evidence." if mode == "smoke" else ""),
        f"- Runs: {len(summaries)} ({sum(r['stage'] == 'validation' for r in summaries)} validation, "
        f"{sum(r['stage'] == 'test' for r in summaries)} frozen-threshold test)",
        f"- Frozen threshold: `{threshold:.17g}`",
        "- Endpoint: `window_peak_score > threshold`, applied identically to "
        "malicious and non-malicious streams over the evaluation window "
        "W = [max(warmup, attack_start + onset_blank), sim_time]. Pairs with "
        "no reception inside W are excluded from every arm rather than "
        "counted as true negatives.",
        "- Endpoint audit: every pair row was checked to satisfy "
        "`window_alert == (window_peak_score > threshold)`; timing arms "
        "suppress pair output by design.",
        "- Because the ROC curve ranks the same statistic the operating point "
        "thresholds, the reported (FPR, TPR) point lies on the reported curve "
        "by construction.",
        "- Victim framing uses the same window and rule as every other "
        "decision; pre-onset excursions are excluded by W, not by a "
        "label-dependent rule.",
        "- Selection constraint and reported clean FPR are different "
        "estimands: the frozen threshold bounds P(a benign run raises any "
        "false positive), while `clean_fpr` is a per-pair rate inside attack "
        "runs. The bound does not transfer to that column.",
        "- Bounded primary metrics: two-sided 95% percentile intervals from "
        f"{args.bootstrap_replicates} deterministic RNG-seed-block bootstrap replicates.",
        "- Other scalar metrics: two-sided 95% Student-t intervals over RNG seeds.",
        "- Time to detection: Kaplan–Meier restricted mean with explicit right "
        f"censoring and one common preregistered horizon of {args.rmst_horizon:g} s.",
        "- Detection-time survival is conditional on at least one valid malicious "
        "reception; malicious opportunity reception is reported separately.",
        "- Seed RMST is undefined (not extrapolated) when follow-up ends before "
        "the common horizon while estimated survival remains above zero.",
        "- ROC/PR table: scalar peak-score discrimination only; it is not the "
        "post-onset crossing-rule endpoint. Curves are descriptive seed means "
        "without pointwise confidence intervals.",
        "- Compute cost: simulator-instrumented `det_us` from serial detector-on "
        "runs only. Whole-process "
        "wall durations remain manifest diagnostics and are not interpreted as "
        "detector overhead because detector-on performs additional evaluation bookkeeping.",
        "- Zero false-event groups include an exact one-sided 95% bound on the "
        "probability that an independent RNG run has any event (not a pair-level FPR bound).",
        "",
        "## Key arm-level metrics",
        "",
        "| family | arm | metric | n | mean | 95% CI |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for row in key_metrics:
        lines.append(
            f"| {row['family']} | {row['arm']} | {row['metric']} | "
            f"{row['metric_n']} | {row['mean']:.6g} | "
            f"[{row['ci95_low']:.6g}, {row['ci95_high']:.6g}] |"
        )
    lines += [
        "",
        "Machine-readable tables: `metrics_v4.csv`, `paired_differences_v4.csv`, "
        "`peak_score_discrimination_v4.csv`, and `survival_v4.csv`.",
        "",
    ]
    atomic_text(args.output_dir / "report_v4.md", "\n".join(lines))
    print(
        f"validated {len(summaries)} runs; wrote {len(metrics)} metrics, "
        f"{len(paired)} paired estimates, {len(curves)} peak-score curve points, and "
        f"{len(survival)} survival rows to {args.output_dir}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    select = sub.add_parser("select-threshold")
    select.add_argument("--summary", type=Path, required=True)
    select.add_argument("--pairs", type=Path, required=True)
    select.add_argument("--output", type=Path, required=True)
    select.add_argument("--grid-step", type=float, default=0.001)
    select.add_argument("--max-clean-fpr-upper", type=float, default=0.01)
    select.add_argument("--clean-fpr-confidence", type=float, default=0.95)
    show = sub.add_parser("show-threshold")
    show.add_argument("--input", type=Path, required=True)
    analyze = sub.add_parser("report")
    analyze.add_argument("--summary", type=Path, required=True)
    analyze.add_argument("--pairs", type=Path, required=True)
    analyze.add_argument("--threshold-json", type=Path, required=True)
    analyze.add_argument("--output-dir", type=Path, required=True)
    analyze.add_argument("--bootstrap-replicates", type=int, default=5000)
    analyze.add_argument("--bootstrap-seed", type=int, default=20260731)
    analyze.add_argument("--rmst-horizon", type=float, default=20.0)
    args = parser.parse_args()
    try:
        if args.command == "select-threshold":
            if not 0.0 <= args.max_clean_fpr_upper <= 1.0:
                raise AnalysisError("--max-clean-fpr-upper must be in [0,1]")
            if not 0.5 < args.clean_fpr_confidence < 1.0:
                raise AnalysisError("--clean-fpr-confidence must be in (0.5,1)")
            select_threshold(args)
        elif args.command == "show-threshold":
            print(f"{float(load_threshold(args.input)['threshold']):.17g}")
        elif args.command == "report":
            if args.bootstrap_replicates < 1000:
                raise AnalysisError("--bootstrap-replicates must be at least 1000")
            if not math.isfinite(args.rmst_horizon) or args.rmst_horizon <= 0.0:
                raise AnalysisError("--rmst-horizon must be finite and positive")
            report(args)
    except AnalysisError as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
