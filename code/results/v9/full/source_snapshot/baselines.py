#!/usr/bin/env python3
"""Replay transparent detector structures over attribution-safe v6 traces.

The rules here are deliberately described by structure, not by the names of
published detectors: range, sudden appearance, majority of plausibility
checks, a sequential decision score, and an identity-contested rule that
fires when one claimed identity arrives from multiple receiver-observed IPv4
sources. The comparison also includes a supervised logistic regression over
the seven pair-level check-fire rates. Its feature definition, scaling,
coefficients and threshold are fitted only on validation traces and serialized
before held-out replay. Each rule is replayed with state
keyed both by the claimed identity (deployable) and by the oracle physical
source (evaluation-only upper-bound diagnostic).

Message truth is read *only* from ``oracle_message_is_malicious``.  Assigned
attacker membership is retained for owner/source attribution, but is never
used as a substitute for message-level maliciousness.  Likewise,
``oracle_attack_active`` is required so pre-attack messages from an assigned
attacker remain honest history.

Every tunable setting is selected on validation traces and serialized with
trace hashes before a held-out test trace can be evaluated. There are no
shipped fitted coefficients or test-tuned thresholds. Each rule then applies
one frozen threshold to its peak signal over the simulator-declared evaluation
window, identically for positive and negative pairs.

Uncertainty is computed by resampling unique RNG-seed blocks.  All attack arms
sharing a seed move together; trace files are never treated as independent
replicates.  Results are also reported by attack stratum, and claimed-minus-
oracle contrasts are paired within the same run before seed-block resampling.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import numpy as np
from scipy.stats import beta as beta_distribution


ROOT = Path(__file__).resolve().parent

# These are evidence tables, not calibrated conditional probabilities.
CHECK_MODELS = {
    "reference": {
        "position": (0.85, 0.02),
        "speed": (0.70, 0.05),
        "stale": (0.40, 0.03),
        "replay": (0.90, 0.01),
        "rate": (0.95, 0.01),
        "map": (0.60, 0.005),
        "heading": (0.75, 0.04),
    },
    "simfit": {
        "position": (0.0160, 0.0003),
        "speed": (0.0165, 0.0004),
        "stale": (0.0612, 0.00005),
        "replay": (0.0399, 0.0040),
        "rate": (0.5500, 0.0023),
        "map": (0.0011, 0.00005),
        "heading": (0.0260, 0.0002),
    },
}
CHECK_FEATURES = tuple(CHECK_MODELS["reference"])

DETECTORS = (
    "range",
    "sudden-appearance",
    "two-of-seven",
    "sequential-score",
    "identity-contested",
    # Established fusion rules, added so the sequential accumulator is
    # compared against real alternatives rather than only against a
    # memoryless majority vote. All five see the identical check outputs on
    # the identical traces at the identical evaluation window; only the
    # combination rule differs, so any difference is attributable to fusion.
    "weighted-sum",     # instantaneous, weights but no memory
    "naive-bayes",      # textbook: non-firing checks contribute negatively
    "ewma",             # exponentially weighted fired-check count
    "logistic-regression",  # validation-trained seven-check-rate model
)

# Only the prespecified held-out attack arms and the matched benign population
# enter headline pooling.  Constant-offset steady/onset guards and every other
# stress/sensitivity family remain visible as secondary controls, but cannot
# overweight one attack in the primary comparison.
HEADLINE_FAMILIES = frozenset({"pure_attack", "benign"})
ORACLE_ASSISTED_STRUCTURAL_BOUNDS = frozenset({"range", "sudden-appearance"})

BASELINE_ARTIFACT_SCHEMA = "v2_baseline_parameters"
EWMA_ALPHA_CANDIDATES = (0.10, 0.20, 0.30, 0.50)
DEFAULT_CLEAN_SEED_CONFIDENCE = 0.95
DEFAULT_MAX_CLEAN_SEED_UPPER = 0.01
METRICS = (
    "stream_tpr",
    "clean_fpr",
    "owner_tpr",
    "owner_fpr",
    "victim_pair_rate",
    "victim_unique_rate",
    "precision",
    "recall",
    "f1",
    "false_positive_count",
    "roc_auc",
    "pr_auc",
    "median_detection_delay_s",
    "censored_fraction",
)


class TraceSchemaError(ValueError):
    """The input cannot support an attribution-safe v6 comparison."""


def parse_bool(value: str) -> bool:
    value = value.strip().lower()
    if value in {"1", "true", "yes", "y"}:
        return True
    if value in {"0", "false", "no", "n"}:
        return False
    raise TraceSchemaError(f"expected boolean field, got {value!r}")


def choose(fields: set[str], *names: str, required: bool = True) -> str | None:
    for name in names:
        if name in fields:
            return name
    if required:
        raise TraceSchemaError(
            "trace is missing one of the required columns: " + ", ".join(names)
        )
    return None


@dataclass(frozen=True)
class Schema:
    rx: str
    now: str
    claimed: str
    seq: str
    tx: str
    x: str
    y: str
    vx: str
    vy: str
    rx_x: str
    rx_y: str
    observable_source: str
    source: str
    source_attacker: str
    assigned_role: str
    owner_attacker: str
    attack_active: str
    message_malicious: str
    victim_id: str
    expected_receiver: str

    @classmethod
    def from_fields(cls, names: Iterable[str]) -> "Schema":
        fields = set(names)
        return cls(
            rx=choose(fields, "receiver_id"),
            now=choose(fields, "rx_time"),
            claimed=choose(fields, "claimed_id"),
            seq=choose(fields, "claimed_seq"),
            tx=choose(fields, "claimed_tx_time"),
            x=choose(fields, "claimed_x"),
            y=choose(fields, "claimed_y"),
            vx=choose(fields, "claimed_vx"),
            vy=choose(fields, "claimed_vy"),
            rx_x=choose(fields, "receiver_true_x"),
            rx_y=choose(fields, "receiver_true_y"),
            observable_source=choose(fields, "observable_source_ipv4"),
            source=choose(fields, "oracle_source_id"),
            source_attacker=choose(fields, "oracle_source_is_attacker"),
            assigned_role=choose(fields, "oracle_assigned_role"),
            owner_attacker=choose(fields, "oracle_owner_is_attacker"),
            attack_active=choose(fields, "oracle_attack_active"),
            message_malicious=choose(fields, "oracle_message_is_malicious"),
            victim_id=choose(fields, "oracle_victim_id"),
            expected_receiver=choose(fields, "oracle_expected_receiver"),
        )


@dataclass(frozen=True)
class RunMeta:
    path: Path
    run_id: str
    seed: int
    attack: str
    partition: str
    family: str
    arm: str
    summary: dict[str, str]


@dataclass
class State:
    have: bool = False
    last_tx: float = 0.0
    seen: set[int] = field(default_factory=set)
    seen_fifo: deque[int] = field(default_factory=deque)
    rx_times: deque[float] = field(default_factory=deque)
    ref_valid: bool = False
    ref_x: float = 0.0
    ref_y: float = 0.0
    ref_t: float = 0.0
    score: float = 0.0
    last_score_time: float | None = None
    nb_score: float = 0.0        # naive-Bayes accumulator (scores non-firing)
    ewma: float = 0.0            # EWMA of the fired-check count
    ewma_candidates: dict[float, float] = field(
        default_factory=lambda: {alpha: 0.0 for alpha in EWMA_ALPHA_CANDIDATES}
    )
    peak_ewma_candidates: dict[float, float] = field(
        default_factory=lambda: {
            alpha: -math.inf for alpha in EWMA_ALPHA_CANDIDATES
        }
    )
    warm_reset: bool = False
    first: bool = True
    window_first: bool = True
    window_messages: int = 0
    check_fire_counts: dict[str, int] = field(
        default_factory=lambda: {name: 0 for name in CHECK_FEATURES}
    )
    peak_signals: dict[str, float] = field(
        default_factory=lambda: {name: -math.inf for name in DETECTORS}
    )
    messages: int = 0
    malicious_stream: bool = False
    first_attack_active_time: float | None = None
    first_malicious_time: float | None = None
    evaluation_start: float = 0.0
    first_stream_alert_time: dict[str, float | None] = field(
        default_factory=lambda: {name: None for name in DETECTORS}
    )
    owner_attacker: bool | None = None
    source_ids: set[int] = field(default_factory=set)
    claimed_ids: set[int] = field(default_factory=set)
    observable_sources: set[str] = field(default_factory=set)
    current_alerts: dict[str, bool] = field(
        default_factory=lambda: {name: False for name in DETECTORS}
    )
    ever_alerts: dict[str, bool] = field(
        default_factory=lambda: {name: False for name in DETECTORS}
    )
    stream_alerts: dict[str, bool] = field(
        default_factory=lambda: {name: False for name in DETECTORS}
    )
    preexisting_alerts: dict[str, bool] = field(
        default_factory=lambda: {name: False for name in DETECTORS}
    )


@dataclass(frozen=True)
class Observation:
    rx: int
    now: float
    claimed: int
    source: int
    source_attacker: bool
    owner_attacker: bool
    attack_active: bool
    message_malicious: bool
    seq: int
    tx: float
    x: float
    y: float
    vx: float
    vy: float
    rx_x: float
    rx_y: float
    observable_source: str


@dataclass(frozen=True)
class MetricRecord:
    seed: int
    attack: str
    run_id: str
    family: str
    arm: str
    mode: str
    detector: str
    values: dict[str, float]


def safe_float(row: dict[str, str], name: str) -> float:
    value = float(row[name])
    if not math.isfinite(value):
        raise TraceSchemaError(f"non-finite value in column {name}")
    return value


def provisional_logistic_model() -> dict[str, object]:
    """Neutral initialization used only before validation fitting."""
    return {
        "feature_names": list(CHECK_FEATURES),
        "feature_definition": (
            "cumulative fraction of pair receptions in the shared evaluation "
            "window for which each plausibility check fired"
        ),
        "scaling_mean": [0.0] * len(CHECK_FEATURES),
        "scaling_scale": [1.0] * len(CHECK_FEATURES),
        "coefficients": [0.0] * len(CHECK_FEATURES),
        "intercept": 0.0,
        "threshold": 0.5,
        "l2_penalty": 1.0,
        "optimizer": "Newton-Raphson on validation pairs",
    }


def logistic_feature_vector(state: State) -> np.ndarray:
    denominator = max(1, state.window_messages)
    return np.asarray(
        [state.check_fire_counts[name] / denominator for name in CHECK_FEATURES],
        dtype=np.float64,
    )


def logistic_probability(state: State, model: dict[str, object]) -> float:
    values = logistic_feature_vector(state)
    mean = np.asarray(model["scaling_mean"], dtype=np.float64)
    scale = np.asarray(model["scaling_scale"], dtype=np.float64)
    coefficients = np.asarray(model["coefficients"], dtype=np.float64)
    linear = float(model["intercept"]) + float(
        np.dot((values - mean) / scale, coefficients)
    )
    if linear >= 0.0:
        return 1.0 / (1.0 + math.exp(-linear))
    exponential = math.exp(linear)
    return exponential / (1.0 + exponential)


def read_schema(path: Path) -> Schema:
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise TraceSchemaError(f"{path}: empty trace or missing CSV header")
        return Schema.from_fields(reader.fieldnames)


def run_metadata(path: Path) -> RunMeta:
    """Read and retain the exact v6 simulator configuration beside a trace."""
    summary_path = path.parent / "summary.csv"
    if not summary_path.is_file():
        raise TraceSchemaError(
            f"{path}: v6 baseline replay requires the adjacent one-row "
            f"{summary_path.name} so replay parameters cannot drift"
        )
    with summary_path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 1:
        raise TraceSchemaError(f"{summary_path}: expected exactly one data row")
    row = rows[0]
    required = {
        "schema", "run", "attack", "detector", "score_model", "threshold",
        "prior", "warmup", "comm_range", "detector_gps_sigma", "spd_sigma",
        "decay_half_life_s", "null_ev", "naive_th", "eval_window_start_s",
    }
    missing = required.difference(row)
    if missing:
        raise TraceSchemaError(f"{summary_path}: missing {sorted(missing)}")
    if row["schema"] != "v6":
        raise TraceSchemaError(f"{summary_path}: expected schema v6")
    try:
        seed = int(row["run"])
    except ValueError as exc:
        raise TraceSchemaError(f"{summary_path}: invalid RNG run") from exc
    attack = row["attack"].strip()
    if not attack:
        raise TraceSchemaError(f"{summary_path}: attack stratum is empty")
    run_id = path.parent.name
    if "__" not in run_id:
        raise TraceSchemaError(
            f"{path}: run directory must begin with the plan partition"
        )
    pieces = run_id.split("__")
    if len(pieces) != 4 or not pieces[3].startswith("seed_"):
        raise TraceSchemaError(
            f"{path}: run directory must encode stage/family/arm/replicate"
        )
    partition, family, arm, encoded_seed = pieces
    if not family or not arm:
        raise TraceSchemaError(f"{path}: empty plan family/arm in run directory")
    try:
        directory_seed = int(encoded_seed.removeprefix("seed_"))
    except ValueError as exc:
        raise TraceSchemaError(f"{path}: invalid encoded seed") from exc
    if directory_seed != seed:
        raise TraceSchemaError(f"{path}: directory seed differs from summary run")
    return RunMeta(path, run_id, seed, attack, partition, family, arm, row)


def verify_replay_config(
    meta: RunMeta, args: argparse.Namespace, expected_partition: str
) -> float:
    """Fail closed when offline detector settings differ from the simulator."""

    row = meta.summary
    if meta.partition != expected_partition:
        raise TraceSchemaError(
            f"{meta.path}: expected {expected_partition!r} traces, not "
            f"partition {meta.partition!r}"
        )
    exact = {
        "detector": "1",
        "score_model": args.score_model,
        "null_ev": "0",
        "naive_th": "0",
    }
    for field, expected in exact.items():
        if row[field] != expected:
            raise TraceSchemaError(
                f"{meta.path}: summary {field}={row[field]!r}, expected {expected!r}"
            )
    numeric = {
        "prior": args.prior,
        "comm_range": args.comm_range,
        "detector_gps_sigma": args.detector_gps_sigma,
        "spd_sigma": args.speed_sigma,
        "decay_half_life_s": args.decay_half_life,
    }
    if expected_partition == "test":
        numeric["threshold"] = args.score_threshold
    for field, expected in numeric.items():
        try:
            actual = float(row[field])
        except ValueError as exc:
            raise TraceSchemaError(
                f"{meta.path}: summary {field} is not numeric"
            ) from exc
        if not math.isfinite(actual) or not math.isclose(
            actual, expected, rel_tol=1e-9, abs_tol=1e-9
        ):
            raise TraceSchemaError(
                f"{meta.path}: replay {field}={expected:g} differs from "
                f"simulator value {actual:g}"
            )
    # Warm-up is deliberately NOT matched against a single global argument: the
    # steady-state arms run warmup=10 so attackers have a genuine pre-attack
    # history, while the mid-stream arms run 5. Replaying either with the wrong
    # warm-up would measure over a different window than the detector did, so
    # the value is taken from the run itself and returned to the replay.
    try:
        eval_start = float(row["eval_window_start_s"])
        run_warmup = float(row["warmup"])
    except ValueError as exc:
        raise TraceSchemaError(
            f"{meta.path}: invalid eval_window_start_s or warmup"
        ) from exc
    if not math.isfinite(run_warmup) or run_warmup < 0.0:
        raise TraceSchemaError(f"{meta.path}: invalid warmup {run_warmup!r}")
    if not math.isfinite(eval_start) or eval_start < run_warmup:
        raise TraceSchemaError(
            f"{meta.path}: invalid evaluation-window start {eval_start!r}"
        )
    return eval_start, run_warmup


def observations(path: Path, schema: Schema) -> Iterable[Observation]:
    last_now = -math.inf
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for row_no, row in enumerate(reader, start=2):
            try:
                now = safe_float(row, schema.now)
                attack_active = parse_bool(row[schema.attack_active])
                malicious = parse_bool(row[schema.message_malicious])
                if now + 1e-12 < last_now:
                    raise TraceSchemaError("reception times are not monotone")
                if malicious and not attack_active:
                    raise TraceSchemaError(
                        "malicious message is labelled outside the active attack period"
                    )
                last_now = now
                observable_source = row[schema.observable_source].strip()
                if not observable_source:
                    raise TraceSchemaError("observable source address is empty")
                assigned_role = row[schema.assigned_role].strip()
                if not assigned_role:
                    raise TraceSchemaError("oracle assigned role is empty")
                int(row[schema.victim_id])
                parse_bool(row[schema.expected_receiver])
                yield Observation(
                    rx=int(row[schema.rx]),
                    now=now,
                    claimed=int(row[schema.claimed]),
                    source=int(row[schema.source]),
                    source_attacker=parse_bool(row[schema.source_attacker]),
                    owner_attacker=parse_bool(row[schema.owner_attacker]),
                    attack_active=attack_active,
                    message_malicious=malicious,
                    seq=int(row[schema.seq]),
                    tx=safe_float(row, schema.tx),
                    x=safe_float(row, schema.x),
                    y=safe_float(row, schema.y),
                    vx=safe_float(row, schema.vx),
                    vy=safe_float(row, schema.vy),
                    rx_x=safe_float(row, schema.rx_x),
                    rx_y=safe_float(row, schema.rx_y),
                    observable_source=observable_source,
                )
            except TraceSchemaError as exc:
                raise TraceSchemaError(f"{path}:{row_no}: {exc}") from exc
            except (KeyError, TypeError, ValueError) as exc:
                raise TraceSchemaError(f"{path}:{row_no}: {exc}") from exc


def reset_measurement_state(state: State, prior_score: float) -> None:
    """Match the simulator's warm-up score reset without erasing history."""
    state.score = prior_score
    # The added fusion arms carry their own accumulators; reset them on the
    # same boundary or they would enter the measurement window warm.
    state.nb_score = prior_score
    state.ewma = 0.0
    state.ewma_candidates = {alpha: 0.0 for alpha in EWMA_ALPHA_CANDIDATES}
    state.peak_ewma_candidates = {
        alpha: -math.inf for alpha in EWMA_ALPHA_CANDIDATES
    }
    state.current_alerts = {name: False for name in DETECTORS}
    state.ever_alerts = {name: False for name in DETECTORS}
    state.stream_alerts = {name: False for name in DETECTORS}
    state.preexisting_alerts = {name: False for name in DETECTORS}
    state.first_stream_alert_time = {name: None for name in DETECTORS}
    state.messages = 0
    state.window_messages = 0
    state.check_fire_counts = {name: 0 for name in CHECK_FEATURES}
    state.window_first = True
    state.peak_signals = {name: -math.inf for name in DETECTORS}
    state.malicious_stream = False
    state.first_attack_active_time = None
    state.first_malicious_time = None
    state.source_ids.clear()
    state.claimed_ids.clear()
    state.observable_sources.clear()
    state.warm_reset = True


def update_state(
    state: State,
    obs: Observation,
    args: argparse.Namespace,
    eval_start: float,
    warmup: float,
) -> None:
    state.evaluation_start = eval_start
    prior_score = math.log(args.prior / (1.0 - args.prior))
    if obs.now >= warmup and not state.warm_reset:
        reset_measurement_state(state, prior_score)

    measured = obs.now >= warmup
    in_window = obs.now >= eval_start
    if in_window:
        state.messages += 1
        if obs.attack_active and state.first_attack_active_time is None:
            state.first_attack_active_time = obs.now
        malicious_onset = (
            obs.message_malicious and state.first_malicious_time is None
        )
        if malicious_onset:
            state.first_malicious_time = obs.now
        state.malicious_stream |= obs.message_malicious
        state.source_ids.add(obs.source)
        state.claimed_ids.add(obs.claimed)
    else:
        malicious_onset = False

    previous_alerts = dict(state.current_alerts)
    current_alerts = {name: False for name in DETECTORS}
    distance = math.hypot(obs.x - obs.rx_x, obs.y - obs.rx_y)
    params = args.baseline_parameters
    current_alerts["range"] = distance > params["range_threshold_m"]
    actual_first_appearance = state.first
    current_alerts["sudden-appearance"] = (
        actual_first_appearance and distance < params["sudden_range_m"]
    )
    state.first = False

    fired = {name: False for name in CHECK_MODELS[args.score_model]}
    fired["stale"] = (obs.now - obs.tx) > args.max_age
    if state.have:
        fired["replay"] = obs.seq in state.seen or obs.tx <= state.last_tx

    if state.ref_valid:
        dt = obs.tx - state.ref_t
        if dt >= args.min_ref_dt:
            dx, dy = obs.x - state.ref_x, obs.y - state.ref_y
            displacement = math.hypot(dx, dy)
            sensor_speed_sigma = math.sqrt(2.0) * args.detector_gps_sigma / dt
            implied = displacement / dt
            asserted = math.hypot(obs.vx, obs.vy)
            fired["position"] = implied > args.vmax + 3.0 * sensor_speed_sigma
            fired["speed"] = abs(implied - asserted) > (
                args.speed_tolerance
                + 3.0 * math.hypot(sensor_speed_sigma, args.speed_sigma)
            )
            if displacement > 3.0 * args.detector_gps_sigma and asserted > 1.0:
                cosine = (dx * obs.vx + dy * obs.vy) / (
                    displacement * asserted
                )
                fired["heading"] = cosine < args.heading_cos_min
            state.ref_x, state.ref_y, state.ref_t = obs.x, obs.y, obs.tx
    else:
        state.ref_valid = True
        state.ref_x, state.ref_y, state.ref_t = obs.x, obs.y, obs.tx

    state.rx_times.append(obs.now)
    while state.rx_times and state.rx_times[0] < obs.now - args.rate_window:
        state.rx_times.popleft()
    fired["rate"] = len(state.rx_times) / args.rate_window > args.rate_limit
    fired["map"] = (
        obs.x < -50.0
        or obs.x > args.road_length + 50.0
        or abs(obs.y) > args.road_width
    )

    fired_count = sum(fired.values())
    current_alerts["two-of-seven"] = (
        fired_count >= int(params["votes_required"])
    )
    state.observable_sources.add(obs.observable_source)
    current_alerts["identity-contested"] = (
        len(state.observable_sources) > params["identity_contested_threshold"]
    )

    if state.last_score_time is None or args.decay_half_life < 0.0:
        retention = 1.0
    else:
        elapsed = max(0.0, obs.now - state.last_score_time)
        retention = math.exp(-math.log(2.0) * elapsed / args.decay_half_life)
    state.score = (
        retention
        * max(-args.score_clamp, min(args.score_clamp, state.score))
        + (1.0 - retention) * prior_score
    )
    for check, active in fired.items():
        if active:
            d_rate, fa_rate = CHECK_MODELS[args.score_model][check]
            state.score += math.log(d_rate / fa_rate)
    state.score = max(-args.score_clamp, min(args.score_clamp, state.score))
    state.last_score_time = obs.now
    bounded_score = 1.0 / (1.0 + math.exp(-state.score))
    current_alerts["sequential-score"] = bounded_score > args.score_threshold

    # --- weighted sum: same weights, no memory -------------------------
    instant = sum(
        math.log(CHECK_MODELS[args.score_model][c][0]
                 / CHECK_MODELS[args.score_model][c][1])
        for c, active in fired.items() if active
    )
    current_alerts["weighted-sum"] = instant > params["weighted_sum_threshold"]

    # --- naive Bayes: non-firing checks contribute negative evidence ----
    # This is the textbook update the paper argues against. Reporting it as a
    # baseline shows the cost of that choice instead of only asserting it.
    state.nb_score = (
        retention * max(-args.score_clamp, min(args.score_clamp, state.nb_score))
        + (1.0 - retention) * prior_score
    )
    for check, active in fired.items():
        d_rate, fa_rate = CHECK_MODELS[args.score_model][check]
        state.nb_score += (
            math.log(d_rate / fa_rate) if active
            else math.log((1.0 - d_rate) / (1.0 - fa_rate))
        )
    state.nb_score = max(-args.score_clamp, min(args.score_clamp, state.nb_score))
    bounded_nb = 1.0 / (1.0 + math.exp(-state.nb_score))
    current_alerts["naive-bayes"] = (
        bounded_nb > params["naive_bayes_score_threshold"]
    )

    # --- EWMA of fired-check count: memory, no weighting ----------------
    for alpha in EWMA_ALPHA_CANDIDATES:
        state.ewma_candidates[alpha] = (
            (1.0 - alpha) * state.ewma_candidates[alpha] + alpha * fired_count
        )
        if in_window:
            state.peak_ewma_candidates[alpha] = max(
                state.peak_ewma_candidates[alpha], state.ewma_candidates[alpha]
            )
    ewma_alpha = float(params["ewma_alpha"])
    state.ewma = state.ewma_candidates[ewma_alpha]
    current_alerts["ewma"] = state.ewma > params["ewma_threshold"]

    if in_window:
        state.window_messages += 1
        for check, active in fired.items():
            state.check_fire_counts[check] += int(active)
        state.peak_signals["range"] = max(
            state.peak_signals["range"], distance
        )
        if actual_first_appearance:
            # Higher signal means more suspicious for every detector. Negating
            # distance turns "appeared closer than r" into signal > -r.
            state.peak_signals["sudden-appearance"] = -distance
            current_alerts["sudden-appearance"] = (
                -distance > detector_threshold("sudden-appearance", args)
            )
        state.peak_signals["two-of-seven"] = max(
            state.peak_signals["two-of-seven"], float(fired_count)
        )
        state.peak_signals["sequential-score"] = max(
            state.peak_signals["sequential-score"], bounded_score
        )
        state.peak_signals["identity-contested"] = max(
            state.peak_signals["identity-contested"],
            float(len(state.observable_sources)),
        )
        state.peak_signals["weighted-sum"] = max(
            state.peak_signals["weighted-sum"], instant
        )
        state.peak_signals["naive-bayes"] = max(
            state.peak_signals["naive-bayes"], bounded_nb
        )
        state.peak_signals["ewma"] = state.peak_ewma_candidates[ewma_alpha]
        logistic_signal = logistic_probability(state, args.logistic_model)
        state.peak_signals["logistic-regression"] = max(
            state.peak_signals["logistic-regression"], logistic_signal
        )
        current_alerts["logistic-regression"] = (
            logistic_signal > float(args.logistic_model["threshold"])
        )

    if measured:
        for detector in DETECTORS:
            current = current_alerts[detector]
            previous = previous_alerts[detector]
            if malicious_onset and previous:
                state.preexisting_alerts[detector] = True
            if current:
                state.ever_alerts[detector] = True
            if (
                current
                and state.first_malicious_time is not None
                and obs.now >= max(eval_start, state.first_malicious_time)
            ):
                state.stream_alerts[detector] = True
                if state.first_stream_alert_time[detector] is None:
                    state.first_stream_alert_time[detector] = obs.now
    state.current_alerts = current_alerts

    state.have = True
    # Match the simulator: a stale replay must not roll the monotone timestamp
    # baseline backwards and let subsequent stale messages evade the check.
    state.last_tx = max(state.last_tx, obs.tx)
    if obs.seq not in state.seen:
        state.seen.add(obs.seq)
        state.seen_fifo.append(obs.seq)
        if len(state.seen_fifo) > args.replay_memory:
            state.seen.remove(state.seen_fifo.popleft())


def evaluate(
    path: Path,
    schema: Schema,
    key_mode: str,
    args: argparse.Namespace,
    eval_start: float,
    warmup: float,
) -> dict[tuple[int, int], State]:
    states: dict[tuple[int, int], State] = defaultdict(State)
    prior_score = math.log(args.prior / (1.0 - args.prior))
    for obs in observations(path, schema):
        identity = obs.claimed if key_mode == "claimed" else obs.source
        state = states[(obs.rx, identity)]
        if not state.have:
            state.score = prior_score
            state.owner_attacker = (
                obs.owner_attacker if key_mode == "claimed" else obs.source_attacker
            )
        expected_owner = (
            obs.owner_attacker if key_mode == "claimed" else obs.source_attacker
        )
        if state.owner_attacker != expected_owner:
            raise TraceSchemaError(
                f"{path}: inconsistent owner label for receiver/key "
                f"{obs.rx}/{identity}"
            )
        update_state(state, obs, args, eval_start, warmup)
    return {
        key: state for key, state in states.items() if state.window_messages > 0
    }


def divide(num: int, den: int) -> float:
    return num / den if den else math.nan


def detector_threshold(
    detector: str, args: argparse.Namespace
) -> float:
    params = args.baseline_parameters
    return {
        "range": params["range_threshold_m"],
        "sudden-appearance": -params["sudden_range_m"],
        "two-of-seven": float(params["votes_required"]) - 0.5,
        "sequential-score": args.score_threshold,
        "identity-contested": params["identity_contested_threshold"],
        "weighted-sum": params["weighted_sum_threshold"],
        "naive-bayes": params["naive_bayes_score_threshold"],
        "ewma": params["ewma_threshold"],
        "logistic-regression": float(args.logistic_model["threshold"]),
    }[detector]


def predicted(state: State, detector: str, args: argparse.Namespace) -> bool:
    return state.peak_signals[detector] > detector_threshold(detector, args)


def rank_auc(scores: list[float], truths: list[bool]) -> float:
    positives = sum(truths)
    negatives = len(truths) - positives
    if not positives or not negatives:
        return math.nan
    order = sorted(range(len(scores)), key=lambda index: scores[index])
    rank_sum = 0.0
    start = 0
    while start < len(order):
        end = start + 1
        while end < len(order) and scores[order[end]] == scores[order[start]]:
            end += 1
        average_rank = 0.5 * ((start + 1) + end)
        rank_sum += average_rank * sum(truths[order[index]] for index in range(start, end))
        start = end
    return (rank_sum - positives * (positives + 1) / 2.0) / (
        positives * negatives
    )


def average_precision(scores: list[float], truths: list[bool]) -> float:
    positives = sum(truths)
    if not positives:
        return math.nan
    order = sorted(range(len(scores)), key=lambda index: scores[index], reverse=True)
    tp = fp = 0
    recall_before = 0.0
    area = 0.0
    start = 0
    while start < len(order):
        end = start + 1
        while end < len(order) and scores[order[end]] == scores[order[start]]:
            end += 1
        group_truth = sum(truths[order[index]] for index in range(start, end))
        tp += group_truth
        fp += end - start - group_truth
        recall = tp / positives
        area += (recall - recall_before) * tp / (tp + fp)
        recall_before = recall
        start = end
    return area


def run_metrics(
    states: dict[tuple[int, int], State],
    key_mode: str,
    args: argparse.Namespace,
) -> dict[str, dict[str, float]]:
    output: dict[str, dict[str, float]] = {}
    victim_ids = {
        identity
        for (_, identity), state in states.items()
        if state.malicious_stream and not state.owner_attacker
    }
    for detector in DETECTORS:
        stream_pos = [s for s in states.values() if s.malicious_stream]
        # Match the simulator's definition exactly: a clean pair is one whose
        # identity owner is honest AND which carried no malicious message.
        # Defining it as "no malicious message" alone would fold in
        # attacker-owned identities that happened to stay quiet, making this
        # column incomparable to the detector's own clean-FPR in the same
        # table.
        clean = [
            s
            for s in states.values()
            if not s.malicious_stream and not s.owner_attacker
        ]
        owner_pos = [s for s in states.values() if s.owner_attacker]
        owner_neg = [s for s in states.values() if not s.owner_attacker]
        victims = [
            s
            for s in states.values()
            if s.malicious_stream and not s.owner_attacker
        ]
        flagged_victim_ids = {
            identity
            for (_, identity), state in states.items()
            if state.malicious_stream
            and not state.owner_attacker
            and predicted(state, detector, args)
        }
        stream_predictions = [predicted(state, detector, args) for state in states.values()]
        stream_truth = [state.malicious_stream for state in states.values()]
        tp = sum(prediction and truth for prediction, truth in zip(stream_predictions, stream_truth))
        fp = sum(prediction and not truth for prediction, truth in zip(stream_predictions, stream_truth))
        fn = sum(not prediction and truth for prediction, truth in zip(stream_predictions, stream_truth))
        delays = [
            state.first_stream_alert_time[detector]
            - max(state.evaluation_start, state.first_malicious_time)
            for state in stream_pos
            if state.first_stream_alert_time[detector] is not None
            and state.first_malicious_time is not None
        ]
        signals = [state.peak_signals[detector] for state in states.values()]
        output[detector] = {
            "stream_tpr": divide(
                sum(predicted(s, detector, args) for s in stream_pos),
                len(stream_pos),
            ),
            "clean_fpr": divide(
                sum(predicted(s, detector, args) for s in clean), len(clean)
            ),
            "owner_tpr": divide(
                sum(predicted(s, detector, args) for s in owner_pos), len(owner_pos)
            ),
            "owner_fpr": divide(
                sum(predicted(s, detector, args) for s in owner_neg), len(owner_neg)
            ),
            "victim_pair_rate": (
                divide(
                    sum(predicted(s, detector, args) for s in victims), len(victims)
                )
                if key_mode == "claimed"
                else math.nan
            ),
            "victim_unique_rate": (
                divide(len(flagged_victim_ids), len(victim_ids))
                if key_mode == "claimed"
                else math.nan
            ),
            "precision": divide(tp, tp + fp),
            "recall": divide(tp, tp + fn),
            "f1": divide(2 * tp, 2 * tp + fp + fn),
            "false_positive_count": float(fp),
            "roc_auc": rank_auc(signals, stream_truth),
            "pr_auc": average_precision(signals, stream_truth),
            "median_detection_delay_s": (
                statistics.median(delays) if delays else math.nan
            ),
            "censored_fraction": divide(len(stream_pos) - len(delays), len(stream_pos)),
        }
    return output


def block_bootstrap_ci(
    values: list[tuple[int, float]], samples: int, rng: random.Random
) -> tuple[float, float, float, int]:
    by_seed: dict[int, list[float]] = defaultdict(list)
    for seed, value in values:
        if math.isfinite(value):
            by_seed[seed].append(value)
    if not by_seed:
        return math.nan, math.nan, math.nan, 0
    seeds = sorted(by_seed)
    observed = [value for seed in seeds for value in by_seed[seed]]
    mean = statistics.fmean(observed)
    if len(seeds) < 2 or samples == 0:
        return mean, math.nan, math.nan, len(seeds)
    replicates: list[float] = []
    for _ in range(samples):
        selected = rng.choices(seeds, k=len(seeds))
        sample = [value for seed in selected for value in by_seed[seed]]
        replicates.append(statistics.fmean(sample))
    replicates.sort()
    lo = replicates[int(0.025 * (samples - 1))]
    hi = replicates[int(0.975 * (samples - 1))]
    return mean, lo, hi, len(seeds)


def format_ci(summary: tuple[float, float, float, int]) -> str:
    mean, lo, hi, seeds = summary
    if not math.isfinite(mean):
        return "--"
    if not math.isfinite(lo):
        return f"{mean:.3f} (S={seeds})"
    return f"{mean:.3f} [{lo:.3f},{hi:.3f}] S={seeds}"


def load_threshold(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.threshold_json is not None:
        try:
            payload = json.loads(args.threshold_json.read_text(encoding="utf-8"))
            artifact_schema = str(payload["schema"])
            if not artifact_schema.startswith("v6_"):
                raise ValueError(
                    f"threshold artifact schema {artifact_schema!r} is not v6"
                )
            threshold = float(payload["threshold"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"cannot read threshold from {args.threshold_json}: {exc}")
        args.score_threshold = threshold
        args.threshold_provenance = (
            f"{args.threshold_json} ({artifact_schema})"
        )
    else:
        args.threshold_provenance = "explicit CLI value"
    if not 0.0 <= args.score_threshold <= 1.0:
        parser.error("score threshold must be in [0,1]")


def provisional_parameters(score_threshold: float) -> dict[str, float | int]:
    """Initialization used only while collecting validation peak signals."""
    return {
        "range_threshold_m": 300.0,
        "sudden_range_m": 150.0,
        "votes_required": 2,
        "identity_contested_threshold": 1.5,
        "weighted_sum_threshold": 3.0,
        "naive_bayes_score_threshold": score_threshold,
        "ewma_alpha": 0.30,
        "ewma_threshold": 0.35,
    }


def load_baseline_artifact(
    path: Path, args: argparse.Namespace, parser: argparse.ArgumentParser
) -> dict[str, float | int]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload["schema"] != BASELINE_ARTIFACT_SCHEMA:
            raise ValueError(f"unexpected schema {payload['schema']!r}")
        if payload["score_model"] != args.score_model:
            raise ValueError("score model differs from the requested replay")
        if not math.isclose(
            float(payload["sequential_score_threshold"]),
            args.score_threshold,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):
            raise ValueError("sequential threshold differs from threshold artifact")
        params = dict(payload["parameters"])
        logistic_model = dict(payload["logistic_regression"])
        selection_protocol = dict(payload["clean_seed_constraint"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f"cannot load baseline parameters from {path}: {exc}")
    required = set(provisional_parameters(args.score_threshold))
    if set(params) != required:
        parser.error(
            f"baseline parameter keys differ: missing={sorted(required-set(params))}, "
            f"extra={sorted(set(params)-required)}"
        )
    for name, value in params.items():
        if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            parser.error(f"baseline parameter {name} is not finite numeric")
    if int(params["votes_required"]) not in range(1, 8):
        parser.error("votes_required must be in [1,7]")
    if float(params["identity_contested_threshold"]) < 1.0:
        parser.error("identity_contested_threshold must be at least one source")
    if float(params["ewma_alpha"]) not in EWMA_ALPHA_CANDIDATES:
        parser.error(f"ewma_alpha must be one of {EWMA_ALPHA_CANDIDATES}")
    try:
        if logistic_model["feature_names"] != list(CHECK_FEATURES):
            raise ValueError("feature names/order differ from the seven checks")
        for name in ("scaling_mean", "scaling_scale", "coefficients"):
            values = list(logistic_model[name])
            if len(values) != len(CHECK_FEATURES) or not all(
                math.isfinite(float(value)) for value in values
            ):
                raise ValueError(f"{name} must contain seven finite values")
        if any(float(value) <= 0.0 for value in logistic_model["scaling_scale"]):
            raise ValueError("scaling_scale entries must be positive")
        for name in ("intercept", "threshold", "l2_penalty"):
            if not math.isfinite(float(logistic_model[name])):
                raise ValueError(f"{name} is not finite")
        if not 0.0 <= float(logistic_model["threshold"]) <= 1.0:
            raise ValueError("logistic threshold is outside [0,1]")
        if float(logistic_model["l2_penalty"]) < 0.0:
            raise ValueError("logistic l2_penalty is negative")
        # Preserve the complete, auditable feature definition from the frozen
        # validation artifact; held-out replay never refits these values.
        str(logistic_model["feature_definition"])
        str(logistic_model["optimizer"])
        if logistic_model["fit_weighting"] != (
            "equal total weight per independent RNG seed block"
        ):
            raise ValueError("unexpected logistic fit weighting")
    except (KeyError, TypeError, ValueError) as exc:
        parser.error(f"invalid logistic-regression artifact: {exc}")
    try:
        if selection_protocol["method"] != "Clopper-Pearson exact one-sided binomial upper bound":
            raise ValueError("unexpected clean-seed bound method")
        if not math.isclose(
            float(selection_protocol["confidence"]),
            args.clean_seed_confidence,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise ValueError("clean-seed confidence differs from frozen artifact")
        if not math.isclose(
            float(selection_protocol["maximum_upper_bound"]),
            args.max_clean_seed_upper,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise ValueError("clean-seed bound differs from frozen artifact")
        total_benign = int(selection_protocol["total_benign_validation_seeds"])
        eligible_benign = int(selection_protocol["eligible_benign_seeds"])
        if total_benign <= 0 or eligible_benign <= 0 or eligible_benign > total_benign:
            raise ValueError("artifact has no eligible benign seeds")
    except (KeyError, TypeError, ValueError) as exc:
        parser.error(f"invalid clean-seed selection protocol: {exc}")
    args.logistic_model = logistic_model
    args.baseline_selection_protocol = selection_protocol
    return params


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--traces",
        type=Path,
        default=ROOT / "results",
        help="directory containing v6 per-reception CSV traces",
    )
    # Pipeline traces live at results/<version>/<mode>/runs/<stage>/<id>/trace.csv.
    # The old default pointed at code/traces/, which holds pre-v5 files whose
    # header lacks every oracle_* column, so the tool aborted on its own
    # default arguments.
    parser.add_argument("--pattern", default="**/trace.csv")
    protocol = parser.add_mutually_exclusive_group(required=True)
    protocol.add_argument(
        "--fit-output",
        type=Path,
        help=(
            "fit every baseline setting on validation traces and write the "
            "frozen JSON artifact"
        ),
    )
    protocol.add_argument(
        "--baseline-parameters",
        type=Path,
        help="evaluate held-out test traces using this frozen validation artifact",
    )
    parser.add_argument(
        "--score-model", choices=sorted(CHECK_MODELS), default="reference"
    )
    parser.add_argument("--bootstrap", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260731)
    parser.add_argument(
        "--max-clean-seed-upper",
        type=float,
        default=DEFAULT_MAX_CLEAN_SEED_UPPER,
        help="maximum exact one-sided upper bound for benign-seed alert probability",
    )
    parser.add_argument(
        "--clean-seed-confidence",
        type=float,
        default=DEFAULT_CLEAN_SEED_CONFIDENCE,
    )
    parser.add_argument(
        "--metrics-output",
        type=Path,
        help="optional JSON output for held-out per-run metrics and seed-block intervals",
    )
    parser.add_argument("--warmup", type=float, default=5.0)
    parser.add_argument("--comm-range", type=float, default=300.0)
    parser.add_argument("--sudden-range", type=float, default=150.0)
    parser.add_argument("--vmax", type=float, default=60.0)
    parser.add_argument("--speed-tolerance", type=float, default=15.0)
    parser.add_argument("--max-age", type=float, default=0.50)
    parser.add_argument("--min-ref-dt", type=float, default=0.50)
    parser.add_argument("--detector-gps-sigma", type=float, default=2.0)
    parser.add_argument("--speed-sigma", type=float, default=0.5)
    parser.add_argument("--rate-window", type=float, default=1.0)
    parser.add_argument("--rate-limit", type=float, default=20.0)
    parser.add_argument("--road-length", type=float, default=5000.0)
    parser.add_argument("--road-width", type=float, default=30.0)
    parser.add_argument("--heading-cos-min", type=float, default=0.0)
    parser.add_argument("--prior", type=float, default=0.05)
    parser.add_argument(
        "--decay-half-life",
        "--decayHalfLife",
        dest="decay_half_life",
        type=float,
        default=3.430961849152064,
        help=(
            "evidence half-life in seconds; -1 disables forgetting "
            "(must match simulator --decayHalfLife)"
        ),
    )
    threshold = parser.add_mutually_exclusive_group(required=True)
    threshold.add_argument(
        "--score-threshold",
        type=float,
        help="explicit bounded decision-score threshold",
    )
    threshold.add_argument(
        "--threshold-json",
        type=Path,
        help="threshold-selection JSON containing a numeric threshold field",
    )
    parser.add_argument("--score-clamp", type=float, default=8.0)
    parser.add_argument("--replay-memory", type=int, default=500)
    args = parser.parse_args()
    if not 0.0 < args.prior < 1.0:
        parser.error("--prior must be strictly between 0 and 1")
    positive = {
        "--rate-window": args.rate_window,
        "--rate-limit": args.rate_limit,
    }
    for name, value in positive.items():
        if not math.isfinite(value) or value <= 0.0:
            parser.error(f"{name} must be finite and positive")
    if (
        not math.isfinite(args.decay_half_life)
        or args.decay_half_life == 0.0
        or args.decay_half_life < -1.0
    ):
        parser.error("--decay-half-life must be positive or exactly -1")
    if args.bootstrap < 0:
        parser.error("--bootstrap cannot be negative")
    if not 0.0 < args.clean_seed_confidence < 1.0:
        parser.error("--clean-seed-confidence must be in (0,1)")
    if not 0.0 < args.max_clean_seed_upper <= 1.0:
        parser.error("--max-clean-seed-upper must be in (0,1]")
    if args.replay_memory <= 0:
        parser.error("--replay-memory must be positive")
    load_threshold(args, parser)
    parameter_path = args.baseline_parameters
    if parameter_path is not None:
        # argparse stores the path under this name; retain the loaded mapping
        # separately so update_state never has an unproven built-in setting.
        args.baseline_parameter_path = parameter_path
        args.baseline_parameters = load_baseline_artifact(parameter_path, args, parser)
    else:
        args.baseline_parameter_path = None
        args.baseline_parameters = provisional_parameters(args.score_threshold)
        args.logistic_model = provisional_logistic_model()
        args.baseline_selection_protocol = None
    return args


def select_records(
    records: list[MetricRecord],
    mode: str,
    detector: str,
    attack: str | None,
    families: frozenset[str] | set[str] | None = None,
) -> list[MetricRecord]:
    return [
        record
        for record in records
        if record.mode == mode
        and record.detector == detector
        and (attack is None or record.attack == attack)
        and (families is None or record.family in families)
    ]


@dataclass(frozen=True)
class FitState:
    seed: int
    attack: str
    run_id: str
    state: State


def fit_logistic_regression(
    records: list[FitState], l2_penalty: float = 1.0
) -> dict[str, object]:
    """Fit a transparent seven-check-rate logistic model on validation only."""
    features = np.vstack(
        [logistic_feature_vector(record.state) for record in records]
    )
    labels = np.asarray(
        [record.state.malicious_stream for record in records], dtype=np.float64
    )
    if not np.any(labels == 0.0) or not np.any(labels == 1.0):
        raise TraceSchemaError(
            "logistic-regression validation fit requires both clean and malicious pairs"
        )
    records_per_seed = defaultdict(int)
    for record in records:
        records_per_seed[record.seed] += 1
    sample_weights = np.asarray(
        [1.0 / records_per_seed[record.seed] for record in records],
        dtype=np.float64,
    )
    # Give every independent RNG seed block equal total fitting weight.
    sample_weights *= len(records) / float(np.sum(sample_weights))
    mean = np.average(features, axis=0, weights=sample_weights)
    scale = np.sqrt(
        np.average((features - mean) ** 2, axis=0, weights=sample_weights)
    )
    scale = np.where(scale > 1e-12, scale, 1.0)
    standardized = (features - mean) / scale
    design = np.column_stack((np.ones(len(records)), standardized))

    coefficients = np.zeros(design.shape[1], dtype=np.float64)
    class_rate = float(np.average(labels, weights=sample_weights))
    coefficients[0] = math.log(class_rate / (1.0 - class_rate))
    regularizer = np.diag(
        np.asarray([0.0] + [float(l2_penalty)] * len(CHECK_FEATURES))
    )
    converged = False
    iterations = 0
    for iterations in range(1, 101):
        linear = np.clip(design @ coefficients, -40.0, 40.0)
        probabilities = 1.0 / (1.0 + np.exp(-linear))
        gradient = (
            design.T @ (sample_weights * (probabilities - labels))
            + regularizer @ coefficients
        )
        curvature = sample_weights * np.maximum(
            probabilities * (1.0 - probabilities), 1e-9
        )
        hessian = design.T @ (design * curvature[:, None]) + regularizer
        try:
            step = np.linalg.solve(hessian, gradient)
        except np.linalg.LinAlgError:
            step = np.linalg.lstsq(hessian, gradient, rcond=None)[0]
        coefficients -= step
        if float(np.max(np.abs(step))) < 1e-9:
            converged = True
            break
    if not np.all(np.isfinite(coefficients)):
        raise TraceSchemaError("logistic-regression fit produced non-finite coefficients")

    return {
        "feature_names": list(CHECK_FEATURES),
        "feature_definition": (
            "cumulative fraction of receiver-identity pair receptions in the "
            "shared evaluation window for which each plausibility check fired; "
            "the pair signal is the maximum fitted probability over these "
            "cumulative rate vectors"
        ),
        "scaling_mean": [float(value) for value in mean],
        "scaling_scale": [float(value) for value in scale],
        "coefficients": [float(value) for value in coefficients[1:]],
        "intercept": float(coefficients[0]),
        "threshold": 0.5,
        "l2_penalty": float(l2_penalty),
        "optimizer": "L2-penalized Newton-Raphson on validation pairs",
        "fit_weighting": "equal total weight per independent RNG seed block",
        "optimizer_converged": converged,
        "optimizer_iterations": iterations,
        "training_pairs": len(records),
        "training_positive_pairs": int(np.sum(labels)),
        "training_seed_blocks": len(records_per_seed),
    }


def validation_states(
    files: list[Path], args: argparse.Namespace
) -> tuple[list[FitState], list[RunMeta]]:
    records: list[FitState] = []
    metadata: list[RunMeta] = []
    seen: set[str] = set()
    for path in files:
        schema = read_schema(path)
        meta = run_metadata(path)
        if meta.run_id in seen:
            raise TraceSchemaError(f"duplicate validation run ID {meta.run_id!r}")
        seen.add(meta.run_id)
        eval_start, run_warmup = verify_replay_config(meta, args, "validation")
        states = evaluate(path, schema, "claimed", args, eval_start, run_warmup)
        metadata.append(meta)
        records.extend(
            FitState(meta.seed, meta.attack, meta.run_id, state)
            for state in states.values()
        )
    return records, metadata


def threshold_candidates(values: list[float], maximum: int = 501) -> list[float]:
    unique = sorted({value for value in values if math.isfinite(value)})
    if not unique:
        return [0.0]
    if len(unique) > maximum - 1:
        # Deterministic rank grid, fixed before labels are consulted.
        indices = {
            round(index * (len(unique) - 1) / (maximum - 2))
            for index in range(maximum - 1)
        }
        unique = [unique[index] for index in sorted(indices)]
    epsilon = max(1e-12, abs(unique[0]) * 1e-12)
    return unique + [unique[0] - epsilon]


def score_threshold(
    records: list[FitState],
    detector: str,
    threshold: float,
    clean_seed_confidence: float = DEFAULT_CLEAN_SEED_CONFIDENCE,
) -> dict[str, float | int]:
    by_seed: dict[int, list[int]] = defaultdict(lambda: [0, 0, 0])
    # [tp, fp, fn], with F1 macro-averaged by independent RNG seed.
    clean_fp = clean_total = 0
    benign_seed_alert: dict[int, bool] = {}
    for record in records:
        state = record.state
        prediction = state.peak_signals[detector] > threshold
        truth = state.malicious_stream
        if truth and prediction:
            by_seed[record.seed][0] += 1
        elif not truth and prediction:
            by_seed[record.seed][1] += 1
        elif truth:
            by_seed[record.seed][2] += 1
        if not state.owner_attacker and not truth:
            clean_total += 1
            clean_fp += int(prediction)
        if record.attack == "none":
            if truth or state.owner_attacker:
                raise TraceSchemaError(
                    f"{record.run_id}: benign validation trace has hostile truth"
                )
            benign_seed_alert[record.seed] = (
                benign_seed_alert.get(record.seed, False) or prediction
            )
    seed_f1 = []
    for tp, fp, fn in by_seed.values():
        denominator = 2 * tp + fp + fn
        if denominator:
            seed_f1.append(2.0 * tp / denominator)
    benign_seed_total = len(benign_seed_alert)
    if not benign_seed_total:
        raise TraceSchemaError("baseline selection has no eligible benign seeds")
    benign_seed_events = sum(benign_seed_alert.values())
    benign_seed_upper = (
        1.0
        if benign_seed_events == benign_seed_total
        else float(
            beta_distribution.ppf(
                clean_seed_confidence,
                benign_seed_events + 1,
                benign_seed_total - benign_seed_events,
            )
        )
    )
    return {
        "threshold": threshold,
        "seed_macro_f1": statistics.fmean(seed_f1) if seed_f1 else 0.0,
        "clean_fp": clean_fp,
        "clean_total": clean_total,
        "benign_seed_events": benign_seed_events,
        "benign_seed_total": benign_seed_total,
        "benign_seed_upper": benign_seed_upper,
        "clean_seed_confidence": clean_seed_confidence,
    }


def select_signal_threshold(
    records: list[FitState],
    detector: str,
    candidates: list[float] | None = None,
    max_clean_seed_upper: float = DEFAULT_MAX_CLEAN_SEED_UPPER,
    clean_seed_confidence: float = DEFAULT_CLEAN_SEED_CONFIDENCE,
) -> dict[str, float | int]:
    if candidates is None:
        candidates = threshold_candidates(
            [record.state.peak_signals[detector] for record in records]
        )
    scored = [
        score_threshold(
            records, detector, value, clean_seed_confidence
        )
        for value in candidates
    ]
    eligible = [
        row
        for row in scored
        if float(row["benign_seed_upper"]) <= max_clean_seed_upper + 1e-15
    ]
    if not eligible:
        minimum = min(float(row["benign_seed_upper"]) for row in scored)
        raise TraceSchemaError(
            f"{detector}: no validation threshold satisfies clean-seed upper "
            f"bound <= {max_clean_seed_upper:g}; best is {minimum:g}"
        )
    # Deterministic tie-break: best seed-macro F1, fewer benign seed events,
    # fewer clean pair FPs, then the higher native-scale threshold.
    return max(
        eligible,
        key=lambda row: (
            float(row["seed_macro_f1"]),
            -int(row["benign_seed_events"]),
            -int(row["clean_fp"]),
            float(row["threshold"]),
        ),
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fit_baselines(
    files: list[Path], args: argparse.Namespace
) -> tuple[dict[str, object], list[RunMeta]]:
    # One pass collects every thresholdable signal except EWMA alpha, which is
    # itself selected on validation and therefore needs one pass per candidate.
    args.baseline_parameters = provisional_parameters(args.score_threshold)
    initial_records, metadata = validation_states(files, args)
    if not initial_records:
        raise TraceSchemaError("validation traces contain no eligible pairs")
    logistic_model = fit_logistic_regression(initial_records)
    del initial_records
    # The supervised coefficients are now frozen. Replay validation once more
    # so its threshold is selected on the same maximum cumulative-rate signal
    # that will be evaluated on held-out test traces.
    args.logistic_model = logistic_model
    records, replay_metadata = validation_states(files, args)
    if [meta.run_id for meta in replay_metadata] != [meta.run_id for meta in metadata]:
        raise TraceSchemaError("validation replay changed its run ordering")

    selection_options = {
        "max_clean_seed_upper": args.max_clean_seed_upper,
        "clean_seed_confidence": args.clean_seed_confidence,
    }
    selections: dict[str, dict[str, float | int]] = {}
    selections["range"] = select_signal_threshold(
        records, "range", **selection_options
    )
    selections["sudden-appearance"] = select_signal_threshold(
        records, "sudden-appearance", **selection_options
    )
    selections["two-of-seven"] = select_signal_threshold(
        records,
        "two-of-seven",
        [float(votes) - 0.5 for votes in range(1, 8)],
        **selection_options,
    )
    selections["sequential-score"] = select_signal_threshold(
        records,
        "sequential-score",
        [args.score_threshold],
        **selection_options,
    )
    selections["identity-contested"] = select_signal_threshold(
        records,
        "identity-contested",
        [1.5],
        **selection_options,
    )
    selections["weighted-sum"] = select_signal_threshold(
        records, "weighted-sum", **selection_options
    )
    selections["naive-bayes"] = select_signal_threshold(
        records, "naive-bayes", **selection_options
    )
    selections["logistic-regression"] = select_signal_threshold(
        records, "logistic-regression", **selection_options
    )

    ewma_choices: list[tuple[float, dict[str, float | int]]] = []
    for alpha in EWMA_ALPHA_CANDIDATES:
        for record in records:
            record.state.peak_signals["ewma"] = (
                record.state.peak_ewma_candidates[alpha]
            )
        selected = select_signal_threshold(
            records, "ewma", **selection_options
        )
        ewma_choices.append((alpha, selected))
    ewma_alpha, ewma_selection = max(
        ewma_choices,
        key=lambda item: (
            float(item[1]["seed_macro_f1"]),
            -int(item[1]["clean_fp"]),
            float(item[1]["threshold"]),
            -item[0],
        ),
    )
    selections["ewma"] = {**ewma_selection, "alpha": ewma_alpha}
    logistic_model["threshold"] = float(
        selections["logistic-regression"]["threshold"]
    )

    parameters: dict[str, float | int] = {
        "range_threshold_m": float(selections["range"]["threshold"]),
        "sudden_range_m": -float(selections["sudden-appearance"]["threshold"]),
        "votes_required": int(
            math.floor(float(selections["two-of-seven"]["threshold"]) + 0.5)
        ),
        "identity_contested_threshold": float(
            selections["identity-contested"]["threshold"]
        ),
        "weighted_sum_threshold": float(
            selections["weighted-sum"]["threshold"]
        ),
        "naive_bayes_score_threshold": float(
            selections["naive-bayes"]["threshold"]
        ),
        "ewma_alpha": ewma_alpha,
        "ewma_threshold": float(ewma_selection["threshold"]),
    }
    benign_seed_totals = {
        int(selection["benign_seed_total"])
        for selection in selections.values()
    }
    if len(benign_seed_totals) != 1:
        raise TraceSchemaError("baseline selectors disagree on eligible benign seeds")
    total_benign_validation_seeds = len(
        {meta.seed for meta in metadata if meta.attack == "none"}
    )
    eligible_benign_seeds = next(iter(benign_seed_totals))
    payload: dict[str, object] = {
        "schema": BASELINE_ARTIFACT_SCHEMA,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "fit_partition": "validation",
        "evaluation_partition": "test",
        "selection_rule": (
            "maximize independent-seed macro F1 subject to the exact one-sided "
            "benign-seed alert-probability upper bound; each rule freezes its "
            "own native-scale threshold with a deterministic conservative tie-break"
        ),
        "clean_seed_constraint": {
            "method": "Clopper-Pearson exact one-sided binomial upper bound",
            "event": "at least one alerted eligible pair in an attack=none validation seed",
            "confidence": args.clean_seed_confidence,
            "maximum_upper_bound": args.max_clean_seed_upper,
            "total_benign_validation_seeds": total_benign_validation_seeds,
            "eligible_benign_seeds": eligible_benign_seeds,
            "validation_trace_count": len(metadata),
        },
        "score_model": args.score_model,
        "sequential_score_threshold": args.score_threshold,
        "sequential_threshold_provenance": args.threshold_provenance,
        "parameters": parameters,
        "logistic_regression": logistic_model,
        "selection_diagnostics": selections,
        "validation_runs": [
            {
                "run_id": meta.run_id,
                "seed": meta.seed,
                "attack": meta.attack,
                "family": meta.family,
                "arm": meta.arm,
                "trace_sha256": file_sha256(meta.path),
                "summary_sha256": file_sha256(meta.path.parent / "summary.csv"),
            }
            for meta in metadata
        ],
    }
    args.baseline_parameters = parameters
    return payload, metadata


def report_table(
    records: list[MetricRecord],
    attack: str | None,
    args: argparse.Namespace,
    rng: random.Random,
    families: frozenset[str] | set[str] | None = None,
    population_label: str | None = None,
) -> None:
    label = population_label or (
        "POOLED (seed blocks retain all selected arms)"
        if attack is None
        else attack
    )
    print(f"\nAttack stratum: {label}")
    print(
        f"{'key':14} {'rule':19} {'stream TPR':29} {'clean FPR':29} "
        f"{'owner TPR':29} {'owner FPR':29} {'victim-pair':29} "
        f"{'victim-ID':29}"
    )
    for mode in ("claimed", "source-oracle"):
        for detector in DETECTORS:
            selected = select_records(records, mode, detector, attack, families)
            summaries = [
                block_bootstrap_ci(
                    [(r.seed, r.values[name]) for r in selected],
                    args.bootstrap,
                    rng,
                )
                for name in METRICS[:6]
            ]
            print(
                f"{mode:14} {detector:19} "
                + " ".join(f"{format_ci(item):29}" for item in summaries)
            )

    print("Held-out classification and delay evidence")
    evidence_metrics = METRICS[6:]
    print(f"{'key':14} {'rule':19} " + " ".join(f"{name:29}" for name in evidence_metrics))
    for mode in ("claimed", "source-oracle"):
        for detector in DETECTORS:
            selected = select_records(records, mode, detector, attack, families)
            summaries = [
                block_bootstrap_ci(
                    [(record.seed, record.values[name]) for record in selected],
                    args.bootstrap,
                    rng,
                )
                for name in evidence_metrics
            ]
            print(
                f"{mode:14} {detector:19} "
                + " ".join(f"{format_ci(item):29}" for item in summaries)
            )

    print("Paired contrast: claimed minus source-oracle")
    print(f"{'rule':19} " + " ".join(f"{name:29}" for name in METRICS[:4]))
    for detector in DETECTORS:
        claimed = {
            r.run_id: r
            for r in select_records(
                records, "claimed", detector, attack, families
            )
        }
        oracle = {
            r.run_id: r
            for r in select_records(
                records, "source-oracle", detector, attack, families
            )
        }
        if claimed.keys() != oracle.keys():
            raise TraceSchemaError(
                f"unpaired claimed/oracle records for detector {detector}"
            )
        summaries = []
        for metric in METRICS[:4]:
            differences = [
                (claimed[key].seed, claimed[key].values[metric] - oracle[key].values[metric])
                for key in claimed
                if math.isfinite(claimed[key].values[metric])
                and math.isfinite(oracle[key].values[metric])
            ]
            summaries.append(
                block_bootstrap_ci(differences, args.bootstrap, rng)
            )
        print(
            f"{detector:19} "
            + " ".join(f"{format_ci(item):29}" for item in summaries)
        )


def main() -> int:
    args = parse_args()
    files = sorted(args.traces.glob(args.pattern))
    if not files:
        print(f"no trace files match {args.traces / args.pattern}", file=sys.stderr)
        return 2

    if args.fit_output is not None:
        try:
            payload, metadata = fit_baselines(files, args)
            args.fit_output.parent.mkdir(parents=True, exist_ok=True)
            args.fit_output.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except TraceSchemaError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(
            f"fitted {len(payload['parameters'])} baseline settings on "
            f"{len(metadata)} validation traces; wrote {args.fit_output}"
        )
        constraint = payload["clean_seed_constraint"]
        print(
            f"clean-seed constraint: {constraint['method']}; "
            f"confidence={constraint['confidence']}; "
            f"upper<={constraint['maximum_upper_bound']}; eligible benign "
            f"seeds={constraint['eligible_benign_seeds']}/"
            f"{constraint['total_benign_validation_seeds']} total"
        )
        print(json.dumps(payload["parameters"], indent=2, sort_keys=True))
        return 0

    records: list[MetricRecord] = []
    metadata: list[RunMeta] = []
    seen_run_ids: set[str] = set()
    replay_timings: list[dict[str, object]] = []
    replay_wall_start = time.perf_counter()
    replay_cpu_start = time.process_time()
    for path in files:
        try:
            schema = read_schema(path)
            meta = run_metadata(path)
            eval_start, run_warmup = verify_replay_config(meta, args, "test")
            if meta.run_id in seen_run_ids:
                raise TraceSchemaError(f"duplicate run ID {meta.run_id!r}")
            seen_run_ids.add(meta.run_id)
            metadata.append(meta)
            for mode in ("claimed", "source-oracle"):
                pass_start = time.perf_counter()
                states = evaluate(path, schema, mode, args, eval_start, run_warmup)
                replay_timings.append(
                    {
                        "run_id": meta.run_id,
                        "mode": mode,
                        "offline_wall_seconds": time.perf_counter() - pass_start,
                    }
                )
                metrics = run_metrics(states, mode, args)
                for detector, values in metrics.items():
                    records.append(
                        MetricRecord(
                            meta.seed,
                            meta.attack,
                            meta.run_id,
                            meta.family,
                            meta.arm,
                            mode,
                            detector,
                            values,
                        )
                    )
        except TraceSchemaError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    replay_wall_seconds = time.perf_counter() - replay_wall_start
    replay_cpu_seconds = time.process_time() - replay_cpu_start

    seeds = sorted({meta.seed for meta in metadata})
    attacks = sorted({meta.attack for meta in metadata})
    print(
        f"{len(files)} v6 traces in {len(seeds)} unique RNG-seed blocks; "
        f"scoreModel={args.score_model}; threshold={args.score_threshold:.12g} "
        f"from {args.threshold_provenance}; "
        f"decayHalfLife={args.decay_half_life:g}s; baseline parameters="
        f"{args.baseline_parameter_path}"
    )
    protocol = args.baseline_selection_protocol
    print(
        "Frozen validation selection (no held-out refitting): "
        f"{protocol['method']}; confidence={protocol['confidence']}; "
        f"upper<={protocol['maximum_upper_bound']}; eligible benign seeds="
        f"{protocol['eligible_benign_seeds']}/"
        f"{protocol['total_benign_validation_seeds']} total; validation traces="
        f"{protocol['validation_trace_count']}."
    )
    print(
        "95% intervals resample RNG seeds; all attack arms with the same seed "
        "move together. Source-oracle is evaluation-only. Identity-contested "
        "uses only the receiver-observed network source address; it does not "
        "read oracle physical-source identity."
    )
    print(
        "Headline population: test/pure_attack/* plus test/benign/* only. "
        "Steady-state, onset-guard and other stress families are reported "
        "separately and never enter headline pooling. Range and sudden-"
        "appearance consume receiver_true_x/y because the trace has no noisy "
        "receiver self-position; they are oracle-assisted structural upper "
        "bounds, not deployable baselines."
    )
    print(
        f"Offline trace replay runtime: wall={replay_wall_seconds:.6f}s, "
        f"CPU={replay_cpu_seconds:.6f}s for {len(replay_timings)} shared "
        "mode/run passes. This is analysis-host runtime, not OBU latency, and "
        "cannot be attributed to individual rules because checks are replayed once."
    )
    rng = random.Random(args.bootstrap_seed)
    try:
        report_table(
            records,
            None,
            args,
            rng,
            HEADLINE_FAMILIES,
            "HEADLINE: pure_attack + benign only",
        )
        for attack in attacks:
            report_table(records, attack, args, rng, HEADLINE_FAMILIES)
        control_families = sorted(
            {record.family for record in records} - HEADLINE_FAMILIES
        )
        for family in control_families:
            report_table(
                records,
                None,
                args,
                rng,
                {family},
                f"SECONDARY CONTROL FAMILY: {family}",
            )
    except TraceSchemaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.metrics_output is not None:
        def json_number(value: float) -> float | None:
            return value if math.isfinite(value) else None

        interval_rng = random.Random(args.bootstrap_seed)
        pooled_intervals: list[dict[str, object]] = []
        for mode in ("claimed", "source-oracle"):
            for detector in DETECTORS:
                selected = select_records(
                    records, mode, detector, None, HEADLINE_FAMILIES
                )
                for metric in METRICS:
                    mean, low, high, seeds_used = block_bootstrap_ci(
                        [(record.seed, record.values[metric]) for record in selected],
                        args.bootstrap,
                        interval_rng,
                    )
                    pooled_intervals.append(
                        {
                            "mode": mode,
                            "detector": detector,
                            "metric": metric,
                            "mean": json_number(mean),
                            "ci95_low": json_number(low),
                            "ci95_high": json_number(high),
                            "seed_blocks": seeds_used,
                            "population": "test/pure_attack + test/benign",
                        }
                    )
        machine_payload = {
            "schema": "v1_heldout_baseline_metrics",
            "partition": "test",
            "baseline_parameters": str(args.baseline_parameter_path),
            "headline_families": sorted(HEADLINE_FAMILIES),
            "excluded_secondary_control_families": sorted(
                {record.family for record in records} - HEADLINE_FAMILIES
            ),
            "oracle_assisted_structural_upper_bound_detectors": sorted(
                ORACLE_ASSISTED_STRUCTURAL_BOUNDS
            ),
            "receiver_position_scope": (
                "range and sudden-appearance use receiver_true_x/y because "
                "the trace does not contain noisy receiver self-position"
            ),
            "frozen_clean_seed_constraint": args.baseline_selection_protocol,
            "runtime_scope": (
                "offline shared trace replay on the analysis host; not OBU "
                "runtime and not attributable per detector"
            ),
            "offline_replay_wall_seconds": replay_wall_seconds,
            "offline_replay_cpu_seconds": replay_cpu_seconds,
            "replay_passes": replay_timings,
            "pooled_seed_block_intervals": pooled_intervals,
            "per_run_metrics": [
                {
                    "seed": record.seed,
                    "attack": record.attack,
                    "run_id": record.run_id,
                    "family": record.family,
                    "arm": record.arm,
                    "mode": record.mode,
                    "detector": record.detector,
                    **{
                        name: json_number(record.values[name])
                        for name in METRICS
                    },
                }
                for record in records
            ],
        }
        args.metrics_output.parent.mkdir(parents=True, exist_ok=True)
        args.metrics_output.write_text(
            json.dumps(machine_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote held-out baseline metrics to {args.metrics_output}")

    print(
        "\nDefinitions: hostile-stream truth is any explicitly malicious "
        "message, never attacker membership. Every detector uses one peak "
        "signal over the simulator-declared evaluation window and one frozen "
        "threshold for positives and negatives. Pre-attack messages remain "
        "detector history. Owner truth uses explicit claimed-owner/source "
        "labels; victim exposure means an honest claimed identity carried at "
        "least one malicious message."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
