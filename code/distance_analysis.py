#!/usr/bin/env python3
"""Held-out, received-exposure-conditional distance-stratified analysis.

This utility streams v6 ``trace.csv`` files and joins them to the sibling
``pairs.csv`` primary endpoint using ``(receiver_id, claimed_id)``.  For each
eligible hostile pair it computes the mean Euclidean oracle separation over
malicious messages *received inside the common evaluation window* and assigns
that pair to one of four predeclared bins::

    [0, 100), [100, 200), [200, 300], (300, infinity) metres.

The output retains attack-specific strata and a pooled stratum.  Confidence
intervals use a nonparametric seed-block bootstrap: every resampled block
contains all receiver/claimed-ID pairs (and, in the pooled stratum, all attack
arms) sharing that RNG seed.

Important estimand boundary
---------------------------
Distance is observed only for successfully received malicious messages.  The
results therefore describe detection conditional on received exposure; they
are neither radio-opportunity PDR estimates nor causal effects of distance.
The reported delay median is additionally conditional on detection, while the
censored count/fraction makes missed endpoints explicit.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import random
import re
import statistics
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence


class DistanceAnalysisError(RuntimeError):
    """Raised when an input artifact violates the analysis contract."""


TRACE_REQUIRED = {
    "receiver_id",
    "rx_time",
    "receiver_true_x",
    "receiver_true_y",
    "claimed_id",
    "oracle_source_id",
    "oracle_true_x",
    "oracle_true_y",
    "oracle_source_is_attacker",
    "oracle_attack_active",
    "oracle_message_is_malicious",
}

PAIR_REQUIRED = {
    "schema",
    "attack",
    "run",
    "attack_start_s",
    "receiver_id",
    "claimed_id",
    "malicious_use",
    "malicious_messages",
    "messages",
    "eval_window_start_s",
    "eligible",
    "window_msgs",
    "window_alert",
    "stream_time_to_detect_s",
    "stream_censored",
}

COMMAND_REQUIRED = {
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
    "mobility",
    "spdSigma",
    "clockSigma",
    "bsmBytes",
}

OUTPUT_FIELDS = (
    "stage",
    "family",
    "attack_stratum",
    "distance_bin",
    "distance_interval",
    "pair_count",
    "seed_count",
    "received_malicious_messages",
    "message_weighted_mean_distance_m",
    "median_pair_mean_distance_m",
    "detected_pair_count",
    "tpr",
    "tpr_ci95_low",
    "tpr_ci95_high",
    "censored_pair_count",
    "censor_fraction",
    "censor_fraction_ci95_low",
    "censor_fraction_ci95_high",
    "median_detected_delay_s",
    "median_detected_delay_ci95_low_s",
    "median_detected_delay_ci95_high_s",
    "delay_bootstrap_valid_reps",
    "bootstrap_reps",
    "bootstrap_seed",
    "ci_method",
    "distance_statistic",
    "distance_estimand",
    "delay_estimand",
)

DISTANCE_ESTIMAND = (
    "conditional on malicious messages received in W; not a radio-opportunity "
    "or causal-distance effect"
)
DELAY_ESTIMAND = (
    "median primary time-to-detect among detected eligible hostile pairs; "
    "misses reported as censored"
)
CI_METHOD = "95% percentile nonparametric RNG-seed-block bootstrap"
DISTANCE_STATISTIC = (
    "per-pair arithmetic mean Euclidean oracle separation over received "
    "malicious messages in W"
)


@dataclass(frozen=True)
class BinSpec:
    label: str
    interval: str

    def contains(self, value: float) -> bool:
        if self.label == "0-100":
            return 0.0 <= value < 100.0
        if self.label == "100-200":
            return 100.0 <= value < 200.0
        if self.label == "200-300":
            return 200.0 <= value <= 300.0
        if self.label == ">300":
            return value > 300.0
        raise AssertionError(f"unknown bin {self.label!r}")


BINS = (
    BinSpec("0-100", "[0,100)"),
    BinSpec("100-200", "[100,200)"),
    BinSpec("200-300", "[200,300]"),
    BinSpec(">300", "(300,inf)"),
)


@dataclass(frozen=True)
class RunConfig:
    trace: Path
    command: Path
    pairs: Path
    experiment_id: str
    stage: str
    family: str
    arm: str
    seed: int
    attack: str
    n_vehicles: int
    warmup: float
    attack_start: float
    onset_blank: float
    sim_time: float
    compatibility_options: tuple[tuple[str, str], ...]

    @property
    def eval_start(self) -> float:
        return max(self.warmup, self.attack_start + self.onset_blank)


@dataclass(frozen=True)
class PairInfo:
    key: tuple[int, int]
    malicious: bool
    malicious_messages: int
    messages: int
    eligible: bool
    window_messages: int
    alert: bool
    delay: float
    censored: int


@dataclass(frozen=True)
class Observation:
    attack: str
    seed: int
    receiver_id: int
    claimed_id: int
    mean_distance_m: float
    distance_sum_m: float
    malicious_messages: int
    alert: bool
    delay_s: float | None
    censored: bool


@dataclass
class TraceCounts:
    post_warmup_messages: dict[tuple[int, int], int]
    post_warmup_malicious: dict[tuple[int, int], int]
    window_messages: dict[tuple[int, int], int]
    window_malicious_count: dict[tuple[int, int], int]
    window_malicious_distance: dict[tuple[int, int], float]


def finite(value: object, context: str) -> float:
    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise DistanceAnalysisError(f"{context}: expected a number, got {value!r}") from exc
    if not math.isfinite(parsed):
        raise DistanceAnalysisError(f"{context}: value must be finite, got {value!r}")
    return parsed


def integer(value: object, context: str, minimum: int = 0) -> int:
    parsed = finite(value, context)
    if not parsed.is_integer() or parsed < minimum:
        raise DistanceAnalysisError(
            f"{context}: expected an integer >= {minimum}, got {value!r}"
        )
    return int(parsed)


def boolean(value: object, context: str) -> bool:
    text = str(value).strip().lower()
    if text in {"1", "true"}:
        return True
    if text in {"0", "false"}:
        return False
    raise DistanceAnalysisError(f"{context}: expected 0/1 or false/true, got {value!r}")


def parse_options(path: Path) -> tuple[dict[str, str], dict[str, object]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DistanceAnalysisError(f"cannot read metadata {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise DistanceAnalysisError(f"{path}: JSON root must be an object")
    argv = document.get("command_argv")
    if not isinstance(argv, list) or not argv or not all(
        isinstance(item, str) for item in argv
    ):
        raise DistanceAnalysisError(
            f"{path}: command_argv must be a non-empty string list"
        )
    options: dict[str, str] = {}
    for argument in argv[1:]:
        if not argument.startswith("--") or "=" not in argument:
            continue
        name, value = argument[2:].split("=", 1)
        if not name or name in options:
            raise DistanceAnalysisError(
                f"{path}: empty or duplicate simulator option {argument!r}"
            )
        options[name] = value
    missing = COMMAND_REQUIRED.difference(options)
    if missing:
        raise DistanceAnalysisError(
            f"{path}: missing simulator options {sorted(missing)}"
        )
    return options, document


def experiment_coordinates(
    document: dict[str, object], trace: Path
) -> tuple[str, str, str, str, int]:
    experiment_id = str(document.get("experiment_id", trace.parent.name)).strip()
    parts = experiment_id.split("__")
    if len(parts) != 4 or not all(parts[:3]):
        raise DistanceAnalysisError(
            f"{trace}: experiment_id must be stage__family__arm__seed_NNNN, "
            f"got {experiment_id!r}"
        )
    match = re.fullmatch(r"seed_([0-9]+)", parts[3])
    if not match:
        raise DistanceAnalysisError(
            f"{trace}: malformed seed suffix in {experiment_id!r}"
        )
    return experiment_id, parts[0], parts[1], parts[2], int(match.group(1))


def load_config(
    trace: Path,
    metadata_name: str,
    pairs_name: str,
    selected_stage: str,
    selected_family: str,
) -> RunConfig | None:
    command = trace.with_name(metadata_name)
    if not command.is_file():
        raise DistanceAnalysisError(f"{trace}: sibling {metadata_name} is missing")
    options, document = parse_options(command)
    experiment_id, stage, family, arm, id_seed = experiment_coordinates(document, trace)
    if stage != selected_stage or family != selected_family:
        return None

    pairs = trace.with_name(pairs_name)
    if not pairs.is_file():
        raise DistanceAnalysisError(f"{trace}: sibling {pairs_name} is missing")
    seed = integer(options["run"], f"{command}/--run", 1)
    if seed != id_seed:
        raise DistanceAnalysisError(f"{command}: experiment_id seed differs from --run")
    if "seed" in document and integer(document["seed"], f"{command}/seed", 1) != seed:
        raise DistanceAnalysisError(f"{command}: metadata seed differs from --run")
    attack = options["attack"].strip().lower()
    if not attack or attack == "none":
        raise DistanceAnalysisError(f"{command}: selected hostile arm has invalid attack")
    if selected_family == "pure_attack" and arm != f"pure_{attack}":
        raise DistanceAnalysisError(
            f"{command}: pure_attack arm {arm!r} disagrees with attack={attack!r}"
        )
    if not boolean(options["detector"], f"{command}/--detector"):
        raise DistanceAnalysisError(f"{command}: selected run has detector disabled")

    n_vehicles = integer(options["nVehicles"], f"{command}/--nVehicles", 2)
    sim_time = finite(options["simTime"], f"{command}/--simTime")
    warmup = finite(options["warmup"], f"{command}/--warmup")
    attack_start = finite(options["attackStart"], f"{command}/--attackStart")
    onset_blank = finite(options["onsetBlank"], f"{command}/--onsetBlank")
    eval_start = max(warmup, attack_start + onset_blank)
    if not (
        sim_time > 0.0
        and 0.0 <= warmup < sim_time
        and 0.0 <= attack_start < sim_time
        and onset_blank >= 0.0
        and eval_start < sim_time
    ):
        raise DistanceAnalysisError(f"{command}: invalid evaluation-window metadata")

    # Attack and seed intentionally vary. Output paths are per-run temporaries.
    # Every other simulator option must be byte-for-byte compatible before
    # attack strata may be pooled.
    varying = {"attack", "run", "pairOutput", "trace"}
    compatibility = tuple(
        sorted((name, value.strip()) for name, value in options.items() if name not in varying)
    )
    return RunConfig(
        trace=trace,
        command=command,
        pairs=pairs,
        experiment_id=experiment_id,
        stage=stage,
        family=family,
        arm=arm,
        seed=seed,
        attack=attack,
        n_vehicles=n_vehicles,
        warmup=warmup,
        attack_start=attack_start,
        onset_blank=onset_blank,
        sim_time=sim_time,
        compatibility_options=compatibility,
    )


def read_pairs(config: RunConfig) -> dict[tuple[int, int], PairInfo]:
    try:
        handle = config.pairs.open(newline="", encoding="utf-8")
    except OSError as exc:
        raise DistanceAnalysisError(f"cannot read {config.pairs}: {exc}") from exc
    result: dict[tuple[int, int], PairInfo] = {}
    with handle:
        reader = csv.DictReader(handle)
        header = reader.fieldnames
        if not header:
            raise DistanceAnalysisError(f"{config.pairs}: missing CSV header")
        if len(header) != len(set(header)):
            raise DistanceAnalysisError(f"{config.pairs}: duplicate CSV field")
        missing = PAIR_REQUIRED.difference(header)
        if missing:
            raise DistanceAnalysisError(
                f"{config.pairs}: missing pair fields {sorted(missing)}"
            )
        for line_no, row in enumerate(reader, 2):
            context = f"{config.pairs}:{line_no}"
            if None in row or any(value is None for value in row.values()):
                raise DistanceAnalysisError(f"{context}: CSV width mismatch")
            if row["schema"] != "v6_pair":
                raise DistanceAnalysisError(f"{context}: expected schema v6_pair")
            if row["attack"].strip().lower() != config.attack:
                raise DistanceAnalysisError(f"{context}: attack differs from metadata")
            if integer(row["run"], f"{context}/run", 1) != config.seed:
                raise DistanceAnalysisError(f"{context}: run differs from metadata")
            if not math.isclose(
                finite(row["attack_start_s"], f"{context}/attack_start_s"),
                config.attack_start,
                rel_tol=0.0,
                abs_tol=1e-9,
            ):
                raise DistanceAnalysisError(f"{context}: attack start differs from metadata")
            receiver = integer(row["receiver_id"], f"{context}/receiver_id")
            claimed = integer(row["claimed_id"], f"{context}/claimed_id")
            if receiver >= config.n_vehicles or claimed >= config.n_vehicles:
                raise DistanceAnalysisError(f"{context}: receiver/claimed ID out of range")
            key = (receiver, claimed)
            if key in result:
                raise DistanceAnalysisError(f"{context}: duplicate pair row {key}")

            malicious = boolean(row["malicious_use"], f"{context}/malicious_use")
            malicious_messages = integer(
                row["malicious_messages"], f"{context}/malicious_messages"
            )
            messages = integer(row["messages"], f"{context}/messages")
            eligible = boolean(row["eligible"], f"{context}/eligible")
            window_messages = integer(row["window_msgs"], f"{context}/window_msgs")
            alert = boolean(row["window_alert"], f"{context}/window_alert")
            delay = finite(
                row["stream_time_to_detect_s"], f"{context}/stream_time_to_detect_s"
            )
            censored_raw = integer(
                row["stream_censored"], f"{context}/stream_censored", -1
            )
            eval_start = finite(
                row["eval_window_start_s"], f"{context}/eval_window_start_s"
            )
            if not math.isclose(
                eval_start, config.eval_start, rel_tol=0.0, abs_tol=1e-9
            ):
                raise DistanceAnalysisError(f"{context}: evaluation window differs from metadata")
            if eligible != (window_messages > 0):
                raise DistanceAnalysisError(f"{context}: eligible disagrees with window_msgs")
            if alert and not eligible:
                raise DistanceAnalysisError(f"{context}: ineligible pair cannot alert")
            if malicious != (malicious_messages > 0):
                raise DistanceAnalysisError(
                    f"{context}: malicious_use disagrees with malicious_messages"
                )
            if messages < malicious_messages:
                raise DistanceAnalysisError(f"{context}: malicious messages exceed all messages")

            if malicious:
                if censored_raw not in {0, 1}:
                    raise DistanceAnalysisError(
                        f"{context}: hostile stream_censored must be 0/1"
                    )
                if alert != (delay >= 0.0) or censored_raw != int(not alert):
                    raise DistanceAnalysisError(
                        f"{context}: primary alert, delay, and censoring disagree"
                    )
            elif delay != -1.0 or censored_raw != -1:
                raise DistanceAnalysisError(
                    f"{context}: non-hostile delay/censoring must use -1 sentinels"
                )

            result[key] = PairInfo(
                key=key,
                malicious=malicious,
                malicious_messages=malicious_messages,
                messages=messages,
                eligible=eligible,
                window_messages=window_messages,
                alert=alert,
                delay=delay,
                censored=censored_raw,
            )
    if not result:
        raise DistanceAnalysisError(f"{config.pairs}: no pair rows")
    return result


def stream_trace(config: RunConfig) -> TraceCounts:
    post_messages: dict[tuple[int, int], int] = defaultdict(int)
    post_malicious: dict[tuple[int, int], int] = defaultdict(int)
    window_messages: dict[tuple[int, int], int] = defaultdict(int)
    window_malicious: dict[tuple[int, int], int] = defaultdict(int)
    distance_sum: dict[tuple[int, int], float] = defaultdict(float)
    try:
        handle = config.trace.open(newline="", encoding="utf-8")
    except OSError as exc:
        raise DistanceAnalysisError(f"cannot read {config.trace}: {exc}") from exc
    row_count = 0
    last_rx = -math.inf
    with handle:
        reader = csv.DictReader(handle)
        header = reader.fieldnames
        if not header:
            raise DistanceAnalysisError(f"{config.trace}: missing CSV header")
        if len(header) != len(set(header)):
            raise DistanceAnalysisError(f"{config.trace}: duplicate CSV field")
        missing = TRACE_REQUIRED.difference(header)
        if missing:
            raise DistanceAnalysisError(
                f"{config.trace}: missing trace fields {sorted(missing)}"
            )
        for line_no, row in enumerate(reader, 2):
            context = f"{config.trace}:{line_no}"
            if None in row or any(value is None for value in row.values()):
                raise DistanceAnalysisError(f"{context}: CSV width mismatch")
            row_count += 1
            receiver = integer(row["receiver_id"], f"{context}/receiver_id")
            claimed = integer(row["claimed_id"], f"{context}/claimed_id")
            source = integer(row["oracle_source_id"], f"{context}/oracle_source_id")
            if max(receiver, claimed, source) >= config.n_vehicles:
                raise DistanceAnalysisError(f"{context}: identity out of range")
            rx_time = finite(row["rx_time"], f"{context}/rx_time")
            if rx_time + 1e-12 < last_rx:
                raise DistanceAnalysisError(f"{context}: reception times are not monotone")
            if rx_time < 0.0 or rx_time > config.sim_time + 1e-9:
                raise DistanceAnalysisError(f"{context}: reception time outside simulation")
            last_rx = rx_time
            receiver_x = finite(row["receiver_true_x"], f"{context}/receiver_true_x")
            receiver_y = finite(row["receiver_true_y"], f"{context}/receiver_true_y")
            source_x = finite(row["oracle_true_x"], f"{context}/oracle_true_x")
            source_y = finite(row["oracle_true_y"], f"{context}/oracle_true_y")
            source_attacker = boolean(
                row["oracle_source_is_attacker"],
                f"{context}/oracle_source_is_attacker",
            )
            active = boolean(row["oracle_attack_active"], f"{context}/oracle_attack_active")
            malicious = boolean(
                row["oracle_message_is_malicious"],
                f"{context}/oracle_message_is_malicious",
            )
            if malicious and (not active or not source_attacker):
                raise DistanceAnalysisError(
                    f"{context}: malicious message lacks active attacker truth"
                )
            key = (receiver, claimed)
            if rx_time >= config.warmup:
                post_messages[key] += 1
                if malicious:
                    post_malicious[key] += 1
            if rx_time >= config.eval_start:
                window_messages[key] += 1
                if malicious:
                    distance = math.hypot(receiver_x - source_x, receiver_y - source_y)
                    if not math.isfinite(distance):
                        raise DistanceAnalysisError(f"{context}: non-finite oracle distance")
                    window_malicious[key] += 1
                    distance_sum[key] += distance
    if row_count == 0:
        raise DistanceAnalysisError(f"{config.trace}: no reception rows")
    return TraceCounts(
        dict(post_messages),
        dict(post_malicious),
        dict(window_messages),
        dict(window_malicious),
        dict(distance_sum),
    )


def join_run(config: RunConfig) -> list[Observation]:
    pairs = read_pairs(config)
    trace = stream_trace(config)

    # These equalities prove that the trace and endpoint are from the same run
    # and use the same warm-up/window boundaries; a key-only join is not enough.
    # Compare on the EVALUATION WINDOW, not on warm-up. pairs.csv contains only
    # pairs eligible in W = [max(warmup, t_a + g), T]; when t_a > warmup a pair
    # can receive between warm-up and W and legitimately never appear there.
    # Keying this check on warm-up made those pairs look like missing rows.
    post_keys = set(trace.window_messages)
    missing_pair_keys = post_keys.difference(pairs)
    if missing_pair_keys:
        raise DistanceAnalysisError(
            f"{config.trace}: post-warm-up trace keys absent from pairs.csv: "
            f"{sorted(missing_pair_keys)[:5]}"
        )
    observations: list[Observation] = []
    for key, pair in pairs.items():
        context = f"{config.experiment_id}/pair{key}"
        # pairs.csv counts are WINDOW-scoped: the simulator increments state.msgs
        # only for receptions with now >= g_evalStart. Comparing them against
        # post-warm-up trace counts disagrees whenever t_a + g > warmup, which is
        # every mid-stream arm.
        if trace.window_messages.get(key, 0) != pair.messages:
            raise DistanceAnalysisError(f"{context}: trace/pair message counts disagree")
        if trace.window_malicious_count.get(key, 0) != pair.malicious_messages:
            raise DistanceAnalysisError(
                f"{context}: trace/pair malicious-message counts disagree"
            )
        if trace.window_messages.get(key, 0) != pair.window_messages:
            raise DistanceAnalysisError(f"{context}: trace/pair window counts disagree")
        if not (pair.eligible and pair.malicious):
            continue
        exposure = trace.window_malicious_count.get(key, 0)
        if exposure <= 0:
            raise DistanceAnalysisError(
                f"{context}: eligible hostile pair has no malicious reception in W"
            )
        distance_sum = trace.window_malicious_distance[key]
        mean_distance = distance_sum / exposure
        observations.append(
            Observation(
                attack=config.attack,
                seed=config.seed,
                receiver_id=key[0],
                claimed_id=key[1],
                mean_distance_m=mean_distance,
                distance_sum_m=distance_sum,
                malicious_messages=exposure,
                alert=pair.alert,
                delay_s=pair.delay if pair.alert else None,
                censored=bool(pair.censored),
            )
        )
    if not observations:
        raise DistanceAnalysisError(
            f"{config.experiment_id}: no eligible hostile received-exposure pairs"
        )
    return observations


def distance_bin(value: float) -> BinSpec:
    if not math.isfinite(value) or value < 0.0:
        raise DistanceAnalysisError(f"invalid mean distance {value!r}")
    for spec in BINS:
        if spec.contains(value):
            return spec
    raise AssertionError(f"nonnegative finite distance escaped bins: {value}")


def percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise DistanceAnalysisError("cannot calculate a percentile of no values")
    if not 0.0 <= probability <= 1.0:
        raise DistanceAnalysisError("percentile probability must be in [0,1]")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def bootstrap_seed_for(base_seed: int, label: str) -> int:
    digest = hashlib.sha256(f"{base_seed}:{label}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def bootstrap_intervals(
    observations: Sequence[Observation],
    reps: int,
    seed: int,
) -> dict[str, float | int | None]:
    if not observations:
        return {
            "tpr_low": None,
            "tpr_high": None,
            "censor_low": None,
            "censor_high": None,
            "delay_low": None,
            "delay_high": None,
            "delay_valid_reps": 0,
        }
    if reps <= 0:
        return {
            "tpr_low": None,
            "tpr_high": None,
            "censor_low": None,
            "censor_high": None,
            "delay_low": None,
            "delay_high": None,
            "delay_valid_reps": 0,
        }
    blocks: dict[int, list[Observation]] = defaultdict(list)
    for observation in observations:
        blocks[observation.seed].append(observation)
    seeds = sorted(blocks)
    rng = random.Random(seed)
    tprs: list[float] = []
    censor_fractions: list[float] = []
    delays: list[float] = []
    for _ in range(reps):
        sampled: list[Observation] = []
        for _block in seeds:
            sampled.extend(blocks[rng.choice(seeds)])
        tprs.append(sum(item.alert for item in sampled) / len(sampled))
        censor_fractions.append(sum(item.censored for item in sampled) / len(sampled))
        detected_delays = [
            item.delay_s for item in sampled if item.delay_s is not None
        ]
        if detected_delays:
            delays.append(statistics.median(detected_delays))
    return {
        "tpr_low": percentile(tprs, 0.025),
        "tpr_high": percentile(tprs, 0.975),
        "censor_low": percentile(censor_fractions, 0.025),
        "censor_high": percentile(censor_fractions, 0.975),
        "delay_low": percentile(delays, 0.025) if delays else None,
        "delay_high": percentile(delays, 0.975) if delays else None,
        "delay_valid_reps": len(delays),
    }


def format_float(value: float | int | None) -> str:
    if value is None:
        return ""
    return format(float(value), ".12g")


def summarize(
    observations: Sequence[Observation],
    stage: str,
    family: str,
    bootstrap_reps: int,
    bootstrap_seed: int,
) -> list[dict[str, object]]:
    attacks = sorted({observation.attack for observation in observations})
    rows: list[dict[str, object]] = []
    for stratum in (*attacks, "pooled"):
        stratum_rows = [
            item
            for item in observations
            if stratum == "pooled" or item.attack == stratum
        ]
        for spec in BINS:
            selected = [
                item for item in stratum_rows if distance_bin(item.mean_distance_m) == spec
            ]
            detected = [item for item in selected if item.alert]
            detected_delays = [
                item.delay_s for item in detected if item.delay_s is not None
            ]
            label = f"{stage}/{family}/{stratum}/{spec.label}"
            intervals = bootstrap_intervals(
                selected,
                bootstrap_reps,
                bootstrap_seed_for(bootstrap_seed, label),
            )
            pair_count = len(selected)
            message_count = sum(item.malicious_messages for item in selected)
            distance_total = sum(item.distance_sum_m for item in selected)
            row: dict[str, object] = {
                "stage": stage,
                "family": family,
                "attack_stratum": stratum,
                "distance_bin": spec.label,
                "distance_interval": spec.interval,
                "pair_count": pair_count,
                "seed_count": len({item.seed for item in selected}),
                "received_malicious_messages": message_count,
                "message_weighted_mean_distance_m": format_float(
                    distance_total / message_count if message_count else None
                ),
                "median_pair_mean_distance_m": format_float(
                    statistics.median(item.mean_distance_m for item in selected)
                    if selected
                    else None
                ),
                "detected_pair_count": len(detected),
                "tpr": format_float(len(detected) / pair_count if pair_count else None),
                "tpr_ci95_low": format_float(intervals["tpr_low"]),
                "tpr_ci95_high": format_float(intervals["tpr_high"]),
                "censored_pair_count": sum(item.censored for item in selected),
                "censor_fraction": format_float(
                    sum(item.censored for item in selected) / pair_count
                    if pair_count
                    else None
                ),
                "censor_fraction_ci95_low": format_float(intervals["censor_low"]),
                "censor_fraction_ci95_high": format_float(intervals["censor_high"]),
                "median_detected_delay_s": format_float(
                    statistics.median(detected_delays) if detected_delays else None
                ),
                "median_detected_delay_ci95_low_s": format_float(
                    intervals["delay_low"]
                ),
                "median_detected_delay_ci95_high_s": format_float(
                    intervals["delay_high"]
                ),
                "delay_bootstrap_valid_reps": intervals["delay_valid_reps"],
                "bootstrap_reps": bootstrap_reps,
                "bootstrap_seed": bootstrap_seed,
                "ci_method": CI_METHOD,
                "distance_statistic": DISTANCE_STATISTIC,
                "distance_estimand": DISTANCE_ESTIMAND,
                "delay_estimand": DELAY_ESTIMAND,
            }
            rows.append(row)
    return rows


def discover_traces(inputs: Sequence[Path], pattern: str) -> list[Path]:
    found: dict[Path, Path] = {}
    for entry in inputs:
        if entry.is_file():
            candidates: Iterable[Path] = (entry,)
        elif entry.is_dir():
            candidates = entry.glob(pattern)
        else:
            raise DistanceAnalysisError(f"trace input does not exist: {entry}")
        for candidate in candidates:
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
            found.setdefault(resolved, candidate)
    if not found:
        raise DistanceAnalysisError("no trace files discovered")
    return sorted(found)


def write_output(path: Path, rows: Sequence[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            writer = csv.DictWriter(
                handle,
                fieldnames=OUTPUT_FIELDS,
                extrasaction="raise",
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except OSError as exc:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
        raise DistanceAnalysisError(f"cannot write {path}: {exc}") from exc


def analyze(
    trace_inputs: Sequence[Path],
    pattern: str,
    metadata_name: str,
    pairs_name: str,
    stage: str,
    family: str,
    bootstrap_reps: int,
    bootstrap_seed: int,
) -> list[dict[str, object]]:
    if bootstrap_reps < 0:
        raise DistanceAnalysisError("bootstrap repetitions must be nonnegative")
    traces = discover_traces(trace_inputs, pattern)
    configs: list[RunConfig] = []
    for trace in traces:
        config = load_config(trace, metadata_name, pairs_name, stage, family)
        if config is not None:
            configs.append(config)
    if not configs:
        raise DistanceAnalysisError(
            f"no traces matched held-out partition {stage}/{family}"
        )

    seen_runs: set[tuple[str, int]] = set()
    expected_compatibility = configs[0].compatibility_options
    for config in configs:
        run_key = (config.attack, config.seed)
        if run_key in seen_runs:
            raise DistanceAnalysisError(
                f"duplicate attack/seed run across inputs: {run_key}"
            )
        seen_runs.add(run_key)
        if config.compatibility_options != expected_compatibility:
            raise DistanceAnalysisError(
                f"{config.command}: simulator metadata is incompatible with "
                f"{configs[0].command}"
            )

    observations: list[Observation] = []
    for config in sorted(configs, key=lambda item: (item.attack, item.seed)):
        observations.extend(join_run(config))
    if not observations:
        raise DistanceAnalysisError("no eligible hostile rows after trace/pair join")
    return summarize(
        observations,
        stage,
        family,
        bootstrap_reps,
        bootstrap_seed,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--traces",
        type=Path,
        action="append",
        required=True,
        help="trace.csv file or directory (repeatable)",
    )
    parser.add_argument(
        "--pattern",
        default="**/trace.csv",
        help="glob used below each --traces directory",
    )
    parser.add_argument("--metadata-name", default="command.json")
    parser.add_argument("--pairs-name", default="pairs.csv")
    parser.add_argument("--stage", default="test")
    parser.add_argument("--family", default="pure_attack")
    parser.add_argument("--bootstrap-reps", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260803)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    parser_args = parse_args(argv)
    try:
        rows = analyze(
            parser_args.traces,
            parser_args.pattern,
            parser_args.metadata_name,
            parser_args.pairs_name,
            parser_args.stage,
            parser_args.family,
            parser_args.bootstrap_reps,
            parser_args.bootstrap_seed,
        )
        write_output(parser_args.output, rows)
    except DistanceAnalysisError as exc:
        raise SystemExit(f"distance analysis failed: {exc}") from exc
    populated = sum(int(row["pair_count"]) > 0 for row in rows)
    print(
        f"Wrote {len(rows)} rows ({populated} populated bins) to "
        f"{parser_args.output}"
    )
    print(f"Estimand: {DISTANCE_ESTIMAND}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
