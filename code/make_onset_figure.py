#!/usr/bin/env python3
"""Reconstruct and plot sequential evidence around constant-offset onset.

The reception trace contains the exact detector-observable BSM fields but does
not contain the decision score.  This script replays the identity-keyed checks
and evidence accumulator using each run's ``command.json`` metadata, validates
the reconstructed operating-point decisions against the sibling pair artifact,
and aggregates curves at the RNG-seed level.  Oracle fields are used only to
separate assigned constant-offset senders from honest reference senders.

Examples
--------
Build the two-panel publication figure from a completed experiment directory::

    python3 make_onset_figure.py --traces results/current/full/runs \
      --metrics results/current/full/analysis/metrics.csv \
      --output figures/fig_onset.pdf

One invocation writes both ``fig_onset.pdf`` and ``fig_onset.png``, whichever
suffix ``--output`` names, so the vector figure the manuscript loads and the
raster preview cannot drift apart.

Pass individual trace files by repeating ``--traces``::

    python3 make_onset_figure.py --traces run_a/trace.csv \
      --traces run_b/trace.csv --output /tmp/onset.png
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import sys
import tempfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

try:
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError as exc:
    raise SystemExit(f"make_onset_figure.py requires numpy and matplotlib: {exc}") from exc

import figstyle
from figstyle import MUTED, RULE, SURFACE

# Both panels reserve the same strip above the axes, so the titles share a line
# whether or not a panel carries a legend.
LEGEND_ANCHOR = (0.0, 1.02)
TITLE_PAD = 26

try:  # scipy is already used by aggregate.py; retain a transparent fallback.
    from scipy.stats import t as student_t
except ImportError:  # pragma: no cover - exercised only in minimal environments
    student_t = None


class OnsetError(RuntimeError):
    """Raised when traces or their simulator provenance are inconsistent."""


TRACE_REQUIRED = {
    "receiver_id",
    "rx_time",
    "claimed_id",
    "claimed_seq",
    "claimed_tx_time",
    "claimed_x",
    "claimed_y",
    "claimed_vx",
    "claimed_vy",
    "oracle_tx_time",
    "oracle_source_is_attacker",
    "oracle_attack_active",
    "oracle_message_is_malicious",
}

CPP_CONSTANTS = (
    "VMAX",
    "SPEED_TOL",
    "MAX_AGE",
    "RATE_WINDOW",
    "RATE_LIMIT",
    "ROAD_LEN",
    "ROAD_WIDTH",
    "LOG_EVIDENCE_CLAMP",
    "MIN_REF_DT",
    "HEADING_COS_MIN",
)
CHECK_COUNT = 7

DATA_FIELDS = (
    "relative_time_s",
    "cohort",
    "mean_score",
    "ci95_low",
    "ci95_high",
    "seed_n",
    "reception_count",
    "threshold",
    "score_model",
    "detector_source_sha256",
)


def finite(value: str | float | int, context: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise OnsetError(f"{context}: expected a number, got {value!r}") from exc
    if not math.isfinite(result):
        raise OnsetError(f"{context}: expected a finite number, got {value!r}")
    return result


def integer(value: str | int, context: str, minimum: int = 0) -> int:
    result = finite(value, context)
    if not result.is_integer() or result < minimum:
        raise OnsetError(
            f"{context}: expected an integer >= {minimum}, got {value!r}"
        )
    return int(result)


def boolean(value: str | int, context: str) -> bool:
    text = str(value).strip().lower()
    if text in {"1", "true"}:
        return True
    if text in {"0", "false"}:
        return False
    raise OnsetError(f"{context}: expected 0/1 or false/true, got {value!r}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise OnsetError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


@dataclass(frozen=True)
class DetectorSource:
    constants: dict[str, float]
    models: dict[str, tuple[tuple[float, float], ...]]
    source_hash: str


def parse_detector_source(path: Path) -> DetectorSource:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OnsetError(f"cannot read detector source {path}: {exc}") from exc
    constants: dict[str, float] = {}
    for name in CPP_CONSTANTS:
        match = re.search(
            rf"static\s+const\s+double\s+{re.escape(name)}\s*=\s*"
            rf"([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)\s*;",
            text,
        )
        if not match:
            raise OnsetError(f"{path}: could not parse detector constant {name}")
        constants[name] = finite(match.group(1), f"{path}/{name}")

    models: dict[str, tuple[tuple[float, float], ...]] = {}
    number = r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?"
    for cli_name, cpp_name in (("reference", "g_checkReference"),
                               ("simfit", "g_checkSimfit")):
        block = re.search(
            rf"static\s+const\s+CheckModel\s+{cpp_name}\[CHK_COUNT\]\s*=\s*"
            rf"\{{(.*?)\}}\s*;",
            text,
            re.DOTALL,
        )
        if not block:
            raise OnsetError(f"{path}: could not parse {cpp_name}")
        entries = re.findall(
            rf"\{{\s*({number})\s*,\s*({number})\s*,\s*S_[A-Z_]+\s*\}}",
            block.group(1),
        )
        if len(entries) != CHECK_COUNT:
            raise OnsetError(
                f"{path}: {cpp_name} has {len(entries)} parsed checks, "
                f"expected {CHECK_COUNT}"
            )
        values = tuple((float(d), float(f)) for d, f in entries)
        if any(not (0.0 < d < 1.0 and 0.0 < f < 1.0) for d, f in values):
            raise OnsetError(f"{path}: {cpp_name} d/f values must lie in (0,1)")
        models[cli_name] = values
    return DetectorSource(constants, models, sha256(path))


def command_options(path: Path) -> tuple[dict[str, str], dict]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OnsetError(f"cannot read simulator metadata {path}: {exc}") from exc
    argv = document.get("command_argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        raise OnsetError(f"{path}: command_argv must be a non-empty string list")
    options: dict[str, str] = {}
    for argument in argv[1:]:
        if not argument.startswith("--") or "=" not in argument:
            continue
        name, value = argument[2:].split("=", 1)
        if name in options:
            raise OnsetError(f"{path}: duplicate simulator option --{name}")
        options[name] = value
    required = {
        "nVehicles", "attackerFraction", "attack", "run", "simTime",
        "warmup", "attackStart", "onsetBlank", "interval", "detector",
        "scoreModel", "nullEvidence", "naiveThresholds", "prior", "threshold",
        "decayHalfLife", "commRange", "gpsSigma", "detectorGpsSigma",
        "mobility", "spdSigma", "clockSigma", "bsmBytes",
    }
    missing = required.difference(options)
    if missing:
        raise OnsetError(f"{path}: missing simulator options {sorted(missing)}")
    return options, document


@dataclass(frozen=True)
class RunConfig:
    trace: Path
    command: Path
    seed: int
    experiment_id: str
    stage: str
    family: str
    arm: str
    warmup: float
    attack_start: float
    onset_blank: float
    prior: float
    threshold: float
    half_life: float
    detector_gps_sigma: float
    speed_sigma: float
    null_evidence: bool
    naive_thresholds: bool
    score_model: str
    compatibility_options: tuple[tuple[str, str], ...]

    @property
    def eval_start(self) -> float:
        return max(self.warmup, self.attack_start + self.onset_blank)

    def compatibility_key(self) -> tuple[object, ...]:
        # Every simulator option except RNG run and output paths must match.
        # This catches scenario drift (vehicle count, attacker fraction, actual
        # GNSS noise, mobility, radio range, clock offset, etc.) as well as
        # detector drift.  Comparing only the handful of replayed parameters
        # would silently pool heterogeneous trajectories.
        return (self.stage, self.family, self.arm, self.compatibility_options)


def experiment_coordinates(
    document: dict, trace: Path
) -> tuple[str, str, str, str, int]:
    experiment_id = str(document.get("experiment_id", trace.parent.name)).strip()
    parts = experiment_id.split("__")
    if len(parts) != 4 or not all(parts[:3]):
        raise OnsetError(
            f"{trace}: experiment_id must be stage__family__arm__seed_NNNN, "
            f"got {experiment_id!r}"
        )
    match = re.fullmatch(r"seed_([0-9]+)", parts[3])
    if not match:
        raise OnsetError(f"{trace}: malformed seed suffix in {experiment_id!r}")
    return experiment_id, parts[0], parts[1], parts[2], int(match.group(1))


def load_run_config(
    trace: Path,
    metadata_name: str,
    trajectory_stage: str,
    trajectory_family: str,
    trajectory_arm: str,
) -> RunConfig | None:
    command = trace.with_name(metadata_name)
    if not command.is_file():
        raise OnsetError(f"{trace}: sibling {metadata_name} is missing")
    options, document = command_options(command)
    experiment_id, stage, family, arm, id_seed = experiment_coordinates(document, trace)
    if (stage, family, arm) != (
        trajectory_stage, trajectory_family, trajectory_arm
    ):
        return None
    if options["attack"].strip().lower() != "constoffset":
        raise OnsetError(
            f"{command}: selected trajectory arm must use attack=constoffset"
        )
    if not boolean(options["detector"], f"{command}/detector"):
        raise OnsetError(f"{command}: detector must be enabled for score replay")
    attack_start = finite(options["attackStart"], f"{command}/attackStart")
    if attack_start <= 0.0:
        # A steady-state arm has no retained pre-onset period and therefore
        # cannot answer the temporal question represented by this figure.
        return None
    seed = integer(options["run"], f"{command}/run", 1)
    if id_seed != seed:
        raise OnsetError(f"{command}: experiment_id seed differs from --run")
    if "seed" in document and integer(document["seed"], f"{command}/seed", 1) != seed:
        raise OnsetError(f"{command}: metadata seed differs from --run")
    score_model = options["scoreModel"].strip().lower()
    prior = finite(options["prior"], f"{command}/prior")
    threshold = finite(options["threshold"], f"{command}/threshold")
    if not 0.0 < prior < 1.0 or not 0.0 < threshold < 1.0:
        raise OnsetError(f"{command}: prior and threshold must lie inside (0,1)")
    half_life = finite(options["decayHalfLife"], f"{command}/decayHalfLife")
    if half_life != -1.0 and half_life <= 0.0:
        raise OnsetError(f"{command}: decayHalfLife must be positive or -1")
    per_run_or_output = {"run", "pairOutput", "trace"}
    compatibility_options = tuple(
        sorted(
            (name, value.strip())
            for name, value in options.items()
            if name not in per_run_or_output
        )
    )
    return RunConfig(
        trace=trace,
        command=command,
        seed=seed,
        experiment_id=experiment_id,
        stage=stage,
        family=family,
        arm=arm,
        warmup=finite(options["warmup"], f"{command}/warmup"),
        attack_start=attack_start,
        onset_blank=finite(options["onsetBlank"], f"{command}/onsetBlank"),
        prior=prior,
        threshold=threshold,
        half_life=half_life,
        detector_gps_sigma=finite(
            options["detectorGpsSigma"], f"{command}/detectorGpsSigma"
        ),
        speed_sigma=finite(options["spdSigma"], f"{command}/spdSigma"),
        null_evidence=boolean(options["nullEvidence"], f"{command}/nullEvidence"),
        naive_thresholds=boolean(
            options["naiveThresholds"], f"{command}/naiveThresholds"
        ),
        score_model=score_model,
        compatibility_options=compatibility_options,
    )


@dataclass
class NeighborState:
    have: bool = False
    last_tx_time: float = 0.0
    seen_seq: set[int] = field(default_factory=set)
    seq_fifo: deque[int] = field(default_factory=deque)
    rx_times: deque[float] = field(default_factory=deque)
    log_evidence: float = 0.0
    have_evidence_update: bool = False
    last_evidence_update: float = 0.0
    ref_valid: bool = False
    ref_x: float = 0.0
    ref_y: float = 0.0
    ref_time: float = 0.0
    warm_reset: bool = False


class EvidenceReplay:
    def __init__(self, config: RunConfig, source: DetectorSource) -> None:
        if config.score_model not in source.models:
            raise OnsetError(
                f"{config.command}: unknown scoreModel {config.score_model!r}; "
                f"source exposes {sorted(source.models)}"
            )
        self.config = config
        self.constants = source.constants
        self.check_model = source.models[config.score_model]
        self.initial_log = math.log(config.prior / (1.0 - config.prior))
        self.states: dict[tuple[int, int], NeighborState] = {}
        self.window_peaks: dict[tuple[int, int], float] = {}

    def decay(self, delta_time: float) -> float:
        if self.config.half_life < 0.0 or delta_time <= 0.0:
            return 1.0
        return math.exp(-math.log(2.0) * delta_time / self.config.half_life)

    def assess(self, row: dict[str, str], context: str) -> tuple[float, tuple[bool, ...]]:
        receiver = integer(row["receiver_id"], f"{context}/receiver_id")
        claimed = integer(row["claimed_id"], f"{context}/claimed_id")
        sequence = integer(row["claimed_seq"], f"{context}/claimed_seq")
        now = finite(row["rx_time"], f"{context}/rx_time")
        tx_time = finite(row["claimed_tx_time"], f"{context}/claimed_tx_time")
        x = finite(row["claimed_x"], f"{context}/claimed_x")
        y = finite(row["claimed_y"], f"{context}/claimed_y")
        vx = finite(row["claimed_vx"], f"{context}/claimed_vx")
        vy = finite(row["claimed_vy"], f"{context}/claimed_vy")
        key = (receiver, claimed)
        state = self.states.get(key)
        if state is None:
            state = NeighborState(log_evidence=self.initial_log)
            self.states[key] = state
        if not state.have:
            state.log_evidence = self.initial_log
        if not state.warm_reset and now >= self.config.warmup:
            state.log_evidence = self.initial_log
            state.have_evidence_update = False
            state.last_evidence_update = 0.0
            state.warm_reset = True

        c = self.constants
        fired = [False] * CHECK_COUNT
        # Same order as enum Check in the simulator source.
        fired[5] = x < -50.0 or x > c["ROAD_LEN"] + 50.0 or abs(y) > c["ROAD_WIDTH"]
        fired[2] = now - tx_time > c["MAX_AGE"]
        if state.have:
            fired[3] = sequence in state.seen_seq or tx_time <= state.last_tx_time

        if state.ref_valid:
            dt = tx_time - state.ref_time
            reference_minimum = 1e-6 if self.config.naive_thresholds else c["MIN_REF_DT"]
            if dt >= reference_minimum:
                dx, dy = x - state.ref_x, y - state.ref_y
                sigma_v = math.sqrt(2.0) * self.config.detector_gps_sigma / dt
                jump_tolerance = c["VMAX"] if self.config.naive_thresholds else (
                    c["VMAX"] + 3.0 * sigma_v
                )
                speed_tolerance = c["SPEED_TOL"] if self.config.naive_thresholds else (
                    c["SPEED_TOL"]
                    + 3.0 * math.sqrt(sigma_v * sigma_v + self.config.speed_sigma ** 2)
                )
                displacement = math.hypot(dx, dy)
                implied = displacement / dt
                asserted = math.hypot(vx, vy)
                fired[0] = implied > jump_tolerance
                fired[1] = abs(implied - asserted) > speed_tolerance
                if displacement > 3.0 * self.config.detector_gps_sigma and asserted > 1.0:
                    cosine = (dx * vx + dy * vy) / (displacement * asserted)
                    fired[6] = cosine < c["HEADING_COS_MIN"]
                state.ref_x, state.ref_y, state.ref_time = x, y, tx_time
        else:
            state.ref_x, state.ref_y, state.ref_time = x, y, tx_time
            state.ref_valid = True

        state.rx_times.append(now)
        while state.rx_times and state.rx_times[0] < now - c["RATE_WINDOW"]:
            state.rx_times.popleft()
        fired[4] = len(state.rx_times) / c["RATE_WINDOW"] > c["RATE_LIMIT"]

        delta = max(0.0, now - state.last_evidence_update) if (
            state.have_evidence_update
        ) else 0.0
        factor = self.decay(delta) if state.have_evidence_update else 1.0
        clamp = c["LOG_EVIDENCE_CLAMP"]
        bounded = max(-clamp, min(clamp, state.log_evidence))
        log_evidence = factor * bounded + (1.0 - factor) * self.initial_log
        for index, (detection_rate, false_rate) in enumerate(self.check_model):
            if fired[index]:
                log_evidence += math.log(detection_rate / false_rate)
            elif self.config.null_evidence:
                log_evidence += math.log(
                    (1.0 - detection_rate) / (1.0 - false_rate)
                )
        log_evidence = max(-clamp, min(clamp, log_evidence))
        state.log_evidence = log_evidence
        state.have_evidence_update = True
        state.last_evidence_update = now
        score = 1.0 / (1.0 + math.exp(-log_evidence))

        state.have = True
        state.last_tx_time = max(state.last_tx_time, tx_time)
        if sequence not in state.seen_seq:
            state.seen_seq.add(sequence)
            state.seq_fifo.append(sequence)
        if len(state.seq_fifo) > 500:
            state.seen_seq.remove(state.seq_fifo.popleft())
        if now >= self.config.eval_start:
            self.window_peaks[key] = max(self.window_peaks.get(key, 0.0), score)
        return score, tuple(fired)


@dataclass
class RunCurve:
    config: RunConfig
    centers: np.ndarray
    attacker_sum: np.ndarray
    attacker_count: np.ndarray
    honest_sum: np.ndarray
    honest_count: np.ndarray
    replay: EvidenceReplay | None
    total_rows: int
    attacker_rows: int
    malicious_rows: int

    def means(self, cohort: str) -> np.ndarray:
        sums, counts = (
            (self.attacker_sum, self.attacker_count)
            if cohort == "assigned_constoffset_sender"
            else (self.honest_sum, self.honest_count)
        )
        result = np.full_like(sums, np.nan, dtype=float)
        np.divide(sums, counts, out=result, where=counts > 0)
        return result

    def release_replay_state(self) -> None:
        """Release per-key histories once provenance validation is complete."""

        if self.replay is not None:
            self.replay.states.clear()
            self.replay.window_peaks.clear()
            self.replay = None


def iter_trace(path: Path) -> Iterable[tuple[int, dict[str, str]]]:
    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError as exc:
        raise OnsetError(f"cannot open trace {path}: {exc}") from exc
    reader = csv.DictReader(handle)
    header = reader.fieldnames or []
    if len(header) != len(set(header)):
        handle.close()
        raise OnsetError(f"{path}: duplicate trace field")
    missing = TRACE_REQUIRED.difference(header)
    if missing:
        handle.close()
        raise OnsetError(f"{path}: missing trace fields {sorted(missing)}")

    def generate() -> Iterable[tuple[int, dict[str, str]]]:
        try:
            for line_no, row in enumerate(reader, 2):
                if None in row or any(value is None for value in row.values()):
                    raise OnsetError(f"{path}:{line_no}: trace row width mismatch")
                yield line_no, row
        finally:
            handle.close()

    return generate()


def reconstruct_run(
    config: RunConfig,
    source: DetectorSource,
    before: float,
    after: float,
    width: float,
) -> RunCurve:
    edges = np.arange(-before, after + width * 1.000001, width, dtype=float)
    if edges[-1] < after:
        edges = np.append(edges, after)
    centers = (edges[:-1] + edges[1:]) / 2.0
    attacker_sum = np.zeros(len(centers), dtype=float)
    attacker_count = np.zeros(len(centers), dtype=np.int64)
    honest_sum = np.zeros(len(centers), dtype=float)
    honest_count = np.zeros(len(centers), dtype=np.int64)
    replay = EvidenceReplay(config, source)
    previous_time = -math.inf
    total_rows = attacker_rows = malicious_rows = 0
    attacker_pre = attacker_post = 0

    for line_no, row in iter_trace(config.trace):
        context = f"{config.trace}:{line_no}"
        now = finite(row["rx_time"], f"{context}/rx_time")
        if now + 1e-12 < previous_time:
            raise OnsetError(f"{context}: trace reception times are not monotone")
        previous_time = now
        source_attacker = boolean(
            row["oracle_source_is_attacker"],
            f"{context}/oracle_source_is_attacker",
        )
        attack_active = boolean(
            row["oracle_attack_active"], f"{context}/oracle_attack_active"
        )
        malicious = boolean(
            row["oracle_message_is_malicious"],
            f"{context}/oracle_message_is_malicious",
        )
        oracle_tx = finite(row["oracle_tx_time"], f"{context}/oracle_tx_time")
        if malicious and (not source_attacker or not attack_active):
            raise OnsetError(
                f"{context}: malicious message lacks assigned/active attacker provenance"
            )
        if attack_active and oracle_tx + 1e-9 < config.attack_start:
            raise OnsetError(f"{context}: attack-active message predates configured onset")
        score, _checks = replay.assess(row, context)
        if not 0.0 <= score <= 1.0:
            raise OnsetError(f"{context}: reconstructed score outside [0,1]")
        total_rows += 1
        attacker_rows += int(source_attacker)
        malicious_rows += int(malicious)
        if source_attacker:
            attacker_pre += int(oracle_tx < config.attack_start)
            attacker_post += int(oracle_tx >= config.attack_start)

        relative = now - config.attack_start
        if relative < -before or relative > after:
            continue
        index = int(math.floor((relative + before) / width))
        if index == len(centers) and math.isclose(relative, after, abs_tol=1e-9):
            index -= 1
        if not 0 <= index < len(centers):
            continue
        if source_attacker:
            attacker_sum[index] += score
            attacker_count[index] += 1
        else:
            honest_sum[index] += score
            honest_count[index] += 1

    if total_rows == 0:
        raise OnsetError(f"{config.trace}: trace contains no receptions")
    if attacker_rows == 0 or attacker_pre == 0 or attacker_post == 0:
        raise OnsetError(
            f"{config.trace}: assigned attacker lacks retained pre/post-onset observations"
        )
    if malicious_rows == 0:
        raise OnsetError(f"{config.trace}: no malicious constant-offset messages observed")
    if not np.any(attacker_count) or not np.any(honest_count):
        raise OnsetError(f"{config.trace}: requested plotting window has empty cohort")
    return RunCurve(
        config, centers, attacker_sum, attacker_count, honest_sum, honest_count,
        replay, total_rows, attacker_rows, malicious_rows,
    )


def validate_pairs(
    curve: RunCurve, pair_name: str, peak_tolerance: float
) -> tuple[int, int, float]:
    path = curve.config.trace.with_name(pair_name)
    if not path.is_file():
        raise OnsetError(
            f"{curve.config.trace}: sibling {pair_name} is required for replay "
            "validation (or pass --skip-pair-validation explicitly)"
        )
    if curve.replay is None:
        raise OnsetError("pair validation requested after replay state was released")
    required = {
        "receiver_id", "claimed_id", "eligible", "window_peak_score", "window_alert"
    }
    compared = decision_mismatches = 0
    max_difference = 0.0
    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError as exc:
        raise OnsetError(f"cannot read pair validation artifact {path}: {exc}") from exc
    with handle:
        reader = csv.DictReader(handle)
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise OnsetError(f"{path}: pair validation fields missing {sorted(missing)}")
        for line_no, row in enumerate(reader, 2):
            if None in row or any(value is None for value in row.values()):
                raise OnsetError(f"{path}:{line_no}: pair row width mismatch")
            if not boolean(row["eligible"], f"{path}:{line_no}/eligible"):
                continue
            key = (
                integer(row["receiver_id"], f"{path}:{line_no}/receiver_id"),
                integer(row["claimed_id"], f"{path}:{line_no}/claimed_id"),
            )
            if key not in curve.replay.window_peaks:
                raise OnsetError(f"{path}:{line_no}: eligible pair absent from trace replay")
            expected = finite(
                row["window_peak_score"], f"{path}:{line_no}/window_peak_score"
            )
            actual = curve.replay.window_peaks[key]
            difference = abs(actual - expected)
            max_difference = max(max_difference, difference)
            if difference > peak_tolerance:
                raise OnsetError(
                    f"{path}:{line_no}: reconstructed window peak differs by "
                    f"{difference:.12g}, exceeding tolerance {peak_tolerance:.12g}"
                )
            expected_alert = boolean(
                row["window_alert"], f"{path}:{line_no}/window_alert"
            )
            decision_mismatches += int((actual > curve.config.threshold) != expected_alert)
            compared += 1
    if compared == 0:
        raise OnsetError(f"{path}: no eligible pair decisions were available to validate")
    return compared, decision_mismatches, max_difference


def seed_curve_statistics(
    curves: Sequence[RunCurve], cohort: str
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    matrix = np.vstack([curve.means(cohort) for curve in curves])
    bins = matrix.shape[1]
    means = np.full(bins, np.nan)
    lows = np.full(bins, np.nan)
    highs = np.full(bins, np.nan)
    seed_n = np.zeros(bins, dtype=np.int64)
    for index in range(bins):
        values = matrix[:, index]
        values = values[np.isfinite(values)]
        seed_n[index] = len(values)
        if not len(values):
            continue
        means[index] = float(np.mean(values))
        if len(values) >= 2:
            critical = (
                float(student_t.ppf(0.975, len(values) - 1))
                if student_t is not None else 1.96
            )
            half_width = critical * float(np.std(values, ddof=1)) / math.sqrt(len(values))
            lows[index] = max(0.0, means[index] - half_width)
            highs[index] = min(1.0, means[index] + half_width)
    counts = sum(
        curve.attacker_count if cohort == "assigned_constoffset_sender"
        else curve.honest_count
        for curve in curves
    )
    return means, lows, highs, seed_n, counts


@dataclass(frozen=True)
class GuardPoint:
    guard_s: float
    estimate: float
    low: float
    high: float
    arm: str


def guard_value(arm: str) -> float | None:
    match = re.search(r"(?:^|_)guard_([0-9]+(?:p[0-9]+)?)$", arm)
    if not match:
        return None
    return float(match.group(1).replace("p", "."))


def metric_interval(
    row: dict[str, str], value_field: str, context: str
) -> tuple[float, float, float]:
    """Read an estimate and CI, collapsing unavailable one-seed CIs to a point."""

    estimate = finite(row[value_field], f"{context}/{value_field}")
    bounds: list[float] = []
    for field in ("ci95_low", "ci95_high"):
        try:
            value = float(row[field])
        except (TypeError, ValueError) as exc:
            raise OnsetError(f"{context}/{field}: expected a number") from exc
        if math.isnan(value):
            value = estimate
        elif not math.isfinite(value):
            raise OnsetError(f"{context}/{field}: expected a finite value or nan")
        bounds.append(value)
    low, high = bounds
    if low > estimate or high < estimate or low > high:
        raise OnsetError(
            f"{context}: invalid interval [{low}, {high}] around {estimate}"
        )
    return estimate, low, high


def read_guard_metrics(
    path: Path | None,
    metric_name: str,
    guard_stage: str,
    guard_family: str,
    guard_arm_prefix: str,
    baseline_family: str,
    baseline_arm: str,
) -> list[GuardPoint]:
    if path is None:
        return []
    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError as exc:
        raise OnsetError(f"cannot open aggregate metrics {path}: {exc}") from exc
    with handle:
        reader = csv.DictReader(handle)
        header = set(reader.fieldnames or [])
        required = {"stage", "family", "arm", "metric", "ci95_low", "ci95_high"}
        if not required.issubset(header) or not ({"mean", "estimate"} & header):
            raise OnsetError(
                f"{path}: metrics require family/arm/metric, CI fields, and mean or estimate"
            )
        points: dict[float, GuardPoint] = {}
        baseline_candidates: list[dict[str, str]] = []
        for line_no, row in enumerate(reader, 2):
            if None in row or any(value is None for value in row.values()):
                raise OnsetError(f"{path}:{line_no}: metrics row width mismatch")
            if row["stage"] != guard_stage or row["metric"] != metric_name:
                continue
            if (
                row["family"] == guard_family
                and row["arm"].startswith(guard_arm_prefix)
            ):
                guard = guard_value(row["arm"])
                if guard is None:
                    continue
                if guard in points:
                    raise OnsetError(f"{path}: duplicate {metric_name} at guard={guard}")
                field = "mean" if row.get("mean", "") else "estimate"
                estimate, low, high = metric_interval(row, field, f"{path}:{line_no}")
                points[guard] = GuardPoint(
                    guard, estimate, low, high, row["arm"],
                )
            elif row["family"] == baseline_family:
                baseline_candidates.append(row)

        if points:
            matching = [
                row for row in baseline_candidates if row["arm"] == baseline_arm
            ]
            if len(matching) != 1:
                raise OnsetError(
                    f"{path}: expected exactly one {guard_stage}/{baseline_family}/"
                    f"{baseline_arm} baseline row for {metric_name}, found {len(matching)}"
                )
            chosen = matching[0]
            field = "mean" if chosen.get("mean", "") else "estimate"
            estimate, low, high = metric_interval(
                chosen, field, f"{path}/baseline"
            )
            points[0.0] = GuardPoint(
                0.0, estimate, low, high, chosen["arm"],
            )
        return [points[key] for key in sorted(points)]


def discover(inputs: Sequence[Path], pattern: str) -> list[Path]:
    paths: set[Path] = set()
    for value in inputs:
        if value.is_file():
            paths.add(value.resolve())
        elif value.is_dir():
            paths.update(path.resolve() for path in value.glob(pattern) if path.is_file())
        else:
            raise OnsetError(f"trace input does not exist: {value}")
    if not paths:
        raise OnsetError(f"no trace files found with pattern {pattern!r}")
    return sorted(paths)


def atomic_csv(path: Path, rows: Iterable[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=DATA_FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Replay detector evidence from raw constoffset traces and draw a "
            "grayscale-safe, seed-clustered onset/guard-sensitivity figure."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--traces", type=Path, action="append", required=True,
        help="Trace CSV or directory to search; repeatable.",
    )
    parser.add_argument(
        "--pattern", default="**/trace.csv",
        help="Glob used recursively beneath directory trace inputs.",
    )
    parser.add_argument(
        "--trajectory-stage", default="test",
        help="Experiment-id stage selected for the trajectory panel.",
    )
    parser.add_argument(
        "--trajectory-family", default="pure_attack",
        help="Experiment-id family selected for the trajectory panel.",
    )
    parser.add_argument(
        "--trajectory-arm", default="pure_constoffset",
        help="Experiment-id arm selected for the trajectory panel.",
    )
    parser.add_argument(
        "--output", type=Path, required=True,
        help="Figure path; the sibling .pdf and .png are both written.",
    )
    parser.add_argument(
        "--data-output", type=Path,
        help="Optional CSV containing the plotted seed-level means and CIs.",
    )
    parser.add_argument(
        "--metrics", type=Path,
        help="Optional long-form aggregate metrics CSV for the guard panel.",
    )
    parser.add_argument(
        "--detector-source", type=Path,
        default=Path(__file__).resolve().with_name("v2v_cybersecurity_v2.cc"),
        help="C++ source from which weights and check constants are parsed.",
    )
    parser.add_argument("--metadata-name", default="command.json")
    parser.add_argument("--pair-name", default="pairs.csv")
    parser.add_argument("--before", type=float, default=2.0, help="Seconds before onset.")
    parser.add_argument("--after", type=float, default=5.0, help="Seconds after onset.")
    parser.add_argument("--bin-width", type=float, default=0.10, help="Trajectory bin width in seconds.")
    parser.add_argument("--guard-metric", default="stream_tpr")
    parser.add_argument("--guard-stage", default="test")
    parser.add_argument("--guard-family", default="onset_guard")
    parser.add_argument(
        "--guard-arm-prefix", default="constoffset_guard_",
        help="Only guard arms with this prefix are plotted.",
    )
    parser.add_argument("--baseline-family", default="pure_attack")
    parser.add_argument(
        "--baseline-arm", default="pure_constoffset",
        help="Exact zero-guard baseline arm.",
    )
    parser.add_argument(
        "--peak-tolerance", type=float, default=1e-10,
        help="Maximum absolute replay/pair window-peak difference.",
    )
    parser.add_argument(
        "--skip-pair-validation", action="store_true",
        help="Do not compare reconstructed decisions with sibling pair CSVs.",
    )
    args = parser.parse_args(argv)
    if args.before <= 0.0 or args.after <= 0.0 or args.bin_width <= 0.0:
        parser.error("--before, --after, and --bin-width must be positive")
    if args.bin_width > args.before + args.after:
        parser.error("--bin-width cannot exceed the plotted interval")
    if not math.isfinite(args.peak_tolerance) or args.peak_tolerance < 0.0:
        parser.error("--peak-tolerance must be finite and non-negative")
    for name in (
        "trajectory_stage", "trajectory_family", "trajectory_arm",
        "guard_stage", "guard_family", "guard_arm_prefix",
        "baseline_family", "baseline_arm",
    ):
        if not getattr(args, name).strip():
            parser.error(f"--{name.replace('_', '-')} cannot be empty")
    return args


def draw(
    *,
    centers: np.ndarray,
    attacker: Sequence,
    honest: Sequence,
    threshold: float,
    guards: Sequence,
    guard_metric: str,
    before: float,
    after: float,
):
    """Draw the two-panel onset figure and return it.

    Separated from the trace replay in ``main`` so the layout can be re-rendered
    from a cached trajectory CSV without re-reading several GB of traces.

    Greys rather than hues throughout: this figure is designed to survive
    grayscale printing, and line style carries the same information as tone.
    """

    figstyle.apply()
    figure, (trajectory_axis, guard_axis) = plt.subplots(
        1, 2, figsize=(figstyle.WDOC, 3.30), gridspec_kw={"width_ratios": (1.55, 1.0)}
    )
    amean, alow, ahigh = attacker[0], attacker[1], attacker[2]
    hmean, hlow, hhigh = honest[0], honest[1], honest[2]
    trajectory_axis.fill_between(
        centers, alow, ahigh, color="0.78", alpha=0.75, linewidth=0.0
    )
    trajectory_axis.plot(
        centers, amean, color="black", linewidth=1.25, linestyle="-",
        label="Assigned constant-offset senders",
    )
    trajectory_axis.fill_between(
        centers, hlow, hhigh, color="0.92", alpha=0.75, linewidth=0.0
    )
    trajectory_axis.plot(
        centers, hmean, color="0.35", linewidth=1.0, linestyle="--",
        label="Honest senders",
    )
    trajectory_axis.axvline(0.0, color="0.15", linestyle=":", linewidth=0.9,
                            label="Attack activation")
    trajectory_axis.axhline(
        threshold, color="0.5", linestyle="-.", linewidth=0.85,
        label=rf"Decision threshold $\tau={threshold:.3f}$",
    )
    trajectory_axis.set_xlim(-before, after)
    trajectory_axis.set_ylim(0.0, 1.02)
    trajectory_axis.set_xlabel("Time relative to attack activation (s)")
    trajectory_axis.set_ylabel("Bounded evidence score")
    # The trajectory fills the upper right of its panel, so the legend goes
    # above the axes: in-panel there is nowhere it does not sit on the curve.
    trajectory_axis.legend(
        frameon=False, fontsize=6.6, loc="lower left",
        bbox_to_anchor=LEGEND_ANCHOR, ncol=2, columnspacing=1.4,
        handlelength=2.0, handletextpad=0.5, borderpad=0.0, labelspacing=0.3,
    )
    trajectory_axis.set_title("(a) Sequential evidence trajectory", pad=TITLE_PAD)

    if guards:
        x = np.array([point.guard_s for point in guards])
        y = np.array([point.estimate for point in guards])
        lower = np.array([max(0.0, point.estimate - point.low) for point in guards])
        upper = np.array([max(0.0, point.high - point.estimate) for point in guards])
        guard_axis.errorbar(
            x, y, yerr=np.vstack((lower, upper)), color="black", linestyle="-",
            marker="s", markersize=3.5, markerfacecolor="white",
            markeredgecolor="black", capsize=2.5, linewidth=1.0,
        )
        guard_axis.set_xlim(left=-0.05)
        guard_axis.set_ylim(0.0, min(1.02, max(0.2, float(np.max(upper + y)) * 1.15)))
    else:
        guard_axis.text(
            0.5, 0.5, "Guard-sensitivity\naggregate unavailable",
            ha="center", va="center", transform=guard_axis.transAxes, color=MUTED,
        )
        guard_axis.set_xlim(0.0, 1.0)
        guard_axis.set_ylim(0.0, 1.0)
    guard_axis.set_xlabel(r"Post-onset exclusion guard $g$ (s)")
    # "stream_tpr" -> "Stream TPR": sentence case, short tokens read as acronyms.
    # Shouting the whole label is a data-key artefact, not a journal axis label.
    words = " ".join(w.upper() if len(w) <= 3 else w
                     for w in guard_metric.split("_"))
    guard_axis.set_ylabel(words[:1].upper() + words[1:])
    # Same pad as (a) even without a legend, so the two titles share a line.
    guard_axis.set_title("(b) Constant-offset onset-guard sensitivity", pad=TITLE_PAD)

    for axis in (trajectory_axis, guard_axis):
        axis.grid(axis="y", color=RULE, linewidth=0.5)
        axis.set_axisbelow(True)
        for spine in ("top", "right"):
            axis.spines[spine].set_visible(False)
        for spine in ("left", "bottom"):
            axis.spines[spine].set_color(RULE)
        axis.tick_params(colors=MUTED, labelsize=6.6, length=3)

    figure.tight_layout(pad=0.5, w_pad=1.4)
    figstyle.assert_no_text_overlap(figure)
    return figure


def save_figure(figure, output: Path) -> Path:
    """Write `output` and its sibling in the other format, then close the figure.

    One invocation therefore refreshes both the PDF the manuscript loads and the
    PNG preview, which cannot drift apart.
    """

    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    for path in (output.with_suffix(".pdf"), output.with_suffix(".png")):
        figure.savefig(path, dpi=400, facecolor=SURFACE)
    plt.close(figure)
    return output


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    source = parse_detector_source(args.detector_source.resolve())
    discovered = discover(args.traces, args.pattern)
    configs: list[RunConfig] = []
    skipped = 0
    for trace in discovered:
        config = load_run_config(
            trace,
            args.metadata_name,
            args.trajectory_stage,
            args.trajectory_family,
            args.trajectory_arm,
        )
        if config is None:
            skipped += 1
            continue
        configs.append(config)
    if not configs:
        raise OnsetError(
            "no temporal constant-offset traces matched "
            f"{args.trajectory_stage}/{args.trajectory_family}/{args.trajectory_arm}"
        )
    seeds = [config.seed for config in configs]
    if len(seeds) != len(set(seeds)):
        duplicates = sorted(seed for seed in set(seeds) if seeds.count(seed) > 1)
        raise OnsetError(f"duplicate RNG seeds across selected traces: {duplicates}")
    reference_key = configs[0].compatibility_key()
    incompatible = [config.experiment_id for config in configs
                    if config.compatibility_key() != reference_key]
    if incompatible:
        raise OnsetError(
            "selected traces differ in detector/onset configuration: "
            + ", ".join(incompatible)
        )

    curves: list[RunCurve] = []
    validation_compared = validation_mismatches = 0
    maximum_peak_difference = math.nan
    for config in sorted(configs, key=lambda item: item.seed):
        curve = reconstruct_run(config, source, args.before, args.after, args.bin_width)
        if not args.skip_pair_validation:
            compared, mismatches, max_difference = validate_pairs(
                curve, args.pair_name, args.peak_tolerance
            )
            validation_compared += compared
            validation_mismatches += mismatches
            if math.isfinite(max_difference):
                maximum_peak_difference = (
                    max_difference
                    if not math.isfinite(maximum_peak_difference)
                    else max(maximum_peak_difference, max_difference)
                )
        curve.release_replay_state()
        curves.append(curve)
    if validation_mismatches:
        raise OnsetError(
            f"trace replay disagrees with {validation_mismatches}/{validation_compared} "
            "simulator operating-point decisions"
        )

    attacker = seed_curve_statistics(curves, "assigned_constoffset_sender")
    honest = seed_curve_statistics(curves, "honest_reference_sender")
    centers = curves[0].centers
    rows: list[dict[str, str]] = []
    for cohort, statistics_ in (
        ("assigned_constoffset_sender", attacker),
        ("honest_reference_sender", honest),
    ):
        means, lows, highs, seed_n, counts = statistics_
        for index, center in enumerate(centers):
            rows.append({
                "relative_time_s": f"{center:.12g}",
                "cohort": cohort,
                "mean_score": f"{means[index]:.12g}",
                "ci95_low": f"{lows[index]:.12g}",
                "ci95_high": f"{highs[index]:.12g}",
                "seed_n": str(int(seed_n[index])),
                "reception_count": str(int(counts[index])),
                "threshold": f"{configs[0].threshold:.12g}",
                "score_model": configs[0].score_model,
                "detector_source_sha256": source.source_hash,
            })
    if args.data_output:
        atomic_csv(args.data_output.resolve(), rows)

    guards = read_guard_metrics(
        args.metrics.resolve() if args.metrics else None,
        args.guard_metric,
        args.guard_stage,
        args.guard_family,
        args.guard_arm_prefix,
        args.baseline_family,
        args.baseline_arm,
    )
    if args.metrics and not guards:
        raise OnsetError(
            f"{args.metrics}: no {args.guard_stage}/{args.guard_family}/"
            f"{args.guard_arm_prefix}* guard rows for metric {args.guard_metric!r}"
        )
    figure = draw(
        centers=centers,
        attacker=attacker,
        honest=honest,
        threshold=configs[0].threshold,
        guards=guards,
        guard_metric=args.guard_metric,
        before=args.before,
        after=args.after,
    )
    output = save_figure(figure, args.output)
    peak_summary = (
        f"{maximum_peak_difference:.3g}"
        if math.isfinite(maximum_peak_difference) else "not checked"
    )
    print(
        f"wrote {output} from {len(curves)} independent RNG seeds "
        f"({validation_compared} pair decisions validated, "
        f"max peak reconstruction difference={peak_summary}; "
        f"skipped {skipped} traces outside the selected trajectory arm)"
    )
    if not guards:
        print("NOTE: guard panel has no aggregate points; pass --metrics when available.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OnsetError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
