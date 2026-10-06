#!/usr/bin/env python3
"""Streaming, seed-aware arm inventory and extended detector diagnostics.

The simulator's merged pair artifact can be several gigabytes.  This utility
therefore consumes summary and pair CSVs one row at a time; it never constructs
a DataFrame or retains individual pair rows.  Quartiles are estimated with the
P-squared online algorithm and are labelled as such in the output.

Examples
--------
Analyze a completed merged experiment::

    python3 extended_analysis.py \
      --summary results/current/full/summary.csv \
      --pairs results/current/full/pairs.csv \
      --output-dir results/current/full/analysis

Restrict a combined artifact to the held-out test partition::

    python3 extended_analysis.py --summary summary.csv --pairs pairs.csv \
      --stage test --output-dir analysis/test
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import random
import statistics
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence


class AnalysisError(RuntimeError):
    """Raised when an input artifact violates its declared contract."""


GROUP_FIELDS = ("mode", "stage", "family", "arm")
SUMMARY_REQUIRED = {
    "experiment_id",
    *GROUP_FIELDS,
    "seed",
    "serial",
    "n",
    "n_attackers",
    "sim_time",
    "eval_window_start_s",
    "pairs",
    "eligible_pairs",
    "track_capacity_dropped_messages",
}
PAIR_REQUIRED = {
    "experiment_id",
    *GROUP_FIELDS,
    "seed",
    "receiver_id",
    "claimed_id",
    "malicious_use",
    "clean_pair",
    "messages",
    "eligible",
    "window_msgs",
    "window_exposure_s",
    "window_alert",
    "stream_time_to_detect_s",
    "stream_censored",
    "track_count",
    "track_alert",
    "honest_track_alert",
    "owner_track_alert",
    "track_capacity_dropped_messages",
    "track_purity",
    "track_merges",
    "track_fragments",
    "track_id_switches",
    "stride_class",
    "stride_ambiguous",
}

INVENTORY_FIELDS = (
    *GROUP_FIELDS,
    "attack",
    "n_vehicles",
    "n_attackers",
    "attacker_fraction",
    "sim_time_s",
    "interval_s",
    "warmup_s",
    "attack_start_s",
    "onset_blank_s",
    "eval_window_start_s",
    "mobility",
    "detector_enabled",
    "score_model",
    "gps_sigma_m",
    "detector_gps_sigma_m",
    "clock_offset_sigma_s",
    "comm_range_m",
    "bsm_bytes",
    "headline_inclusion",
    "analysis_role",
    "runs",
    "seeds",
    "pair_output_expected_runs",
    "pair_output_observed_runs",
    "pair_run_coverage",
    "pair_metrics_status",
    "summary_received_messages",
    "detector_pair_messages",
    "eligible_window_messages",
    "pair_rows",
    "eligible_pairs",
    "malicious_pairs",
    "stream_negative_pairs",
    "clean_honest_pairs",
    "pair_prevalence",
    "honest_receiver_runs",
    "receiver_minutes",
    "negative_window_messages",
    "clean_window_messages",
    "clean_evaluation_window_tracks",
    "identity_stream_false_positives",
    "identity_clean_false_positives",
    "track_false_positive_pairs",
)

METRIC_FIELDS = (
    *GROUP_FIELDS,
    "metric",
    "estimate",
    "numerator",
    "denominator",
    "unit",
    "seed_n",
    "ci95_low",
    "ci95_high",
    "point_estimator",
    "ci_method",
    "sample_unit",
    "notes",
)


def finite(value: str | float | int, context: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise AnalysisError(f"{context}: expected a number, got {value!r}") from exc
    if not math.isfinite(result):
        raise AnalysisError(f"{context}: expected a finite number, got {value!r}")
    return result


def nonnegative(value: str | float | int, context: str) -> float:
    result = finite(value, context)
    if result < 0.0:
        raise AnalysisError(f"{context}: expected a non-negative value, got {result}")
    return result


def integer(value: str | int, context: str, minimum: int = 0) -> int:
    number = finite(value, context)
    if not number.is_integer() or number < minimum:
        raise AnalysisError(
            f"{context}: expected an integer >= {minimum}, got {value!r}"
        )
    return int(number)


def boolean(value: str | int, context: str) -> bool:
    text = str(value).strip().lower()
    if text in {"1", "true"}:
        return True
    if text in {"0", "false"}:
        return False
    raise AnalysisError(f"{context}: expected 0/1 or false/true, got {value!r}")


def group_of(row: dict[str, str]) -> tuple[str, str, str, str]:
    values = tuple(row[field].strip() for field in GROUP_FIELDS)
    if any(not value for value in values):
        raise AnalysisError(f"empty grouping value in {dict(zip(GROUP_FIELDS, values))}")
    return values  # type: ignore[return-value]


def selected(row: dict[str, str], stages: set[str], modes: set[str]) -> bool:
    return (not stages or row["stage"] in stages) and (
        not modes or row["mode"] in modes
    )


def dict_rows(path: Path, required: set[str]) -> Iterable[tuple[int, dict[str, str]]]:
    """Yield validated-width CSV rows while keeping the file handle streaming."""

    try:
        handle = path.open(newline="", encoding="utf-8")
    except OSError as exc:
        raise AnalysisError(f"cannot open {path}: {exc}") from exc
    reader = csv.DictReader(handle)
    header = reader.fieldnames or []
    if not header:
        handle.close()
        raise AnalysisError(f"{path}: missing CSV header")
    if len(header) != len(set(header)):
        handle.close()
        raise AnalysisError(f"{path}: duplicate CSV field")
    missing = required.difference(header)
    if missing:
        handle.close()
        raise AnalysisError(f"{path}: missing required fields {sorted(missing)}")

    def generate() -> Iterable[tuple[int, dict[str, str]]]:
        try:
            for line_no, row in enumerate(reader, 2):
                if None in row or any(value is None for value in row.values()):
                    raise AnalysisError(f"{path}:{line_no}: CSV row width mismatch")
                yield line_no, row
        finally:
            handle.close()

    return generate()


class P2Quantile:
    """Jain-Chlamtac P-squared streaming quantile estimator.

    The estimator keeps five markers after its exact five-value bootstrap.
    Small samples therefore remain exact and large samples require constant
    memory.  It is appropriate here because retaining millions of pair rows
    merely to print three descriptive quartiles is unnecessary.
    """

    def __init__(self, probability: float) -> None:
        if not 0.0 < probability < 1.0:
            raise ValueError("P2 probability must lie strictly inside (0, 1)")
        self.p = probability
        self.initial: list[float] = []
        self.q = [0.0] * 5
        self.n = [0] * 5
        self.np = [0.0] * 5
        self.dn = [0.0, probability / 2.0, probability,
                   (1.0 + probability) / 2.0, 1.0]
        self.count = 0

    def add(self, value: float) -> None:
        if not math.isfinite(value):
            raise ValueError("P2 observations must be finite")
        self.count += 1
        if len(self.initial) < 5:
            self.initial.append(value)
            if len(self.initial) == 5:
                self.initial.sort()
                self.q[:] = self.initial
                self.n[:] = [1, 2, 3, 4, 5]
                p = self.p
                self.np[:] = [1.0, 1.0 + 2.0 * p, 1.0 + 4.0 * p,
                              3.0 + 2.0 * p, 5.0]
            return

        if value < self.q[0]:
            self.q[0] = value
            cell = 0
        elif value >= self.q[4]:
            self.q[4] = value
            cell = 3
        else:
            cell = next(index for index in range(4) if value < self.q[index + 1])
        for index in range(cell + 1, 5):
            self.n[index] += 1
        for index in range(5):
            self.np[index] += self.dn[index]

        for index in (1, 2, 3):
            delta = self.np[index] - self.n[index]
            direction = 1 if delta >= 1.0 else (-1 if delta <= -1.0 else 0)
            if direction == 0:
                continue
            if (direction > 0 and self.n[index + 1] - self.n[index] <= 1) or (
                direction < 0 and self.n[index - 1] - self.n[index] >= -1
            ):
                continue
            left = self.n[index] - self.n[index - 1]
            right = self.n[index + 1] - self.n[index]
            span = self.n[index + 1] - self.n[index - 1]
            candidate = self.q[index] + direction / span * (
                (left + direction) * (self.q[index + 1] - self.q[index]) / right
                + (right - direction)
                * (self.q[index] - self.q[index - 1]) / left
            )
            if self.q[index - 1] < candidate < self.q[index + 1]:
                self.q[index] = candidate
            else:
                neighbor = index + direction
                self.q[index] += direction * (
                    self.q[neighbor] - self.q[index]
                ) / (self.n[neighbor] - self.n[index])
            self.n[index] += direction

    def value(self) -> float:
        if self.count == 0:
            return math.nan
        if len(self.initial) < 5:
            values = sorted(self.initial)
            location = (len(values) - 1) * self.p
            low = int(math.floor(location))
            high = int(math.ceil(location))
            if low == high:
                return values[low]
            weight = location - low
            return values[low] * (1.0 - weight) + values[high] * weight
        return self.q[2]


@dataclass
class Quartiles:
    q1: P2Quantile = field(default_factory=lambda: P2Quantile(0.25))
    median: P2Quantile = field(default_factory=lambda: P2Quantile(0.50))
    q3: P2Quantile = field(default_factory=lambda: P2Quantile(0.75))

    def add(self, value: float) -> None:
        self.q1.add(value)
        self.median.add(value)
        self.q3.add(value)

    @property
    def count(self) -> int:
        return self.median.count

    def values(self) -> tuple[float, float, float]:
        return self.q1.value(), self.median.value(), self.q3.value()


@dataclass
class Counters:
    pair_rows: int = 0
    pair_messages: int = 0
    window_messages: int = 0
    eligible_pairs: int = 0
    malicious_pairs: int = 0
    negative_pairs: int = 0
    clean_pairs: int = 0
    negative_messages: int = 0
    clean_messages: int = 0
    stream_fp: int = 0
    clean_fp: int = 0
    track_fp_pairs: int = 0
    clean_tracks: int = 0
    receiver_runs: int = 0
    receiver_minutes: float = 0.0
    clean_exposure_minutes: float = 0.0
    malicious_censored: int = 0
    malicious_detected: int = 0
    eligible_alerts: int = 0
    stride_ambiguous_alerts: int = 0
    stride_unassigned_alerts: int = 0
    track_count: int = 0
    track_merges: int = 0
    track_fragments: int = 0
    track_switches: int = 0
    purity_weight: int = 0
    purity_weighted_sum: float = 0.0


@dataclass
class SeedAccumulator:
    counters: Counters = field(default_factory=Counters)
    exposure: Quartiles = field(default_factory=Quartiles)
    clean_exposure: Quartiles = field(default_factory=Quartiles)
    malicious_exposure: Quartiles = field(default_factory=Quartiles)
    detected_delay: Quartiles = field(default_factory=Quartiles)
    track_purity: Quartiles = field(default_factory=Quartiles)
    run_ids: set[str] = field(default_factory=set)
    pair_run_ids: set[str] = field(default_factory=set)


@dataclass
class ArmAccumulator:
    counters: Counters = field(default_factory=Counters)
    exposure: Quartiles = field(default_factory=Quartiles)
    clean_exposure: Quartiles = field(default_factory=Quartiles)
    malicious_exposure: Quartiles = field(default_factory=Quartiles)
    detected_delay: Quartiles = field(default_factory=Quartiles)
    track_purity: Quartiles = field(default_factory=Quartiles)
    run_ids: set[str] = field(default_factory=set)
    pair_expected_run_ids: set[str] = field(default_factory=set)
    pair_run_ids: set[str] = field(default_factory=set)
    seeds: set[int] = field(default_factory=set)
    summary_received_messages: int = 0
    config_values: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )


@dataclass(frozen=True)
class RunMetadata:
    group: tuple[str, str, str, str]
    seed: int
    expected_pairs: int
    expected_eligible: int
    expected_stream_fp: int | None
    expected_clean_fp: int | None
    pair_output_expected: bool
    honest_receivers: int
    receiver_minutes: float


def add_pair(
    target: ArmAccumulator | SeedAccumulator,
    *,
    eligible: bool,
    malicious: bool,
    clean: bool,
    alert: bool,
    messages: int,
    window_messages: int,
    exposure_s: float,
    censored: bool,
    delay_s: float,
    track_count: int,
    track_alert: bool,
    track_purity: float,
    track_merges: int,
    track_fragments: int,
    track_switches: int,
    stride_ambiguous: bool,
    stride_unassigned: bool,
) -> None:
    c = target.counters
    c.pair_rows += 1
    c.pair_messages += messages
    if not eligible:
        return
    c.eligible_pairs += 1
    c.window_messages += window_messages
    c.track_count += track_count
    c.track_merges += track_merges
    c.track_fragments += track_fragments
    c.track_switches += track_switches
    c.purity_weight += window_messages
    c.purity_weighted_sum += track_purity * window_messages
    target.exposure.add(exposure_s)
    target.track_purity.add(track_purity)

    if malicious:
        c.malicious_pairs += 1
        target.malicious_exposure.add(exposure_s)
        if censored:
            c.malicious_censored += 1
        else:
            c.malicious_detected += 1
            target.detected_delay.add(delay_s)
    else:
        c.negative_pairs += 1
        c.negative_messages += window_messages
        if alert:
            c.stream_fp += 1

    if clean:
        c.clean_pairs += 1
        c.clean_messages += window_messages
        c.clean_exposure_minutes += exposure_s / 60.0
        c.clean_tracks += track_count
        target.clean_exposure.add(exposure_s)
        if alert:
            c.clean_fp += 1
        if track_alert:
            c.track_fp_pairs += 1

    if alert:
        c.eligible_alerts += 1
        if stride_ambiguous:
            c.stride_ambiguous_alerts += 1
        if stride_unassigned:
            c.stride_unassigned_alerts += 1


def percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    location = (len(ordered) - 1) * probability
    low = int(math.floor(location))
    high = int(math.ceil(location))
    if low == high:
        return ordered[low]
    weight = location - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def bootstrap_ratio(
    seeds: Sequence[SeedAccumulator],
    numerator: Callable[[Counters], float],
    denominator: Callable[[Counters], float],
    reps: int,
    rng: random.Random,
) -> tuple[int, float, float]:
    usable = [seed for seed in seeds if denominator(seed.counters) > 0.0]
    if len(usable) < 2 or reps <= 0:
        return len(usable), math.nan, math.nan
    estimates: list[float] = []
    for _ in range(reps):
        sample = [usable[rng.randrange(len(usable))] for _ in usable]
        den = sum(denominator(seed.counters) for seed in sample)
        if den > 0.0:
            estimates.append(sum(numerator(seed.counters) for seed in sample) / den)
    return len(usable), percentile(estimates, 0.025), percentile(estimates, 0.975)


def bootstrap_scalar(
    values: Sequence[float], reps: int, rng: random.Random
) -> tuple[int, float, float, float]:
    usable = [value for value in values if math.isfinite(value)]
    if not usable:
        return 0, math.nan, math.nan, math.nan
    estimate = statistics.fmean(usable)
    if len(usable) < 2 or reps <= 0:
        return len(usable), estimate, math.nan, math.nan
    sampled = [
        statistics.fmean(usable[rng.randrange(len(usable))] for _ in usable)
        for _ in range(reps)
    ]
    return len(usable), estimate, percentile(sampled, 0.025), percentile(sampled, 0.975)


def fmt(value: float | int | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return "nan" if not math.isfinite(value) else f"{value:.12g}"
    return str(value)


def metric_row(
    group: tuple[str, str, str, str],
    metric: str,
    estimate: float,
    numerator: float | None,
    denominator: float | None,
    unit: str,
    seed_n: int,
    low: float,
    high: float,
    estimator: str,
    ci_method: str,
    sample_unit: str,
    notes: str = "",
) -> dict[str, str]:
    return {
        **dict(zip(GROUP_FIELDS, group)),
        "metric": metric,
        "estimate": fmt(estimate),
        "numerator": fmt(numerator),
        "denominator": fmt(denominator),
        "unit": unit,
        "seed_n": str(seed_n),
        "ci95_low": fmt(low),
        "ci95_high": fmt(high),
        "point_estimator": estimator,
        "ci_method": ci_method,
        "sample_unit": sample_unit,
        "notes": notes,
    }


def atomic_csv(path: Path, fields: Sequence[str], rows: Iterable[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
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
            "Stream merged simulator CSVs and emit a per-arm inventory plus "
            "seed-clustered extended metrics."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--summary", type=Path, action="append", required=True,
        help="Merged summary CSV; repeat for multiple compatible artifacts.",
    )
    parser.add_argument(
        "--pairs", type=Path, action="append", required=True,
        help="Merged pair CSV; repeat for multiple compatible artifacts.",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--stage", action="append", default=[],
        help="Only include this stage (repeatable); empty includes all stages.",
    )
    parser.add_argument(
        "--mode", action="append", default=[],
        help="Only include this mode (repeatable); empty includes all modes.",
    )
    parser.add_argument(
        "--bootstrap-reps", type=int, default=2000,
        help="Cluster-bootstrap replicates over RNG seeds; zero disables CIs.",
    )
    parser.add_argument("--bootstrap-seed", type=int, default=20260802)
    parser.add_argument(
        "--allow-partial-pairs", action="store_true",
        help=(
            "Allow summary runs to be absent from the supplied pair CSVs. "
            "Observed runs are still reconciled exactly."
        ),
    )
    args = parser.parse_args(argv)
    if args.bootstrap_reps < 0:
        parser.error("--bootstrap-reps must be non-negative")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    stages, modes = set(args.stage), set(args.mode)
    arms: dict[tuple[str, str, str, str], ArmAccumulator] = defaultdict(ArmAccumulator)
    seed_arms: dict[tuple[tuple[str, str, str, str], int], SeedAccumulator] = (
        defaultdict(SeedAccumulator)
    )
    runs: dict[str, RunMetadata] = {}
    observed_pairs: dict[str, int] = defaultdict(int)
    observed_eligible: dict[str, int] = defaultdict(int)
    observed_stream_fp: dict[str, int] = defaultdict(int)
    observed_clean_fp: dict[str, int] = defaultdict(int)

    for path in args.summary:
        for line_no, row in dict_rows(path, SUMMARY_REQUIRED):
            if not selected(row, stages, modes):
                continue
            context = f"{path}:{line_no}"
            experiment_id = row["experiment_id"].strip()
            if not experiment_id:
                raise AnalysisError(f"{context}: empty experiment_id")
            if experiment_id in runs:
                raise AnalysisError(f"{context}: duplicate summary for {experiment_id}")
            group = group_of(row)
            seed = integer(row["seed"], f"{context}/seed", 1)
            n = integer(row["n"], f"{context}/n", 1)
            n_attackers = integer(row["n_attackers"], f"{context}/n_attackers")
            if n_attackers > n:
                raise AnalysisError(f"{context}: n_attackers exceeds n")
            sim_time = nonnegative(row["sim_time"], f"{context}/sim_time")
            eval_start = nonnegative(
                row["eval_window_start_s"], f"{context}/eval_window_start_s"
            )
            if eval_start >= sim_time:
                raise AnalysisError(f"{context}: evaluation window is empty")
            expected_pairs = integer(row["pairs"], f"{context}/pairs")
            expected_eligible = integer(
                row["eligible_pairs"], f"{context}/eligible_pairs"
            )
            if expected_eligible > expected_pairs:
                raise AnalysisError(f"{context}: eligible_pairs exceeds pairs")
            summary_stream_fp = (
                integer(row["stream_fp"], f"{context}/stream_fp")
                if "stream_fp" in row else None
            )
            summary_clean_fp = (
                integer(row["clean_fp"], f"{context}/clean_fp")
                if "clean_fp" in row else None
            )
            serial = boolean(row["serial"], f"{context}/serial")
            receiver_minutes = (
                (n - n_attackers) * (sim_time - eval_start) / 60.0
            )
            runs[experiment_id] = RunMetadata(
                group=group,
                seed=seed,
                expected_pairs=expected_pairs,
                expected_eligible=expected_eligible,
                expected_stream_fp=summary_stream_fp,
                expected_clean_fp=summary_clean_fp,
                pair_output_expected=not serial,
                honest_receivers=n - n_attackers,
                receiver_minutes=receiver_minutes,
            )
            arm = arms[group]
            seed_arm = seed_arms[(group, seed)]
            arm.run_ids.add(experiment_id)
            arm.seeds.add(seed)
            seed_arm.run_ids.add(experiment_id)
            if not serial:
                arm.pair_expected_run_ids.add(experiment_id)
            if "received" in row:
                arm.summary_received_messages += integer(
                    row["received"], f"{context}/received"
                )
            # Preserve every arm-defining value instead of silently taking the
            # first run. A pipe-separated value in the final inventory exposes
            # accidental within-arm heterogeneity.
            config_sources = {
                "attack": "attack",
                "n_vehicles": "n",
                "n_attackers": "n_attackers",
                "attacker_fraction": "frac",
                "sim_time_s": "sim_time",
                "interval_s": "interval",
                "warmup_s": "warmup",
                "attack_start_s": "attack_start_s",
                "onset_blank_s": "onset_blank_s",
                "eval_window_start_s": "eval_window_start_s",
                "mobility": "mobility",
                "detector_enabled": "detector",
                "score_model": "score_model",
                "gps_sigma_m": "gps_sigma",
                "detector_gps_sigma_m": "detector_gps_sigma",
                "clock_offset_sigma_s": "clock_sigma",
                "comm_range_m": "comm_range",
                "bsm_bytes": "bsm_bytes",
            }
            for output_field, source_field in config_sources.items():
                value = row.get(source_field, "").strip()
                if value:
                    arm.config_values[output_field].add(value)

    if not runs:
        raise AnalysisError("no summary rows matched the requested mode/stage filters")

    for path in args.pairs:
        for line_no, row in dict_rows(path, PAIR_REQUIRED):
            if not selected(row, stages, modes):
                continue
            context = f"{path}:{line_no}"
            experiment_id = row["experiment_id"].strip()
            metadata = runs.get(experiment_id)
            if metadata is None:
                raise AnalysisError(
                    f"{context}: pair references unknown summary run {experiment_id!r}"
                )
            if group_of(row) != metadata.group:
                raise AnalysisError(f"{context}: pair/summary arm metadata mismatch")
            seed = integer(row["seed"], f"{context}/seed", 1)
            if seed != metadata.seed:
                raise AnalysisError(f"{context}: pair/summary seed mismatch")

            eligible = boolean(row["eligible"], f"{context}/eligible")
            malicious = boolean(row["malicious_use"], f"{context}/malicious_use")
            clean = boolean(row["clean_pair"], f"{context}/clean_pair")
            alert = boolean(row["window_alert"], f"{context}/window_alert")
            if clean and malicious:
                raise AnalysisError(f"{context}: clean_pair cannot be malicious_use")
            if not eligible and alert:
                raise AnalysisError(f"{context}: ineligible pair cannot alert")
            messages = integer(row["messages"], f"{context}/messages")
            window_messages = integer(row["window_msgs"], f"{context}/window_msgs")
            if eligible != (window_messages > 0):
                raise AnalysisError(
                    f"{context}: eligible must equal (window_msgs > 0)"
                )
            exposure = nonnegative(
                row["window_exposure_s"], f"{context}/window_exposure_s"
            )
            delay = finite(
                row["stream_time_to_detect_s"],
                f"{context}/stream_time_to_detect_s",
            )
            if malicious and eligible:
                censored = boolean(
                    row["stream_censored"], f"{context}/stream_censored"
                )
                if censored and delay >= 0.0:
                    raise AnalysisError(f"{context}: censored pair has detected delay")
                if not censored and delay < 0.0:
                    raise AnalysisError(f"{context}: uncensored pair lacks detected delay")
                # The post-onset delay event is stricter than the full-window
                # classification endpoint: a pre-hostile peak may yield
                # alert=True with a censored post-onset clock.  The converse is
                # impossible, because every observed post-onset event is itself
                # an above-threshold observation inside the evaluation window.
                if not censored and not alert:
                    raise AnalysisError(
                        f"{context}: post-onset delay event lacks window alert"
                    )
            else:
                # The simulator deliberately writes -1 for an inapplicable
                # survival clock on negative pairs.  It is not a censoring
                # event and must not be forced through the Boolean parser.
                censored = False
            track_count = integer(row["track_count"], f"{context}/track_count")
            track_alert = boolean(row["track_alert"], f"{context}/track_alert")
            # Parse separately even though this field is not a numerator here;
            # schema-level validation prevents silent 0/1 drift in mitigation data.
            boolean(row["honest_track_alert"], f"{context}/honest_track_alert")
            boolean(row["owner_track_alert"], f"{context}/owner_track_alert")
            integer(
                row["track_capacity_dropped_messages"],
                f"{context}/track_capacity_dropped_messages",
            )
            purity = finite(row["track_purity"], f"{context}/track_purity")
            if not 0.0 <= purity <= 1.0:
                raise AnalysisError(f"{context}: track_purity outside [0,1]")
            track_merges = integer(row["track_merges"], f"{context}/track_merges")
            track_fragments = integer(
                row["track_fragments"], f"{context}/track_fragments"
            )
            track_switches = integer(
                row["track_id_switches"], f"{context}/track_id_switches"
            )
            ambiguous = boolean(
                row["stride_ambiguous"], f"{context}/stride_ambiguous"
            )
            stride = row["stride_class"].strip().lower()
            unassigned = stride in {"", "none", "unassigned", "s_none", "6", "-1"}

            parameters = dict(
                eligible=eligible,
                malicious=malicious,
                clean=clean,
                alert=alert,
                messages=messages,
                window_messages=window_messages,
                exposure_s=exposure,
                censored=censored,
                delay_s=delay,
                track_count=track_count,
                track_alert=track_alert,
                track_purity=purity,
                track_merges=track_merges,
                track_fragments=track_fragments,
                track_switches=track_switches,
                stride_ambiguous=ambiguous,
                stride_unassigned=unassigned,
            )
            add_pair(arms[metadata.group], **parameters)
            add_pair(seed_arms[(metadata.group, seed)], **parameters)
            observed_pairs[experiment_id] += 1
            if eligible:
                observed_eligible[experiment_id] += 1
                if not malicious and alert:
                    observed_stream_fp[experiment_id] += 1
                if clean and alert:
                    observed_clean_fp[experiment_id] += 1

    for experiment_id, metadata in runs.items():
        observed = observed_pairs.get(experiment_id, 0)
        if observed == 0 and not metadata.pair_output_expected:
            continue
        if observed == 0 and args.allow_partial_pairs:
            continue
        checks = (
            ("pairs", observed, metadata.expected_pairs),
            ("eligible_pairs", observed_eligible.get(experiment_id, 0),
             metadata.expected_eligible),
        )
        for name, actual, expected in checks:
            if actual != expected:
                raise AnalysisError(
                    f"{experiment_id}: merged pair {name}={actual}, summary={expected}"
                )
        if metadata.expected_stream_fp is not None and (
            observed_stream_fp.get(experiment_id, 0) != metadata.expected_stream_fp
        ):
            raise AnalysisError(
                f"{experiment_id}: computed stream_fp="
                f"{observed_stream_fp.get(experiment_id, 0)}, "
                f"summary={metadata.expected_stream_fp}"
            )
        if metadata.expected_clean_fp is not None and (
            observed_clean_fp.get(experiment_id, 0) != metadata.expected_clean_fp
        ):
            raise AnalysisError(
                f"{experiment_id}: computed clean_fp="
                f"{observed_clean_fp.get(experiment_id, 0)}, "
                f"summary={metadata.expected_clean_fp}"
            )

        # Add run/time denominators only after proving that this run's complete
        # pair block is present.  In partial mode, absent pair runs therefore do
        # not masquerade as zero-event observations.  Serial timing runs never
        # enter this set because they intentionally suppress pair output.
        arm = arms[metadata.group]
        seed_arm = seed_arms[(metadata.group, metadata.seed)]
        arm.pair_run_ids.add(experiment_id)
        seed_arm.pair_run_ids.add(experiment_id)
        arm.counters.receiver_runs += metadata.honest_receivers
        seed_arm.counters.receiver_runs += metadata.honest_receivers
        arm.counters.receiver_minutes += metadata.receiver_minutes
        seed_arm.counters.receiver_minutes += metadata.receiver_minutes

    inventory: list[dict[str, str]] = []
    metrics: list[dict[str, str]] = []
    rng = random.Random(args.bootstrap_seed)
    bootstrap_method = (
        f"percentile cluster bootstrap ({args.bootstrap_reps} resamples of RNG seeds)"
        if args.bootstrap_reps else "disabled"
    )

    for group in sorted(arms):
        arm = arms[group]
        c = arm.counters
        prevalence = c.malicious_pairs / c.eligible_pairs if c.eligible_pairs else math.nan
        expected_pair_runs = len(arm.pair_expected_run_ids)
        observed_pair_runs = len(arm.pair_run_ids)
        pair_coverage = (
            observed_pair_runs / expected_pair_runs
            if expected_pair_runs else math.nan
        )
        if expected_pair_runs == 0:
            pair_status = "not_applicable_no_pair_output"
        elif observed_pair_runs == expected_pair_runs:
            pair_status = "complete"
        elif observed_pair_runs == 0:
            pair_status = "unavailable_no_observed_pair_runs"
        else:
            pair_status = "partial"
        family = group[2]
        headline = family in {
            "pure_attack", "benign", "mixedhard_prevalence"
        }
        analysis_role = {
            "threshold_selection": "validation-only threshold selection",
            "pure_attack": "headline attack-stratified detection",
            "benign": "headline attacker-free false-alarm bound",
            "mixedhard_prevalence": "headline mixed-prevalence detection",
            "steady_state": "activation-transient control",
            "onset_guard": "activation-guard sensitivity",
            "benign_stress": "attacker-free model-mismatch stress",
            "noise_misspecification": "mixed-attack noise sensitivity",
            "mobility": "kinematic-perturbation sensitivity",
            "score_variant": "score-model sensitivity",
            "scale": "vehicle-count scaling",
            "serial_timing": "serial detector-on/off cost",
        }.get(family, "secondary sensitivity/control")
        config_fields = INVENTORY_FIELDS[4:22]
        config = {
            field: "|".join(sorted(arm.config_values.get(field, set()))) or "-"
            for field in config_fields
        }
        inventory.append({
            **dict(zip(GROUP_FIELDS, group)),
            **config,
            "headline_inclusion": "yes" if headline else "no",
            "analysis_role": analysis_role,
            "runs": str(len(arm.run_ids)),
            "seeds": str(len(arm.seeds)),
            "pair_output_expected_runs": str(expected_pair_runs),
            "pair_output_observed_runs": str(observed_pair_runs),
            "pair_run_coverage": fmt(pair_coverage),
            "pair_metrics_status": pair_status,
            "summary_received_messages": str(arm.summary_received_messages),
            "detector_pair_messages": str(c.pair_messages),
            "eligible_window_messages": str(c.window_messages),
            "pair_rows": str(c.pair_rows),
            "eligible_pairs": str(c.eligible_pairs),
            "malicious_pairs": str(c.malicious_pairs),
            "stream_negative_pairs": str(c.negative_pairs),
            "clean_honest_pairs": str(c.clean_pairs),
            "pair_prevalence": fmt(prevalence),
            "honest_receiver_runs": str(c.receiver_runs),
            "receiver_minutes": fmt(c.receiver_minutes),
            "negative_window_messages": str(c.negative_messages),
            "clean_window_messages": str(c.clean_messages),
            "clean_evaluation_window_tracks": str(c.clean_tracks),
            "identity_stream_false_positives": str(c.stream_fp),
            "identity_clean_false_positives": str(c.clean_fp),
            "track_false_positive_pairs": str(c.track_fp_pairs),
        })
        # Pair-derived metrics do not exist for pairless timing arms.  Omitting
        # those metric rows is preferable to publishing exact zeros for events
        # that were never observed; the inventory above records why they are
        # unavailable.  Partial artifacts use only fully observed pair runs.
        if not arm.pair_run_ids:
            continue
        seeds = [
            seed_arms[(group, seed)]
            for seed in sorted(arm.seeds)
            if seed_arms[(group, seed)].pair_run_ids
        ]

        def ratio_metric(
            name: str,
            numerator: Callable[[Counters], float],
            denominator: Callable[[Counters], float],
            unit: str,
            sample_unit: str,
            notes: str = "",
            scale: float = 1.0,
        ) -> None:
            num = numerator(c)
            den = denominator(c)
            estimate = scale * num / den if den > 0.0 else math.nan
            seed_n, low, high = bootstrap_ratio(
                seeds, numerator, denominator, args.bootstrap_reps, rng
            )
            if math.isfinite(low):
                low *= scale
                high *= scale
            metrics.append(metric_row(
                group, name, estimate, num, den, unit, seed_n, low, high,
                "ratio of pooled event counts/opportunities",
                bootstrap_method, sample_unit, notes,
            ))

        ratio_metric(
            "pair_prevalence", lambda x: x.malicious_pairs,
            lambda x: x.eligible_pairs, "proportion", "eligible pair",
        )
        ratio_metric(
            "stream_false_positive_rate_per_negative_pair",
            lambda x: x.stream_fp, lambda x: x.negative_pairs,
            "false positives / negative pair", "negative eligible pair",
        )
        # Counters intentionally contain no sets. Build run-normalized rows
        # directly so a design with multiple runs sharing one seed remains
        # clustered correctly.
        run_num = c.stream_fp
        run_den = len(arm.pair_run_ids)
        run_seed_values = [
            seed.counters.stream_fp / len(seed.pair_run_ids)
            for seed in seeds if seed.pair_run_ids
        ]
        seed_n, _run_mean, low, high = bootstrap_scalar(
            run_seed_values, args.bootstrap_reps, rng
        )
        metrics.append(metric_row(
            group, "stream_false_positives_per_run",
            run_num / run_den if run_den else math.nan, run_num, run_den,
            "false positives / observed pair run", seed_n, low, high,
            "ratio of pooled event counts/runs", bootstrap_method,
            "independent RNG seed",
            "Only runs with complete observed pair blocks contribute.",
        ))
        clean_run_values = [
            seed.counters.clean_fp / len(seed.pair_run_ids)
            for seed in seeds if seed.pair_run_ids
        ]
        seed_n, _run_mean, low, high = bootstrap_scalar(
            clean_run_values, args.bootstrap_reps, rng
        )
        metrics.append(metric_row(
            group, "clean_false_positives_per_run",
            c.clean_fp / run_den if run_den else math.nan,
            c.clean_fp, run_den, "false positives / observed pair run", seed_n,
            low, high, "ratio of pooled event counts/runs", bootstrap_method,
            "independent RNG seed",
            "Only runs with complete observed pair blocks contribute.",
        ))
        ratio_metric(
            "stream_false_positives_per_receiver_run",
            lambda x: x.stream_fp, lambda x: x.receiver_runs,
            "false-positive pair events / honest receiver-run",
            "honest receiver-run",
            "Each honest receiver contributes one exposure unit in each "
            "complete observed run.",
        )
        ratio_metric(
            "clean_false_positives_per_receiver_run",
            lambda x: x.clean_fp, lambda x: x.receiver_runs,
            "clean-pair false-positive events / honest receiver-run",
            "honest receiver-run",
            "Each honest receiver contributes one exposure unit in each "
            "complete observed run.",
        )
        ratio_metric(
            "stream_false_positives_per_receiver_minute",
            lambda x: x.stream_fp, lambda x: x.receiver_minutes,
            "false positives / receiver-minute", "receiver-minute",
            "Receiver-minutes use honest receivers times the common evaluation-window duration."
        )
        ratio_metric(
            "stream_false_positives_per_million_negative_messages",
            lambda x: x.stream_fp, lambda x: x.negative_messages,
            "false-positive pair events / million negative messages",
            "negative message",
            "The numerator is a receiver--claimed-identity window event, not a "
            "per-message decision; messages provide an exposure denominator.",
            scale=1_000_000.0,
        )
        ratio_metric(
            "clean_false_positive_rate_per_clean_pair",
            lambda x: x.clean_fp, lambda x: x.clean_pairs,
            "false positives / clean honest pair", "clean honest eligible pair",
        )
        ratio_metric(
            "clean_false_positives_per_receiver_minute",
            lambda x: x.clean_fp, lambda x: x.receiver_minutes,
            "false positives / receiver-minute", "receiver-minute",
        )
        ratio_metric(
            "clean_false_positives_per_million_clean_messages",
            lambda x: x.clean_fp, lambda x: x.clean_messages,
            "false-positive pair events / million clean messages",
            "clean honest message",
            "The numerator is a clean-pair window event, not a per-message "
            "decision; messages provide an exposure denominator.",
            scale=1_000_000.0,
        )
        ratio_metric(
            "track_false_positive_pair_rate",
            lambda x: x.track_fp_pairs, lambda x: x.clean_pairs,
            "track-alerted clean pairs / clean pair", "clean honest eligible pair",
            "Numerator is pair-level because the pair schema exposes whether any track alerted."
        )
        ratio_metric(
            "track_false_positive_pairs_per_clean_evaluation_window_track",
            lambda x: x.track_fp_pairs, lambda x: x.clean_tracks,
            "track-alerted clean pairs / clean evaluation-window track",
            "clean evaluation-window content-associated track",
            "Conservative pair-event numerator; individual alerted-track count is "
            "not in the schema. Track count requires at least one window message."
        )
        ratio_metric(
            "malicious_delay_censoring_rate",
            lambda x: x.malicious_censored, lambda x: x.malicious_pairs,
            "proportion", "malicious eligible pair",
            "Censoring is reported separately; delay quartiles condition on detection."
        )
        ratio_metric(
            "postwarmup_track_merges_per_evaluation_window_track",
            lambda x: x.track_merges, lambda x: x.track_count,
            "post-warm-up merges / evaluation-window track",
            "evaluation-window content-associated track",
            "Merge counts span all post-warm-up tracked messages; the pair schema "
            "exposes only evaluation-window track count as a normalization base.",
        )
        ratio_metric(
            "postwarmup_track_fragments_per_evaluation_window_track",
            lambda x: x.track_fragments, lambda x: x.track_count,
            "post-warm-up fragments / evaluation-window track",
            "evaluation-window content-associated track",
            "Fragment counts span all post-warm-up tracked messages; this is a "
            "descriptive normalization, not a window-matched event rate.",
        )
        ratio_metric(
            "postwarmup_track_id_switches_per_evaluation_window_track",
            lambda x: x.track_switches, lambda x: x.track_count,
            "post-warm-up ID switches / evaluation-window track",
            "evaluation-window content-associated track",
            "ID-switch counts span all post-warm-up tracked messages; this is a "
            "descriptive normalization, not a window-matched event rate.",
        )
        ratio_metric(
            "window_message_weighted_postwarmup_track_purity",
            lambda x: x.purity_weighted_sum, lambda x: x.purity_weight,
            "proportion", "eligible-window message",
            "Each pair's post-warm-up track purity is weighted by its "
            "evaluation-window message count; purity itself is not window-restricted."
        )
        ratio_metric(
            "stride_ambiguous_rate_among_alerts",
            lambda x: x.stride_ambiguous_alerts, lambda x: x.eligible_alerts,
            "proportion", "alerted eligible pair",
        )
        ratio_metric(
            "stride_unassigned_rate_among_alerts",
            lambda x: x.stride_unassigned_alerts, lambda x: x.eligible_alerts,
            "proportion", "alerted eligible pair",
        )

        quantile_specs = (
            ("pair_exposure", arm.exposure,
             [seed.exposure for seed in seeds], "s", "eligible pair"),
            ("clean_pair_exposure", arm.clean_exposure,
             [seed.clean_exposure for seed in seeds], "s", "clean honest eligible pair"),
            ("malicious_pair_exposure", arm.malicious_exposure,
             [seed.malicious_exposure for seed in seeds], "s", "malicious eligible pair"),
            ("detected_delay", arm.detected_delay,
             [seed.detected_delay for seed in seeds], "s", "detected malicious pair"),
            ("postwarmup_track_purity", arm.track_purity,
             [seed.track_purity for seed in seeds], "proportion", "eligible pair"),
        )
        for prefix, pooled, seed_quartiles, unit, sample_unit in quantile_specs:
            q1, median, q3 = pooled.values()
            for suffix, value in (("q1", q1), ("median", median), ("q3", q3)):
                metrics.append(metric_row(
                    group, f"{prefix}_{suffix}_pooled_p2", value, None,
                    pooled.count, unit, 0, math.nan, math.nan,
                    "P-squared online quantile over pooled pair observations",
                    "not computed for pooled descriptive quantile", sample_unit,
                    "Constant-memory approximation; use seed rows below for uncertainty."
                ))
            for index, suffix in ((0, "q1"), (1, "median"), (2, "q3")):
                values = [item.values()[index] for item in seed_quartiles if item.count]
                seed_n, estimate, low, high = bootstrap_scalar(
                    values, args.bootstrap_reps, rng
                )
                metrics.append(metric_row(
                    group, f"seed_mean_of_within_seed_{prefix}_{suffix}",
                    estimate, None, seed_n, unit, seed_n, low, high,
                    f"mean of per-seed P-squared {suffix} estimates",
                    bootstrap_method, "independent RNG seed",
                    f"Within-seed observations are {sample_unit}s; seeds are the inferential unit."
                ))

    output_dir = args.output_dir.resolve()
    inventory_path = output_dir / "arm_inventory.csv"
    metrics_path = output_dir / "extended_metrics.csv"
    atomic_csv(inventory_path, INVENTORY_FIELDS, inventory)
    atomic_csv(metrics_path, METRIC_FIELDS, metrics)
    print(
        f"wrote {len(inventory)} arm rows to {inventory_path} and "
        f"{len(metrics)} metric rows to {metrics_path}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AnalysisError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
