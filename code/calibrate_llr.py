#!/usr/bin/env python3
"""Fit descriptive simulator evidence weights from labelled v4 traces.

This tool is intentionally not a posterior calibrator.  It replays the same
plausibility checks and estimates their firing rates on messages explicitly
labelled by ``oracle_message_is_malicious``.  It never substitutes assigned
attacker membership for message truth: pre-attack transmissions from assigned
attackers are honest observations.

Rates are balanced in two stages: unique RNG seeds are averaged within each
explicit assigned-role stratum, then role strata are weighted equally.  This prevents a
high-rate attack, a long trace, or repeated arms sharing one seed from
dominating the fit.  Use ``--output-json`` to save a versioned artifact with
configuration, raw counts, seed/attack strata, input hashes, and fitted rates.
The result remains simulator-fit evidence and must be trained on seeds disjoint
from validation and test.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import re
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parent

CHECKS = (
    "POSITION_JUMP",
    "SPEED_MISMATCH",
    "STALENESS",
    "REPLAY",
    "RATE",
    "MAP_BOUNDS",
    "HEADING",
)

REFERENCE = {
    "POSITION_JUMP": (0.85, 0.02),
    "SPEED_MISMATCH": (0.70, 0.05),
    "STALENESS": (0.40, 0.03),
    "REPLAY": (0.90, 0.01),
    "RATE": (0.95, 0.01),
    "MAP_BOUNDS": (0.60, 0.005),
    "HEADING": (0.75, 0.04),
}

MALICIOUS = 0
HONEST = 1
CLASS_NAMES = ("malicious_message", "honest_message")


class TraceSchemaError(ValueError):
    """Raised when a trace cannot support attribution-safe v4 fitting."""


def parse_bool(value: str) -> bool:
    value = value.strip().lower()
    if value in {"1", "true", "yes", "y"}:
        return True
    if value in {"0", "false", "no", "n"}:
        return False
    raise TraceSchemaError(f"expected an oracle boolean, got {value!r}")


def choose(fields: set[str], name: str) -> str:
    if name not in fields:
        raise TraceSchemaError(f"missing required v4 column: {name}")
    return name


@dataclass(frozen=True)
class Schema:
    receiver: str
    rx_time: str
    claimed_id: str
    claimed_seq: str
    claimed_tx_time: str
    claimed_x: str
    claimed_y: str
    claimed_vx: str
    claimed_vy: str
    observable_source: str
    source_id: str
    source_is_attacker: str
    assigned_role: str
    attack_active: str
    message_is_malicious: str
    victim_id: str
    owner_is_attacker: str
    expected_receiver: str
    actual_gps_sigma: str | None
    detector_gps_sigma: str | None

    @classmethod
    def from_fields(cls, names: Iterable[str]) -> "Schema":
        fields = set(names)
        required = {
            "receiver_id",
            "rx_time",
            "claimed_id",
            "claimed_seq",
            "claimed_tx_time",
            "claimed_x",
            "claimed_y",
            "claimed_vx",
            "claimed_vy",
            "receiver_true_x",
            "receiver_true_y",
            "observable_source_ipv4",
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
        }
        missing = sorted(required - fields)
        if missing:
            raise TraceSchemaError(
                "trace is not v4; missing required columns: " + ", ".join(missing)
            )
        actual = next(
            (
                name
                for name in (
                    "gps_sigma",
                    "actual_gps_sigma",
                    "oracle_actual_gps_sigma",
                )
                if name in fields
            ),
            None,
        )
        detector = next(
            (
                name
                for name in (
                    "detector_gps_sigma",
                    "detector_assumed_gps_sigma",
                )
                if name in fields
            ),
            None,
        )
        return cls(
            receiver=choose(fields, "receiver_id"),
            rx_time=choose(fields, "rx_time"),
            claimed_id=choose(fields, "claimed_id"),
            claimed_seq=choose(fields, "claimed_seq"),
            claimed_tx_time=choose(fields, "claimed_tx_time"),
            claimed_x=choose(fields, "claimed_x"),
            claimed_y=choose(fields, "claimed_y"),
            claimed_vx=choose(fields, "claimed_vx"),
            claimed_vy=choose(fields, "claimed_vy"),
            observable_source=choose(fields, "observable_source_ipv4"),
            source_id=choose(fields, "oracle_source_id"),
            source_is_attacker=choose(fields, "oracle_source_is_attacker"),
            assigned_role=choose(fields, "oracle_assigned_role"),
            attack_active=choose(fields, "oracle_attack_active"),
            message_is_malicious=choose(
                fields, "oracle_message_is_malicious"
            ),
            victim_id=choose(fields, "oracle_victim_id"),
            owner_is_attacker=choose(fields, "oracle_owner_is_attacker"),
            expected_receiver=choose(fields, "oracle_expected_receiver"),
            actual_gps_sigma=actual,
            detector_gps_sigma=detector,
        )


@dataclass
class State:
    have: bool = False
    last_tx: float = 0.0
    seen: set[int] = field(default_factory=set)
    fifo: deque[int] = field(default_factory=deque)
    receptions: deque[float] = field(default_factory=deque)
    ref_valid: bool = False
    ref_x: float = 0.0
    ref_y: float = 0.0
    ref_t: float = 0.0


@dataclass(frozen=True)
class Config:
    warmup: float
    vmax: float
    speed_tolerance: float
    max_age: float
    rate_window: float
    rate_limit: float
    road_length: float
    road_width: float
    min_ref_dt: float
    heading_cos_min: float
    speed_sigma: float
    replay_memory: int


@dataclass(frozen=True)
class RunMeta:
    path: Path
    run_id: str
    seed: int
    attack: str
    partition: str


@dataclass
class RunCounts:
    meta: RunMeta
    totals: list[int] = field(default_factory=lambda: [0, 0])
    fires: dict[str, list[int]] = field(
        default_factory=lambda: {check: [0, 0] for check in CHECKS}
    )
    source_attacker_messages: list[int] = field(default_factory=lambda: [0, 0])
    roles: set[str] = field(default_factory=set)
    role_totals: dict[str, list[int]] = field(
        default_factory=lambda: defaultdict(lambda: [0, 0])
    )
    role_fires: dict[str, dict[str, list[int]]] = field(
        default_factory=lambda: {
            check: defaultdict(lambda: [0, 0]) for check in CHECKS
        }
    )
    actual_sigmas: set[float] = field(default_factory=set)
    detector_sigmas: set[float] = field(default_factory=set)
    sha256: str = ""


def finite(row: dict[str, str], column: str) -> float:
    value = float(row[column])
    if not math.isfinite(value):
        raise TraceSchemaError(f"non-finite value in {column}")
    return value


def optional_sigma(
    row: dict[str, str],
    column: str | None,
    fallback: float | None,
    label: str,
) -> float | None:
    value = finite(row, column) if column else fallback
    if value is not None and value < 0.0:
        raise TraceSchemaError(f"{label} must be non-negative")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_meta(path: Path) -> RunMeta:
    summary = path.parent / "summary.csv"
    if summary.is_file():
        with summary.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        if len(rows) != 1:
            raise TraceSchemaError(f"{summary}: expected exactly one row")
        try:
            seed = int(rows[0]["run"])
            attack = rows[0]["attack"].strip()
        except (KeyError, ValueError) as exc:
            raise TraceSchemaError(
                f"{summary}: missing valid run/attack metadata"
            ) from exc
        if not attack:
            raise TraceSchemaError(f"{summary}: empty attack stratum")
        return RunMeta(
            path,
            path.parent.name,
            seed,
            attack,
            path.parent.parent.name,
        )

    run_id = path.parent.name if path.name == "trace.csv" else path.stem
    match = re.fullmatch(
        r"(?P<partition>[^_]+)__(?:[^_]+(?:_[^_]+)*)__"
        r"(?P<attack>[^_]+(?:_[^_]+)*)__seed_(?P<seed>\d+)",
        run_id,
    )
    if not match:
        raise TraceSchemaError(
            f"{path}: cannot recover seed and attack. Add a one-row "
            "summary.csv beside the trace with run and attack columns"
        )
    return RunMeta(
        path,
        run_id,
        int(match.group("seed")),
        match.group("attack"),
        match.group("partition"),
    )


def replay_file(
    path: Path,
    schema: Schema,
    args: argparse.Namespace,
    config: Config,
    counts: RunCounts,
) -> None:
    states: dict[tuple[int, int], State] = defaultdict(State)
    last_now = -math.inf
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for row_no, row in enumerate(reader, start=2):
            try:
                now = finite(row, schema.rx_time)
                if now + 1e-12 < last_now:
                    raise TraceSchemaError("reception times are not monotone")
                last_now = now
                receiver = int(row[schema.receiver])
                claimed_id = int(row[schema.claimed_id])
                seq = int(row[schema.claimed_seq])
                tx_time = finite(row, schema.claimed_tx_time)
                x = finite(row, schema.claimed_x)
                y = finite(row, schema.claimed_y)
                vx = finite(row, schema.claimed_vx)
                vy = finite(row, schema.claimed_vy)
                int(row[schema.source_id])
                source_attacker = parse_bool(row[schema.source_is_attacker])
                parse_bool(row[schema.owner_is_attacker])
                parse_bool(row[schema.expected_receiver])
                int(row[schema.victim_id])
                if not row[schema.observable_source].strip():
                    raise TraceSchemaError("observable source address is empty")
                role = row[schema.assigned_role].strip()
                if not role:
                    raise TraceSchemaError("oracle assigned role is empty")
                attack_active = parse_bool(row[schema.attack_active])
                malicious = parse_bool(row[schema.message_is_malicious])
                if malicious and not attack_active:
                    raise TraceSchemaError(
                        "malicious message is labelled outside active attack"
                    )

                actual_sigma = optional_sigma(
                    row,
                    schema.actual_gps_sigma,
                    args.actual_gps_sigma,
                    "actual GPS sigma",
                )
                detector_sigma = optional_sigma(
                    row,
                    schema.detector_gps_sigma,
                    args.detector_gps_sigma,
                    "detector GPS sigma",
                )
                if detector_sigma is None:
                    raise TraceSchemaError(
                        "detector GPS sigma is absent; pass "
                        "--detector-gps-sigma explicitly"
                    )
                if actual_sigma is not None:
                    counts.actual_sigmas.add(actual_sigma)
                counts.detector_sigmas.add(detector_sigma)
                counts.roles.add(role)
            except TraceSchemaError as exc:
                raise TraceSchemaError(f"{path}:{row_no}: {exc}") from exc
            except (KeyError, TypeError, ValueError) as exc:
                raise TraceSchemaError(f"{path}:{row_no}: {exc}") from exc

            state = states[(receiver, claimed_id)]
            fired = {check: False for check in CHECKS}
            fired["MAP_BOUNDS"] = (
                x < -50.0
                or x > config.road_length + 50.0
                or abs(y) > config.road_width
            )
            fired["STALENESS"] = (now - tx_time) > config.max_age
            if state.have:
                fired["REPLAY"] = seq in state.seen or tx_time <= state.last_tx

            if state.ref_valid:
                sample_dt = tx_time - state.ref_t
                if sample_dt >= config.min_ref_dt:
                    dx, dy = x - state.ref_x, y - state.ref_y
                    displacement = math.hypot(dx, dy)
                    implied = displacement / sample_dt
                    asserted = math.hypot(vx, vy)
                    position_speed_sigma = (
                        math.sqrt(2.0) * detector_sigma / sample_dt
                    )
                    fired["POSITION_JUMP"] = implied > (
                        config.vmax + 3.0 * position_speed_sigma
                    )
                    fired["SPEED_MISMATCH"] = abs(implied - asserted) > (
                        config.speed_tolerance
                        + 3.0
                        * math.hypot(position_speed_sigma, config.speed_sigma)
                    )
                    if displacement > 3.0 * detector_sigma and asserted > 1.0:
                        cosine = (dx * vx + dy * vy) / (
                            displacement * asserted
                        )
                        fired["HEADING"] = cosine < config.heading_cos_min
                    state.ref_x, state.ref_y, state.ref_t = x, y, tx_time
            else:
                state.ref_valid = True
                state.ref_x, state.ref_y, state.ref_t = x, y, tx_time

            state.receptions.append(now)
            while (
                state.receptions
                and state.receptions[0] < now - config.rate_window
            ):
                state.receptions.popleft()
            fired["RATE"] = (
                len(state.receptions) / config.rate_window > config.rate_limit
            )

            state.have = True
            state.last_tx = tx_time
            if seq not in state.seen:
                state.seen.add(seq)
                state.fifo.append(seq)
                if len(state.fifo) > config.replay_memory:
                    state.seen.remove(state.fifo.popleft())

            # Pre-warm-up rows build exactly the same clean history, but are
            # not observations in the fitting estimand.
            if now < config.warmup:
                continue
            label = MALICIOUS if malicious else HONEST
            counts.totals[label] += 1
            counts.role_totals[role][label] += 1
            if source_attacker:
                counts.source_attacker_messages[label] += 1
            for check, active in fired.items():
                if active:
                    counts.fires[check][label] += 1
                    counts.role_fires[check][role][label] += 1


def per_run_role_rate(
    counts: RunCounts, check: str, role: str, label: int
) -> float:
    """Jeffreys-smoothed rate for one run/assigned-role/class cell."""
    return (counts.role_fires[check][role][label] + 0.5) / (
        counts.role_totals[role][label] + 1.0
    )


def balanced_rate(
    runs: list[RunCounts], check: str, label: int
) -> tuple[float, dict[str, object]]:
    by_role_seed: dict[str, dict[int, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for run in runs:
        for role, totals in run.role_totals.items():
            if totals[label] == 0:
                continue
            by_role_seed[role][run.meta.seed].append(
                per_run_role_rate(run, check, role, label)
            )
    if not by_role_seed:
        return math.nan, {"assigned_role_strata": {}, "n_role_strata": 0}

    role_rates: dict[str, float] = {}
    strata_detail: dict[str, object] = {}
    for role, seed_values in sorted(by_role_seed.items()):
        seed_rates = {
            str(seed): statistics_mean(values)
            for seed, values in sorted(seed_values.items())
        }
        role_rates[role] = statistics_mean(seed_rates.values())
        strata_detail[role] = {
            "rate": role_rates[role],
            "seed_rates": seed_rates,
            "unique_seeds": len(seed_rates),
        }
    return statistics_mean(role_rates.values()), {
        "assigned_role_strata": strata_detail,
        "n_role_strata": len(role_rates),
        "estimator": (
            "Jeffreys-smoothed per-run rates; runs averaged within unique "
            "seed blocks; seeds averaged within assigned role; roles equal-weighted"
        ),
    }


def statistics_mean(values: Iterable[float]) -> float:
    values = list(values)
    if not values:
        return math.nan
    return math.fsum(values) / len(values)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--traces",
        type=Path,
        default=ROOT / "results",
        help="directory containing v4 trace CSVs",
    )
    parser.add_argument("--pattern", default="**/trace.csv")
    parser.add_argument(
        "--fit-partition",
        choices=("training",),
        required=True,
        help=(
            "fit only the disjoint training partition; validation and test "
            "are rejected"
        ),
    )
    parser.add_argument(
        "--actual-gps-sigma",
        type=float,
        help="generation sigma if it is not embedded in the trace",
    )
    parser.add_argument(
        "--detector-gps-sigma",
        type=float,
        help="detector-assumed sigma if it is not embedded in the trace",
    )
    parser.add_argument("--warmup", type=float, default=5.0)
    parser.add_argument("--vmax", type=float, default=60.0)
    parser.add_argument("--speed-tolerance", type=float, default=15.0)
    parser.add_argument("--max-age", type=float, default=0.50)
    parser.add_argument("--rate-window", type=float, default=1.0)
    parser.add_argument("--rate-limit", type=float, default=20.0)
    parser.add_argument("--road-length", type=float, default=5000.0)
    parser.add_argument("--road-width", type=float, default=30.0)
    parser.add_argument("--min-ref-dt", type=float, default=0.5)
    parser.add_argument("--heading-cos-min", type=float, default=0.0)
    parser.add_argument("--speed-sigma", type=float, default=0.5)
    parser.add_argument("--replay-memory", type=int, default=500)
    parser.add_argument(
        "--output-json",
        type=Path,
        help="write a reproducible v4 simulator-fit artifact",
    )
    args = parser.parse_args()

    nonnegative = {
        "--actual-gps-sigma": args.actual_gps_sigma,
        "--detector-gps-sigma": args.detector_gps_sigma,
        "--warmup": args.warmup,
        "--max-age": args.max_age,
        "--road-length": args.road_length,
        "--road-width": args.road_width,
        "--min-ref-dt": args.min_ref_dt,
        "--speed-sigma": args.speed_sigma,
    }
    for name, value in nonnegative.items():
        if value is not None and (not math.isfinite(value) or value < 0.0):
            parser.error(f"{name} must be finite and non-negative")
    if (
        not math.isfinite(args.rate_window)
        or args.rate_window <= 0.0
        or not math.isfinite(args.rate_limit)
        or args.rate_limit <= 0.0
    ):
        parser.error("--rate-window and --rate-limit must be finite and positive")
    if args.replay_memory <= 0:
        parser.error("--replay-memory must be positive")
    if not args.fit_partition.strip():
        parser.error("--fit-partition cannot be empty")
    return args


def build_artifact(
    runs: list[RunCounts],
    config: Config,
    results: dict[str, dict[str, object]],
    args: argparse.Namespace,
) -> dict[str, object]:
    inputs = []
    for run in runs:
        inputs.append(
            {
                "path": str(run.meta.path),
                "sha256": run.sha256,
                "run_id": run.meta.run_id,
                "rng_seed": run.meta.seed,
                "attack_stratum": run.meta.attack,
                "partition": run.meta.partition,
                "message_counts": dict(zip(CLASS_NAMES, run.totals)),
                "firing_counts": {
                    check: dict(zip(CLASS_NAMES, run.fires[check]))
                    for check in CHECKS
                },
                "source_attacker_message_counts": dict(
                    zip(CLASS_NAMES, run.source_attacker_messages)
                ),
                "assigned_roles": sorted(run.roles),
                "assigned_role_message_counts": {
                    role: dict(zip(CLASS_NAMES, totals))
                    for role, totals in sorted(run.role_totals.items())
                },
                "assigned_role_firing_counts": {
                    check: {
                        role: dict(zip(CLASS_NAMES, values))
                        for role, values in sorted(
                            run.role_fires[check].items()
                        )
                    }
                    for check in CHECKS
                },
            }
        )
    input_set = hashlib.sha256(
        "".join(sorted(item["sha256"] for item in inputs)).encode("ascii")
    ).hexdigest()
    return {
        "schema": "v4_simulator_fit_evidence_weights",
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "label_definition": (
            "oracle_message_is_malicious; source-attacker membership is not a label"
        ),
        "fit_partition": args.fit_partition,
        "estimator": (
            "Jeffreys-smoothed per-run firing rates, averaged within RNG-seed "
            "blocks, then within explicit assigned-role strata, then equally "
            "across assigned-role strata"
        ),
        "configuration": asdict(config),
        "tool": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256(Path(__file__).resolve()),
        },
        "actual_gps_sigmas": sorted(
            {value for run in runs for value in run.actual_sigmas}
        ),
        "detector_gps_sigmas": sorted(
            {value for run in runs for value in run.detector_sigmas}
        ),
        "unique_rng_seeds": sorted({run.meta.seed for run in runs}),
        "attack_strata": sorted({run.meta.attack for run in runs}),
        "assigned_role_strata": sorted(
            {role for run in runs for role in run.roles}
        ),
        "input_set_sha256": input_set,
        "inputs": inputs,
        "checks": results,
        "caveat": (
            "Simulator-fit sensitivity weights only; not a calibrated posterior "
            "and not evidence of external generalization"
        ),
    }


def main() -> int:
    args = parse_args()
    files = sorted(args.traces.glob(args.pattern))
    if not files:
        print(
            f"error: no v4 training traces match {args.traces / args.pattern}. "
            "Calibration-training trace generation may not yet be wired into "
            "the experiment pipeline; do not substitute validation/test data.",
            file=sys.stderr,
        )
        return 2

    config = Config(
        warmup=args.warmup,
        vmax=args.vmax,
        speed_tolerance=args.speed_tolerance,
        max_age=args.max_age,
        rate_window=args.rate_window,
        rate_limit=args.rate_limit,
        road_length=args.road_length,
        road_width=args.road_width,
        min_ref_dt=args.min_ref_dt,
        heading_cos_min=args.heading_cos_min,
        speed_sigma=args.speed_sigma,
        replay_memory=args.replay_memory,
    )

    runs: list[RunCounts] = []
    seen_run_ids: set[str] = set()
    for path in files:
        try:
            meta = read_meta(path)
            if meta.partition != args.fit_partition:
                raise TraceSchemaError(
                    f"{path}: partition {meta.partition!r} does not match "
                    f"--fit-partition {args.fit_partition!r}"
                )
            if meta.run_id in seen_run_ids:
                raise TraceSchemaError(f"duplicate run ID {meta.run_id!r}")
            seen_run_ids.add(meta.run_id)
            with path.open(newline="") as handle:
                reader = csv.DictReader(handle)
                if reader.fieldnames is None:
                    raise TraceSchemaError(f"{path}: empty trace or missing header")
                schema = Schema.from_fields(reader.fieldnames)
            counts = RunCounts(meta)
            replay_file(path, schema, args, config, counts)
            counts.sha256 = sha256(path)
            runs.append(counts)
        except TraceSchemaError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    raw_totals = [sum(run.totals[label] for run in runs) for label in (0, 1)]
    if raw_totals[MALICIOUS] == 0 or raw_totals[HONEST] == 0:
        print(
            "error: fitting requires both explicitly malicious and honest "
            "post-warm-up messages",
            file=sys.stderr,
        )
        return 2

    results: dict[str, dict[str, object]] = {}
    print(
        f"{len(runs)} v4 training traces; "
        f"{len({run.meta.seed for run in runs})} unique RNG seeds; "
        f"{len({run.meta.attack for run in runs})} attack strata"
    )
    print(
        f"{raw_totals[MALICIOUS]:,} explicitly malicious and "
        f"{raw_totals[HONEST]:,} honest messages after warm-up\n"
    )
    print(
        f"{'check':16} {'d balanced':>12} {'d reference':>12} "
        f"{'f balanced':>12} {'f reference':>12} "
        f"{'weight fit':>11} {'weight ref':>11}"
    )
    for check in CHECKS:
        d_rate, d_detail = balanced_rate(runs, check, MALICIOUS)
        f_rate, f_detail = balanced_rate(runs, check, HONEST)
        if not math.isfinite(d_rate) or not math.isfinite(f_rate):
            print(f"error: no balanced cells for {check}", file=sys.stderr)
            return 2
        d_reference, f_reference = REFERENCE[check]
        weight = math.log(d_rate / f_rate)
        results[check] = {
            "malicious_message_firing_rate": d_rate,
            "honest_message_firing_rate": f_rate,
            "log_rate_ratio": weight,
            "reference_malicious_rate": d_reference,
            "reference_honest_rate": f_reference,
            "raw_malicious_firings": sum(
                run.fires[check][MALICIOUS] for run in runs
            ),
            "raw_honest_firings": sum(run.fires[check][HONEST] for run in runs),
            "malicious_balance": d_detail,
            "honest_balance": f_detail,
        }
        print(
            f"{check:16} {d_rate:12.6f} {d_reference:12.6f} "
            f"{f_rate:12.6f} {f_reference:12.6f} "
            f"{weight:11.3f} {math.log(d_reference / f_reference):11.3f}"
        )

    print("\nCandidate v4 simulator-fit table (review before use):")
    for check in CHECKS:
        result = results[check]
        print(
            f"    /* {check:14} */ "
            f"{{{result['malicious_message_firing_rate']:.6f}, "
            f"{result['honest_message_firing_rate']:.6f}}},"
        )

    artifact = build_artifact(runs, config, results, args)
    if args.output_json is not None:
        try:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(
                json.dumps(artifact, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"error: cannot write {args.output_json}: {exc}", file=sys.stderr)
            return 2
        print(f"\nWrote reproducible artifact: {args.output_json}")

    print(
        "\nCAVEAT: these are simulator-fit evidence weights. They are not a "
        "calibrated posterior or evidence of external generalization. Keep "
        "their training seeds disjoint from threshold selection and testing."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
