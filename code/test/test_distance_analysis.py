#!/usr/bin/env python3
"""Focused regressions for the received-distance held-out analysis."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import distance_analysis as distance  # noqa: E402


TRACE_FIELDS = (
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
)

PAIR_FIELDS = (
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
)


def write_csv(
    path: Path,
    fields: tuple[str, ...],
    rows: list[dict[str, object]],
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def command_document(experiment_id: str, seed: int, attack: str) -> dict[str, object]:
    options = [
        "--nVehicles=20",
        "--attackerFraction=0.3",
        f"--attack={attack}",
        f"--run={seed}",
        "--simTime=10",
        "--warmup=2",
        "--attackStart=5",
        "--onsetBlank=0",
        "--interval=0.1",
        "--detector=true",
        "--scoreModel=reference",
        "--nullEvidence=false",
        "--naiveThresholds=false",
        "--prior=0.05",
        "--threshold=0.4",
        "--decayHalfLife=3.43",
        "--commRange=300",
        "--gpsSigma=2",
        "--detectorGpsSigma=2",
        "--mobility=constant",
        "--spdSigma=0.5",
        "--clockSigma=0.02",
        "--bsmBytes=320",
        "--pairOutput=/tmp/pairs.csv",
        "--trace=/tmp/trace.csv",
    ]
    return {
        "experiment_id": experiment_id,
        "seed": seed,
        "command_argv": ["simulator", *options],
    }


def make_run(
    root: Path,
    attack: str,
    seed: int,
    endpoints: list[tuple[float, bool, float]],
) -> Path:
    experiment_id = f"test__pure_attack__pure_{attack}__seed_{seed:04d}"
    run_dir = root / experiment_id
    run_dir.mkdir()
    (run_dir / "command.json").write_text(
        json.dumps(command_document(experiment_id, seed, attack)),
        encoding="utf-8",
    )
    traces: list[dict[str, object]] = []
    pairs: list[dict[str, object]] = []
    for index, (separation, alert, delay_s) in enumerate(endpoints, 1):
        traces.append(
            {
                "receiver_id": 0,
                "rx_time": 6 + index / 100,
                "receiver_true_x": 0,
                "receiver_true_y": 0,
                "claimed_id": index,
                "oracle_source_id": 19,
                "oracle_true_x": separation,
                "oracle_true_y": 0,
                "oracle_source_is_attacker": 1,
                "oracle_attack_active": 1,
                "oracle_message_is_malicious": 1,
            }
        )
        pairs.append(
            {
                "schema": "v6_pair",
                "attack": attack,
                "run": seed,
                "attack_start_s": 5,
                "receiver_id": 0,
                "claimed_id": index,
                "malicious_use": 1,
                "malicious_messages": 1,
                "messages": 1,
                "eval_window_start_s": 5,
                "eligible": 1,
                "window_msgs": 1,
                "window_alert": int(alert),
                "stream_time_to_detect_s": delay_s if alert else -1,
                "stream_censored": 0 if alert else 1,
            }
        )
    write_csv(run_dir / "trace.csv", TRACE_FIELDS, traces)
    write_csv(run_dir / "pairs.csv", PAIR_FIELDS, pairs)
    return run_dir / "trace.csv"


class DistanceAnalysisTests(unittest.TestCase):
    def test_predeclared_bin_edges(self) -> None:
        cases = {
            0.0: "0-100",
            99.999999: "0-100",
            100.0: "100-200",
            199.999999: "100-200",
            200.0: "200-300",
            300.0: "200-300",
            300.000001: ">300",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(distance.distance_bin(value).label, expected)

    def test_stream_join_preserves_attack_strata_and_pool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_run(
                root,
                "spoof",
                1,
                [(0.0, True, 0.1), (100.0, False, -1),
                 (200.0, True, 0.3), (300.000001, False, -1)],
            )
            make_run(root, "dos", 1, [(50.0, True, 0.2)])
            rows = distance.analyze(
                [root], "**/trace.csv", "command.json", "pairs.csv",
                "test", "pure_attack", 100, 77,
            )
            indexed = {
                (row["attack_stratum"], row["distance_bin"]): row for row in rows
            }
            self.assertEqual(len(rows), 12)
            self.assertEqual(indexed[("spoof", "0-100")]["pair_count"], 1)
            self.assertEqual(indexed[("spoof", "100-200")]["pair_count"], 1)
            self.assertEqual(indexed[("spoof", "200-300")]["pair_count"], 1)
            self.assertEqual(indexed[("spoof", ">300")]["pair_count"], 1)
            self.assertEqual(indexed[("pooled", "0-100")]["pair_count"], 2)
            self.assertEqual(
                indexed[("pooled", "0-100")]["received_malicious_messages"], 2
            )
            self.assertEqual(indexed[("spoof", "100-200")]["tpr"], "0")
            self.assertEqual(
                indexed[("spoof", "100-200")]["censor_fraction"], "1"
            )
            self.assertEqual(
                indexed[("spoof", "200-300")]["median_detected_delay_s"],
                "0.3",
            )
            self.assertIn("conditional on malicious messages received", distance.DISTANCE_ESTIMAND)

    def test_seed_block_bootstrap_is_deterministic(self) -> None:
        observations = [
            distance.Observation(
                attack="spoof",
                seed=seed,
                receiver_id=0,
                claimed_id=seed,
                mean_distance_m=50,
                distance_sum_m=50,
                malicious_messages=1,
                alert=alert,
                delay_s=float(seed) if alert else None,
                censored=not alert,
            )
            for seed, alert in ((1, True), (2, False), (3, True), (4, False))
        ]
        first = distance.bootstrap_intervals(observations, 500, 12345)
        second = distance.bootstrap_intervals(observations, 500, 12345)
        self.assertEqual(first, second)
        # Replicates containing only censored seed blocks have no detected-only
        # delay statistic and are deliberately excluded (and counted).
        self.assertGreater(first["delay_valid_reps"], 0)
        self.assertLess(first["delay_valid_reps"], 500)

    def test_missing_sibling_and_missing_schema_field_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = make_run(root, "spoof", 1, [(50.0, True, 0.2)])
            trace.with_name("pairs.csv").unlink()
            with self.assertRaisesRegex(
                distance.DistanceAnalysisError, "sibling pairs.csv is missing"
            ):
                distance.analyze(
                    [trace], "**/trace.csv", "command.json", "pairs.csv",
                    "test", "pure_attack", 10, 1,
                )

            trace = make_run(root, "dos", 2, [(50.0, True, 0.2)])
            malformed_fields = tuple(
                field for field in TRACE_FIELDS if field != "oracle_true_y"
            )
            with trace.open(newline="", encoding="utf-8") as handle:
                original = next(csv.DictReader(handle))
            write_csv(
                trace,
                malformed_fields,
                [{field: original[field] for field in malformed_fields}],
            )
            with self.assertRaisesRegex(
                distance.DistanceAnalysisError, "missing trace fields"
            ):
                distance.analyze(
                    [trace], "**/trace.csv", "command.json", "pairs.csv",
                    "test", "pure_attack", 10, 1,
                )

    def test_count_mismatch_and_duplicate_pair_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = make_run(root, "spoof", 1, [(50.0, True, 0.2)])
            pair_path = trace.with_name("pairs.csv")
            with pair_path.open(newline="", encoding="utf-8") as handle:
                pair = next(csv.DictReader(handle))
            mismatched = dict(pair)
            mismatched["messages"] = 2
            write_csv(pair_path, PAIR_FIELDS, [mismatched])
            config = distance.load_config(
                trace, "command.json", "pairs.csv", "test", "pure_attack"
            )
            self.assertIsNotNone(config)
            with self.assertRaisesRegex(
                distance.DistanceAnalysisError, "trace/pair message counts disagree"
            ):
                distance.join_run(config)  # type: ignore[arg-type]

            write_csv(pair_path, PAIR_FIELDS, [pair, pair])
            config = distance.load_config(
                trace, "command.json", "pairs.csv", "test", "pure_attack"
            )
            self.assertIsNotNone(config)
            with self.assertRaisesRegex(distance.DistanceAnalysisError, "duplicate pair row"):
                distance.join_run(config)  # type: ignore[arg-type]

    def test_no_eligible_hostile_rows_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = make_run(root, "spoof", 1, [(50.0, True, 0.2)])
            with trace.open(newline="", encoding="utf-8") as handle:
                trace_row = next(csv.DictReader(handle))
            trace_row["oracle_message_is_malicious"] = "0"
            write_csv(trace, TRACE_FIELDS, [trace_row])
            pair_path = trace.with_name("pairs.csv")
            with pair_path.open(newline="", encoding="utf-8") as handle:
                pair = next(csv.DictReader(handle))
            pair.update(
                {
                    "malicious_use": "0",
                    "malicious_messages": "0",
                    "window_alert": "0",
                    "stream_time_to_detect_s": "-1",
                    "stream_censored": "-1",
                }
            )
            write_csv(pair_path, PAIR_FIELDS, [pair])
            with self.assertRaisesRegex(
                distance.DistanceAnalysisError,
                "no eligible hostile received-exposure pairs",
            ):
                distance.analyze(
                    [trace], "**/trace.csv", "command.json", "pairs.csv",
                    "test", "pure_attack", 10, 1,
                )

    def test_incompatible_run_metadata_cannot_be_pooled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_run(root, "spoof", 1, [(50.0, True, 0.2)])
            second = make_run(root, "dos", 1, [(50.0, True, 0.2)])
            command_path = second.with_name("command.json")
            document = json.loads(command_path.read_text(encoding="utf-8"))
            document["command_argv"] = [
                "--gpsSigma=8" if item == "--gpsSigma=2" else item
                for item in document["command_argv"]
            ]
            command_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(
                distance.DistanceAnalysisError, "metadata is incompatible"
            ):
                distance.analyze(
                    [root], "**/trace.csv", "command.json", "pairs.csv",
                    "test", "pure_attack", 10, 1,
                )


if __name__ == "__main__":
    unittest.main()
