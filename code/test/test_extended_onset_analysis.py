#!/usr/bin/env python3
"""Focused regressions for extended metrics and onset-trajectory provenance."""

from __future__ import annotations

import csv
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import extended_analysis as extended  # noqa: E402
import make_onset_figure as onset  # noqa: E402


def write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def summary_row(
    experiment_id: str,
    *,
    family: str,
    arm: str,
    seed: int,
    serial: int,
    pairs: int,
    eligible_pairs: int,
    stream_fp: int = 0,
    clean_fp: int = 0,
) -> dict[str, object]:
    return {
        "experiment_id": experiment_id,
        "mode": "full",
        "stage": "test",
        "family": family,
        "arm": arm,
        "seed": seed,
        "serial": serial,
        "n": 2,
        "n_attackers": 0,
        "sim_time": 10,
        "eval_window_start_s": 4,
        "pairs": pairs,
        "eligible_pairs": eligible_pairs,
        "track_capacity_dropped_messages": 0,
        "stream_fp": stream_fp,
        "clean_fp": clean_fp,
        "received": 100,
    }


def pair_row(
    experiment_id: str,
    *,
    family: str,
    arm: str,
    seed: int,
    malicious: int = 0,
    clean: int = 1,
    alert: int = 1,
    delay: float = -1.0,
    censored: int = -1,
) -> dict[str, object]:
    return {
        "experiment_id": experiment_id,
        "mode": "full",
        "stage": "test",
        "family": family,
        "arm": arm,
        "seed": seed,
        "receiver_id": 0,
        "claimed_id": 1,
        "malicious_use": malicious,
        "clean_pair": clean,
        "messages": 10,
        "eligible": 1,
        "window_msgs": 5,
        "window_exposure_s": 1.0,
        "window_alert": alert,
        "stream_time_to_detect_s": delay,
        "stream_censored": censored,
        "track_count": 1,
        "track_alert": alert,
        "honest_track_alert": 0,
        "owner_track_alert": 0,
        "track_capacity_dropped_messages": 0,
        "track_purity": 1.0,
        "track_merges": 0,
        "track_fragments": 0,
        "track_id_switches": 0,
        "stride_class": "none",
        "stride_ambiguous": 0,
    }


def write_extended_artifacts(
    directory: Path,
    summaries: list[dict[str, object]],
    pairs: list[dict[str, object]],
) -> tuple[Path, Path]:
    summary_fields = sorted(
        extended.SUMMARY_REQUIRED | {"stream_fp", "clean_fp", "received"}
    )
    pair_fields = sorted(extended.PAIR_REQUIRED)
    summary_path = directory / "summary.csv"
    pair_path = directory / "pairs.csv"
    write_csv(summary_path, summary_fields, summaries)
    write_csv(pair_path, pair_fields, pairs)
    return summary_path, pair_path


def command_document(
    experiment_id: str, seed: int, *, gps_sigma: str = "2"
) -> dict[str, object]:
    options = [
        "--nVehicles=50",
        "--attackerFraction=0.3",
        "--attack=constoffset",
        f"--run={seed}",
        "--simTime=60",
        "--warmup=5",
        "--attackStart=10",
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
        f"--gpsSigma={gps_sigma}",
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


def make_config(
    directory: Path,
    experiment_id: str,
    seed: int,
    *,
    gps_sigma: str = "2",
) -> onset.RunConfig:
    run_dir = directory / experiment_id
    run_dir.mkdir()
    trace = run_dir / "trace.csv"
    trace.touch()
    (run_dir / "command.json").write_text(
        json.dumps(command_document(experiment_id, seed, gps_sigma=gps_sigma)),
        encoding="utf-8",
    )
    config = onset.load_run_config(
        trace, "command.json", "test", "pure_attack", "pure_constoffset"
    )
    if config is None:
        raise AssertionError("selected test trajectory was unexpectedly skipped")
    return config


def run_curve(config: onset.RunConfig, peak: float) -> onset.RunCurve:
    replay = SimpleNamespace(states={(0, 1): object()}, window_peaks={(1, 2): peak})
    zeros = np.zeros(1, dtype=float)
    counts = np.ones(1, dtype=np.int64)
    return onset.RunCurve(
        config=config,
        centers=zeros.copy(),
        attacker_sum=zeros.copy(),
        attacker_count=counts.copy(),
        honest_sum=zeros.copy(),
        honest_count=counts.copy(),
        replay=replay,  # type: ignore[arg-type]
        total_rows=1,
        attacker_rows=1,
        malicious_rows=1,
    )


class ExtendedAnalysisTests(unittest.TestCase):
    def test_pairless_and_partial_run_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            observed_id = "test__benign__benign__seed_0001"
            missing_id = "test__benign__benign__seed_0002"
            serial_id = "test__serial_timing__detector_on__seed_0003"
            summaries = [
                summary_row(
                    observed_id, family="benign", arm="benign", seed=1,
                    serial=0, pairs=1, eligible_pairs=1, stream_fp=1, clean_fp=1,
                ),
                summary_row(
                    missing_id, family="benign", arm="benign", seed=2,
                    serial=0, pairs=1, eligible_pairs=1,
                ),
                summary_row(
                    serial_id, family="serial_timing", arm="detector_on", seed=3,
                    serial=1, pairs=0, eligible_pairs=0,
                ),
            ]
            pairs = [
                pair_row(observed_id, family="benign", arm="benign", seed=1)
            ]
            summary_path, pair_path = write_extended_artifacts(root, summaries, pairs)
            output = root / "analysis"
            self.assertEqual(
                extended.main([
                    "--summary", str(summary_path), "--pairs", str(pair_path),
                    "--output-dir", str(output), "--allow-partial-pairs",
                    "--bootstrap-reps", "0",
                ]),
                0,
            )

            with (output / "arm_inventory.csv").open(newline="", encoding="utf-8") as handle:
                inventory = {(row["family"], row["arm"]): row for row in csv.DictReader(handle)}
            benign = inventory[("benign", "benign")]
            self.assertEqual(benign["pair_output_expected_runs"], "2")
            self.assertEqual(benign["pair_output_observed_runs"], "1")
            self.assertEqual(float(benign["pair_run_coverage"]), 0.5)
            self.assertEqual(benign["pair_metrics_status"], "partial")
            self.assertAlmostEqual(float(benign["receiver_minutes"]), 0.2)
            serial = inventory[("serial_timing", "detector_on")]
            self.assertEqual(serial["pair_metrics_status"], "not_applicable_no_pair_output")

            with (output / "extended_metrics.csv").open(newline="", encoding="utf-8") as handle:
                metrics = list(csv.DictReader(handle))
            self.assertFalse(any(row["family"] == "serial_timing" for row in metrics))
            by_name = {row["metric"]: row for row in metrics}
            per_run = by_name["stream_false_positives_per_run"]
            self.assertEqual(per_run["denominator"], "1")
            self.assertEqual(float(per_run["estimate"]), 1.0)
            per_minute = by_name["stream_false_positives_per_receiver_minute"]
            self.assertAlmostEqual(float(per_minute["denominator"]), 0.2)
            self.assertAlmostEqual(float(per_minute["estimate"]), 5.0)

    def test_post_onset_event_requires_window_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            experiment_id = "test__pure_attack__pure_constoffset__seed_0001"
            summaries = [
                summary_row(
                    experiment_id, family="pure_attack", arm="pure_constoffset",
                    seed=1, serial=0, pairs=1, eligible_pairs=1,
                )
            ]
            pairs = [
                pair_row(
                    experiment_id, family="pure_attack", arm="pure_constoffset",
                    seed=1, malicious=1, clean=0, alert=0, delay=0.2, censored=0,
                )
            ]
            summary_path, pair_path = write_extended_artifacts(root, summaries, pairs)
            with self.assertRaisesRegex(extended.AnalysisError, "lacks window alert"):
                extended.main([
                    "--summary", str(summary_path), "--pairs", str(pair_path),
                    "--output-dir", str(root / "analysis"), "--bootstrap-reps", "0",
                ])

    def test_alert_with_censored_post_onset_clock_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            experiment_id = "test__pure_attack__pure_constoffset__seed_0001"
            summaries = [
                summary_row(
                    experiment_id, family="pure_attack", arm="pure_constoffset",
                    seed=1, serial=0, pairs=1, eligible_pairs=1,
                )
            ]
            pairs = [
                pair_row(
                    experiment_id, family="pure_attack", arm="pure_constoffset",
                    seed=1, malicious=1, clean=0, alert=1, delay=-1, censored=1,
                )
            ]
            summary_path, pair_path = write_extended_artifacts(root, summaries, pairs)
            self.assertEqual(
                extended.main([
                    "--summary", str(summary_path), "--pairs", str(pair_path),
                    "--output-dir", str(root / "analysis"), "--bootstrap-reps", "0",
                ]),
                0,
            )


class OnsetAnalysisTests(unittest.TestCase):
    def test_selection_and_full_configuration_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = make_config(
                root, "test__pure_attack__pure_constoffset__seed_0001", 1
            )
            second = make_config(
                root, "test__pure_attack__pure_constoffset__seed_0002", 2,
                gps_sigma="4",
            )
            self.assertNotEqual(first.compatibility_key(), second.compatibility_key())

            other_dir = root / "test__onset_guard__constoffset_guard_0p25__seed_0003"
            other_dir.mkdir()
            trace = other_dir / "trace.csv"
            trace.touch()
            (other_dir / "command.json").write_text(
                json.dumps(command_document(other_dir.name, 3)), encoding="utf-8"
            )
            self.assertIsNone(
                onset.load_run_config(
                    trace, "command.json", "test", "pure_attack", "pure_constoffset"
                )
            )

    def test_pair_validation_is_required_and_peak_tolerance_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = make_config(
                root, "test__pure_attack__pure_constoffset__seed_0001", 1
            )
            curve = run_curve(config, 0.5001)
            with self.assertRaisesRegex(onset.OnsetError, "is required"):
                onset.validate_pairs(curve, "missing.csv", 1e-10)

            write_csv(
                config.trace.with_name("pairs.csv"),
                ["receiver_id", "claimed_id", "eligible", "window_peak_score", "window_alert"],
                [{
                    "receiver_id": 1, "claimed_id": 2, "eligible": 1,
                    "window_peak_score": 0.5, "window_alert": 1,
                }],
            )
            with self.assertRaisesRegex(onset.OnsetError, "exceeding tolerance"):
                onset.validate_pairs(curve, "pairs.csv", 1e-10)

            curve.replay.window_peaks[(1, 2)] = 0.5  # type: ignore[union-attr]
            compared, mismatches, difference = onset.validate_pairs(
                curve, "pairs.csv", 1e-10
            )
            self.assertEqual((compared, mismatches), (1, 0))
            self.assertEqual(difference, 0.0)
            curve.release_replay_state()
            self.assertIsNone(curve.replay)

    def test_guard_rows_are_stage_and_constoffset_specific(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "metrics.csv"
            fields = [
                "stage", "family", "arm", "metric", "mean", "ci95_low", "ci95_high"
            ]
            rows = [
                {
                    "stage": "test", "family": "onset_guard",
                    "arm": "constoffset_guard_0p25", "metric": "stream_tpr",
                    "mean": 0.7, "ci95_low": 0.6, "ci95_high": 0.8,
                },
                {
                    "stage": "test", "family": "onset_guard",
                    "arm": "mixedhard_guard_0p25", "metric": "stream_tpr",
                    "mean": 0.2, "ci95_low": 0.1, "ci95_high": 0.3,
                },
                {
                    "stage": "validation", "family": "onset_guard",
                    "arm": "constoffset_guard_0p5", "metric": "stream_tpr",
                    "mean": 0.1, "ci95_low": 0.0, "ci95_high": 0.2,
                },
                {
                    "stage": "test", "family": "pure_attack",
                    "arm": "pure_constoffset", "metric": "stream_tpr",
                    "mean": 0.8, "ci95_low": 0.7, "ci95_high": 0.9,
                },
            ]
            write_csv(path, fields, rows)
            points = onset.read_guard_metrics(
                path, "stream_tpr", "test", "onset_guard", "constoffset_guard_",
                "pure_attack", "pure_constoffset",
            )
            self.assertEqual([point.guard_s for point in points], [0.0, 0.25])
            self.assertEqual([point.estimate for point in points], [0.8, 0.7])

    def test_cli_defaults_are_constoffset_specific(self) -> None:
        args = onset.parse_args(["--traces", "/tmp/traces", "--output", "/tmp/x.png"])
        self.assertEqual(
            (args.trajectory_stage, args.trajectory_family, args.trajectory_arm),
            ("test", "pure_attack", "pure_constoffset"),
        )
        self.assertEqual(
            (args.guard_family, args.guard_arm_prefix, args.baseline_family, args.baseline_arm),
            ("onset_guard", "constoffset_guard_", "pure_attack", "pure_constoffset"),
        )
        self.assertTrue(math.isclose(args.peak_tolerance, 1e-10))


if __name__ == "__main__":
    unittest.main()
