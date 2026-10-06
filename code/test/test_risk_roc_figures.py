#!/usr/bin/env python3
"""Focused regressions for held-out ROC and risk-figure population contracts."""

from __future__ import annotations

import csv
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import make_risk_figure as risk  # noqa: E402
import make_roc_figure as roc  # noqa: E402


FIELDS = (
    "mode",
    "stage",
    "family",
    "arm",
    "seed",
    "attack",
    "n",
    "frac",
    "eligible",
    "window_peak_score",
    "malicious_use",
    "clean_pair",
    "trust_decision",
    "priority_index",
    "stride_class",
    "stride_ambiguous",
)


def row(
    *,
    stage: str,
    family: str,
    attack: str,
    malicious: bool,
    clean: bool,
    score: object,
    decision: str,
    priority: object,
    stride: str = "none",
    ambiguous: object = 0,
    seed: int = 1,
    n: int = 50,
    frac: float = 0.3,
    arm: str | None = None,
) -> dict[str, object]:
    if arm is None:
        arm = f"validation_{attack}" if stage == "validation" else f"pure_{attack}"
    return {
        "mode": "full",
        "stage": stage,
        "family": family,
        "arm": arm,
        "seed": seed,
        "attack": attack,
        "n": n,
        "frac": frac,
        "eligible": 1,
        "window_peak_score": score,
        "malicious_use": int(malicious),
        "clean_pair": int(clean),
        "trust_decision": decision,
        "priority_index": priority,
        "stride_class": stride,
        "stride_ambiguous": ambiguous,
    }


def matched_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index, attack in enumerate(roc.ATTACK_ORDER, 1):
        for stage, positive_score, negative_score in (
            ("validation", 0.82, 0.18),
            ("test", 0.74, 0.26),
        ):
            family = "threshold_selection" if stage == "validation" else "pure_attack"
            rows.extend(
                [
                    row(
                        stage=stage,
                        family=family,
                        attack=attack,
                        malicious=True,
                        clean=False,
                        score=positive_score,
                        decision="compromised",
                        priority=0.6,
                        stride="tampering",
                        seed=index,
                    ),
                    row(
                        stage=stage,
                        family=family,
                        attack=attack,
                        malicious=False,
                        clean=True,
                        score=negative_score,
                        decision=(
                            "trusted" if attack == "falsify" else "compromised"
                        ),
                        priority=0.4,
                        seed=index,
                    ),
                ]
            )
            if stage == "test":
                # A trusted hostile row must affect TPR but never Q/STRIDE.
                rows.append(
                    row(
                        stage=stage,
                        family=family,
                        attack=attack,
                        malicious=True,
                        clean=False,
                        score=0.35,
                        decision="trusted",
                        priority=0.99,
                        stride="spoofing",
                        seed=index,
                    )
                )
                # A victim stream is neither a hostile stream nor clean_pair.
                rows.append(
                    row(
                        stage=stage,
                        family=family,
                        attack=attack,
                        malicious=False,
                        clean=False,
                        score=1.0,
                        decision="compromised",
                        priority=1.0,
                        stride="spoofing",
                        seed=index,
                    )
                )
    # Extreme controls would change every result if family filtering regressed.
    rows.extend(
        [
            row(
                stage="test",
                family="onset_time",
                arm="constoffset_onset_5s",
                attack="constoffset",
                malicious=True,
                clean=False,
                score=0.0,
                decision="compromised",
                priority=1.0,
                stride="spoofing",
                seed=999,
            ),
            row(
                stage="test",
                family="onset_guard",
                arm="constoffset_guard_2s",
                attack="constoffset",
                malicious=False,
                clean=True,
                score=1.0,
                decision="compromised",
                priority=1.0,
                seed=999,
            ),
        ]
    )
    return rows


def write_rows(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class RocFigureTests(unittest.TestCase):
    def test_ties_move_together_and_metrics_are_descriptive(self) -> None:
        scores = np.array([0.9, 0.9, 0.2, 0.2])
        truth = np.array([True, False, True, False])
        fpr, tpr, recall, precision, auc, average_precision = roc.curves(scores, truth)
        np.testing.assert_allclose(fpr, [0.0, 0.5, 1.0])
        np.testing.assert_allclose(tpr, [0.0, 0.5, 1.0])
        np.testing.assert_allclose(recall, [0.0, 0.5, 1.0])
        np.testing.assert_allclose(precision, [1.0, 0.5, 0.5])
        self.assertAlmostEqual(auc, 0.5)
        self.assertAlmostEqual(average_precision, 0.5)

    def test_filters_controls_victims_and_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pairs = root / "pairs.csv"
            write_rows(pairs, matched_rows())
            loaded = roc.load(pairs)
            for stage in ("validation", "test"):
                population = loaded.populations[stage]
                expected = 14 if stage == "validation" else 21
                # Test has two hostile rows and one clean row per attack; the
                # neither-hostile-nor-clean victim and controls are excluded.
                self.assertEqual(population.scores.size, expected)
                self.assertEqual(population.n_vehicles, 50)
                self.assertEqual(population.attacker_fraction, 0.3)
            self.assertEqual(loaded.clean_test_scores.size, 7)
            self.assertEqual(loaded.hostile_test_scores.size, 14)

            threshold = root / "threshold.json"
            threshold.write_text(json.dumps({"threshold": 0.5}), encoding="utf-8")
            figures = root / "figures"
            metrics = root / "roc_metrics.csv"
            self.assertEqual(
                roc.main(
                    [
                        "--pairs",
                        str(pairs),
                        "--threshold-json",
                        str(threshold),
                        "--metrics-csv",
                        str(metrics),
                        "--out",
                        str(figures),
                    ]
                ),
                0,
            )
            self.assertTrue((figures / "fig_roc.pdf").is_file())
            self.assertTrue((figures / "fig_roc.png").is_file())
            with metrics.open(newline="", encoding="utf-8") as handle:
                metric_rows = list(csv.DictReader(handle))
            self.assertEqual(len(metric_rows), 4)
            self.assertTrue(
                all("descriptive" in metric["uncertainty"] for metric in metric_rows)
            )
            self.assertTrue(
                all(metric["aggregation_unit"].endswith("(pooled)") for metric in metric_rows)
            )

    def test_mismatched_n_and_malformed_required_score_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = matched_rows()
            for candidate in rows:
                if (
                    candidate["stage"] == "validation"
                    and candidate["attack"] == "spoof"
                ):
                    candidate["n"] = 70
            mismatch = root / "mismatch.csv"
            write_rows(mismatch, rows)
            with self.assertRaisesRegex(roc.RocFigureError, "N mismatch for spoof"):
                roc.load(mismatch)

            rows = matched_rows()
            next(
                candidate
                for candidate in rows
                if candidate["stage"] == "test" and candidate["family"] == "pure_attack"
            )["window_peak_score"] = "not-a-number"
            malformed = root / "malformed.csv"
            write_rows(malformed, rows)
            with self.assertRaisesRegex(
                roc.RocFigureError, "invalid window_peak_score"
            ):
                roc.load(malformed)


class RiskFigureTests(unittest.TestCase):
    def test_alert_conditioning_clean_negative_and_zero_alert_na(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pairs = root / "pairs.csv"
            write_rows(pairs, matched_rows())
            loaded = risk.load(pairs)

            # For falsify, only the compromised hostile row contributes Q and
            # STRIDE.  The trusted hostile row's Q=.99/tag=spoofing is absent.
            self.assertEqual(loaded.priority[("falsify", 1, True)], [0.6, 1.0])
            self.assertNotIn(("falsify", 1, False), loaded.priority)
            self.assertEqual(loaded.stride[("falsify", 1, "tampering")], 1)
            self.assertNotIn(("falsify", 1, "spoofing"), loaded.stride)
            self.assertEqual(loaded.confusion[("falsify", 1)], [1, 1, 0, 1])

            figures = root / "figures"
            metrics = root / "risk_metrics.csv"
            rendered = risk.render(
                loaded,
                out_dir=figures,
                out_csv=metrics,
                bootstrap_replicates=100,
                bootstrap_seed=7,
            )
            indexed = {
                (entry["attack"], entry["metric"], entry["stratum"]): entry
                for entry in rendered
            }
            clean_q = indexed[("falsify", "mean_peak_priority", "clean")]
            self.assertEqual(clean_q["mean"], "NA")
            self.assertEqual(clean_q["ci95_low"], "NA")
            self.assertEqual(clean_q["ci95_high"], "NA")
            self.assertEqual(clean_q["denominator"], 0)
            self.assertEqual(clean_q["status"], "NA_no_alerted_pairs")
            hostile_q = indexed[("falsify", "mean_peak_priority", "hostile")]
            self.assertEqual(hostile_q["denominator"], 1)
            self.assertAlmostEqual(float(hostile_q["mean"]), 0.6)
            stride_share = indexed[("falsify", "stride_share", "tampering")]
            self.assertAlmostEqual(float(stride_share["mean"]), 1.0)
            self.assertIn("seed-block", stride_share["ci_method"])
            self.assertTrue((figures / "fig_risk.pdf").is_file())
            self.assertTrue((figures / "fig_risk.png").is_file())
            text = metrics.read_text(encoding="utf-8").lower()
            self.assertNotIn("nan", text)
            self.assertIn("na_no_alerted_pairs", text)

    def test_malformed_alert_priority_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pairs = Path(temporary) / "pairs.csv"
            rows = matched_rows()
            next(
                candidate
                for candidate in rows
                if candidate["stage"] == "test"
                and candidate["family"] == "pure_attack"
                and candidate["malicious_use"] == 1
                and candidate["trust_decision"] == "compromised"
            )["priority_index"] = math.inf
            write_rows(pairs, rows)
            with self.assertRaisesRegex(
                risk.RiskFigureError, "priority_index must be finite"
            ):
                risk.load(pairs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
