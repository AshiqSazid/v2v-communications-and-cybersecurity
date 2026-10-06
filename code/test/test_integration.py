#!/usr/bin/env python3
"""Fast integration assertions against the built ns-3 executable."""

from __future__ import annotations

import argparse
import csv
import math
import subprocess
import tempfile
from pathlib import Path


SUMMARY_REQUIRED = {
    "schema",
    "n",
    "frac",
    "n_attackers",
    "attack",
    "run",
    "detector",
    "score_model",
    "threshold",
    "decay_half_life_s",
    "attack_start_s",
    "gps_sigma",
    "detector_gps_sigma",
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
    "contested_tp",
    "contested_fp",
    "contested_tn",
    "contested_fn",
    "victim_pairs",
    "victim_pairs_alerted",
    "victim_ids",
    "victim_ids_alerted",
    "victim_pairs_contested",
    "victim_ids_contested",
    "latency_sum_s",
    "latency_n",
    "latency_ms",
    "pdr_rx",
    "pdr_expected",
    "pdr",
    "assigned_attacker_rx",
    "attack_active_rx",
    "malicious_rx",
    "malicious_expected_pairs",
    "malicious_expected_pairs_observed",
    "malicious_observed_pairs_any_range",
    "malicious_zero_reception_pairs",
    "track_stream_tp",
    "track_stream_fp",
    "track_stream_tn",
    "track_stream_fn",
    "victim_pairs_track_alerted",
    "victim_ids_track_alerted",
    "track_capacity_dropped_messages",
}

PAIR_REQUIRED = {
    "schema",
    "receiver_id",
    "claimed_id",
    "source_count",
    "source_ids",
    "assigned_attacker_use",
    "attack_active_use",
    "malicious_use",
    "malicious_messages",
    "owner_is_attacker",
    "clean_pair",
    "victim_exposure_pair",
    "peak_score",
    "stream_peak_score",
    "final_score",
    "final_alert",
    "ever_alert",
    "stream_alert",
    "eligible",
    "window_msgs",
    "window_exposure_s",
    "window_peak_score",
    "window_first_exceed_s",
    "window_alert",
    "eval_window_start_s",
    "preexisting_alert",
    "post_onset_crossing_intervals",
    "first_malicious_seen_s",
    "first_stream_cross_s",
    "stream_time_to_detect_s",
    "stream_censor_time_s",
    "stream_censored",
    "observable_source_count",
    "observable_source_ipv4s",
    "identity_contested",
    "contested_stream_alert",
    "preexisting_contested",
    "track_alert",
    "honest_track_alert",
    "owner_track_peak",
    "owner_track_alert",
    "track_capacity_dropped_messages",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def integer(row: dict[str, str], field: str) -> int:
    value = float(row[field])
    require(math.isfinite(value) and value.is_integer(), f"{field} is not an integer")
    return int(value)


def binary(row: dict[str, str], field: str) -> bool:
    require(row[field] in {"0", "1"}, f"{field} is not binary: {row[field]!r}")
    return row[field] == "1"


def crossing_alert(encoded: str, threshold: float) -> bool:
    if not encoded:
        return False
    previous_high = -1.0
    for item in encoded.split("|"):
        pieces = item.split(":")
        require(len(pieces) == 2, f"malformed crossing interval: {item!r}")
        low, high = map(float, pieces)
        require(
            0.0 <= low < high <= 1.0 and low > previous_high,
            f"crossing intervals are not sorted, disjoint, and merged: {encoded!r}",
        )
        if low <= threshold < high:
            return True
        previous_high = high
    return False


def confusion(
    pairs: list[dict[str, str]], prediction, truth
) -> tuple[int, int, int, int]:
    tp = fp = tn = fn = 0
    for pair in pairs:
        pred, actual = prediction(pair), truth(pair)
        if pred and actual:
            tp += 1
        elif pred:
            fp += 1
        elif actual:
            fn += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def run_simulator(
    binary_path: Path,
    output_dir: Path,
    *,
    run: int,
    attack: str,
    fraction: float,
    clock_sigma: float,
    trace: bool = False,
) -> tuple[dict[str, str], list[dict[str, str]], Path | None]:
    pair_path = output_dir / f"pairs_{run}.csv"
    trace_path = output_dir / f"trace_{run}.csv" if trace else None
    command = [
        str(binary_path),
        "--nVehicles=14",
        f"--attackerFraction={fraction}",
        f"--attack={attack}",
        f"--run={run}",
        "--simTime=6",
        "--warmup=1",
        "--attackStart=3",
        "--interval=0.1",
        "--commRange=5000",
        "--gpsSigma=2",
        "--detectorGpsSigma=2",
        f"--clockSigma={clock_sigma}",
        f"--pairOutput={pair_path}",
    ]
    if trace_path is not None:
        command.append(f"--trace={trace_path}")
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    require(
        completed.returncode == 0,
        f"simulator failed ({completed.returncode}): {completed.stderr}",
    )
    csv_lines = [
        line.removeprefix("CSV,")
        for line in completed.stdout.splitlines()
        if line.startswith("CSV,")
    ]
    require(len(csv_lines) == 1, "simulator must emit exactly one CSV row")

    schema_result = subprocess.run(
        [str(binary_path), "--csvHeader=true"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    # --csvHeader emits the summary schema then the pair schema; take the first.
    headers = next(csv.reader([schema_result.stdout.strip().splitlines()[0]]))
    values = next(csv.reader([csv_lines[0]]))
    require(len(headers) >= len(SUMMARY_REQUIRED), "summary schema is unexpectedly narrow")
    require(len(headers) == len(set(headers)), "summary schema has duplicate columns")
    require(SUMMARY_REQUIRED <= set(headers), "summary schema is missing required fields")
    require(len(values) == len(headers), "summary row width differs from schema")
    summary = dict(zip(headers, values))
    require(summary["schema"] == "v6", "summary schema tag is not v6")

    with pair_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        require(reader.fieldnames is not None, "pair output has no header")
        require(len(reader.fieldnames) >= len(PAIR_REQUIRED), "pair schema is too narrow")
        require(
            len(reader.fieldnames) == len(set(reader.fieldnames)),
            "pair schema has duplicate columns",
        )
        require(PAIR_REQUIRED <= set(reader.fieldnames), "pair schema missing fields")
        pairs = list(reader)
    require(integer(summary, "pairs") == len(pairs), "summary/pair row count mismatch")
    require(all(pair["schema"] == "v6_pair" for pair in pairs), "bad pair schema tag")
    return summary, pairs, trace_path


def check_pair_metrics(summary: dict[str, str], pairs: list[dict[str, str]]) -> None:
    # Only pairs with exposure inside the evaluation window carry a decision;
    # the simulator excludes the rest from every arm rather than counting them
    # as true negatives, so the recomputation must do the same.
    eligible_pairs = [row for row in pairs if binary(row, "eligible")]
    require(
        integer(summary, "eligible_pairs") == len(eligible_pairs)
        and integer(summary, "ineligible_pairs") == len(pairs) - len(eligible_pairs),
        "eligible/ineligible pair counts disagree with the pair rows",
    )
    # THE regression check for the v4 defect: the stored decision must be
    # exactly the ranked statistic, thresholded.
    threshold = float(summary["threshold"])
    require(
        all(
            binary(row, "window_alert")
            == (float(row["window_peak_score"]) > threshold)
            for row in eligible_pairs
        ),
        "window_alert is not window_peak_score > threshold",
    )
    pairs = eligible_pairs
    stream = confusion(
        pairs,
        lambda row: binary(row, "window_alert"),
        lambda row: binary(row, "malicious_use"),
    )
    owner = confusion(
        pairs,
        lambda row: binary(row, "window_alert"),
        lambda row: binary(row, "owner_is_attacker"),
    )
    require(
        stream
        == tuple(
            integer(summary, field)
            for field in ("stream_tp", "stream_fp", "stream_tn", "stream_fn")
        ),
        "stream confusion cannot be reproduced from pair rows",
    )
    require(
        owner
        == tuple(
            integer(summary, field)
            for field in ("owner_tp", "owner_fp", "owner_tn", "owner_fn")
        ),
        "owner confusion cannot be reproduced from pair rows",
    )
    contested = confusion(
        pairs,
        lambda row: (
            binary(row, "contested_stream_alert")
            if binary(row, "malicious_use")
            else binary(row, "identity_contested")
        ),
        lambda row: binary(row, "malicious_use"),
    )
    require(
        contested
        == tuple(
            integer(summary, field)
            for field in ("contested_tp", "contested_fp", "contested_tn", "contested_fn")
        ),
        "contested-ID confusion cannot be reproduced from pair rows",
    )

    clean = [row for row in pairs if binary(row, "clean_pair")]
    require(
        sum(binary(row, "window_alert") for row in clean)
        == integer(summary, "clean_fp"),
        "clean FP count differs from pair output",
    )
    require(
        sum(not binary(row, "window_alert") for row in clean)
        == integer(summary, "clean_tn"),
        "clean TN count differs from pair output",
    )
    victims = [row for row in pairs if binary(row, "victim_exposure_pair")]
    require(len(victims) == integer(summary, "victim_pairs"), "victim pair mismatch")
    require(
        sum(binary(row, "window_alert") for row in victims)
        == integer(summary, "victim_pairs_alerted"),
        "post-onset alerted victim pair mismatch",
    )
    victim_ids = {row["claimed_id"] for row in victims}
    alerted_ids = {
        row["claimed_id"] for row in victims if binary(row, "window_alert")
    }
    require(len(victim_ids) == integer(summary, "victim_ids"), "victim ID mismatch")
    require(
        len(alerted_ids) == integer(summary, "victim_ids_alerted"),
        "alerted victim ID mismatch",
    )
    contested_victims = [
        row for row in victims if binary(row, "contested_stream_alert")
    ]
    require(
        len(contested_victims) == integer(summary, "victim_pairs_contested"),
        "post-onset contested victim pair mismatch",
    )
    require(
        len({row["claimed_id"] for row in contested_victims})
        == integer(summary, "victim_ids_contested"),
        "post-onset contested victim ID mismatch",
    )
    track_confusion = confusion(
        pairs,
        lambda row: binary(row, "track_alert"),
        lambda row: binary(row, "malicious_use"),
    )
    require(
        track_confusion
        == tuple(
            integer(summary, field)
            for field in (
                "track_stream_tp",
                "track_stream_fp",
                "track_stream_tn",
                "track_stream_fn",
            )
        ),
        "track confusion cannot be reproduced from pair rows",
    )
    owner_track_victims = [
        row for row in victims if binary(row, "owner_track_alert")
    ]
    require(
        len(owner_track_victims)
        == integer(summary, "victim_pairs_track_alerted")
        and len({row["claimed_id"] for row in owner_track_victims})
        == integer(summary, "victim_ids_track_alerted"),
        "owner-carrying track victim metric differs from pair rows",
    )

    for row in pairs:
        source_ids = set(filter(None, row["source_ids"].split(";")))
        require(
            len(source_ids) == integer(row, "source_count"),
            "source_count differs from source_ids",
        )
        observable_sources = set(
            filter(None, row["observable_source_ipv4s"].split(";"))
        )
        require(
            len(observable_sources) == integer(row, "observable_source_count"),
            "observable_source_count differs from observable_source_ipv4s",
        )
        require(
            binary(row, "identity_contested") == (len(observable_sources) > 1),
            "identity_contested differs from observable source multiplicity",
        )
        malicious = binary(row, "malicious_use")
        malicious_messages = integer(row, "malicious_messages")
        require(
            malicious == (malicious_messages > 0),
            "malicious_use differs from the malicious-message count",
        )
        require(
            malicious_messages <= integer(row, "window_msgs"),
            "malicious-message count exceeds W receptions",
        )
        if malicious:
            require(
                float(row["first_malicious_seen_s"])
                >= float(row["eval_window_start_s"]),
                "pair truth/latency origin begins before W",
            )
        if malicious:
            require(
                binary(row, "assigned_attacker_use")
                and binary(row, "attack_active_use"),
                "malicious pair lacks assigned/active attacker provenance",
            )
            threshold = float(summary["threshold"])
            require(
                crossing_alert(row["post_onset_crossing_intervals"], threshold)
                == binary(row, "stream_alert"),
                "runtime stream_alert differs from crossing-interval membership",
            )
        for field in ("peak_score", "stream_peak_score", "final_score"):
            value = float(row[field])
            require(0.0 <= value <= 1.0, f"{field} is outside [0,1]")
        stream_ttd = float(row["stream_time_to_detect_s"])
        if stream_ttd >= 0.0:
            require(malicious, "stream latency event belongs to a clean pair")
            require(
                binary(row, "window_alert"),
                "stream latency event lacks the primary window decision",
            )
            require(
                row["stream_censored"] == "0",
                "detected stream is marked censored",
            )
        elif malicious:
            require(
                row["stream_censored"] == "1",
                "undetected malicious stream is not censored",
            )
        else:
            require(
                row["stream_censored"] == "-1" and stream_ttd == -1.0,
                "clean pair does not use stream-survival sentinels",
            )
        if binary(row, "stream_alert"):
            first_hostile = float(row["first_malicious_seen_s"])
            first_cross = float(row["first_stream_cross_s"])
            require(first_hostile >= 0 and first_cross >= first_hostile, "bad stream times")
        if binary(row, "contested_stream_alert"):
            first_malicious = float(row["first_malicious_seen_s"])
            first_contested = float(row["first_stream_contested_s"])
            require(
                first_malicious >= 0.0 and first_contested >= first_malicious,
                "contested-ID mitigation credited a pre-onset transition",
            )

    require(
        sum(integer(row, "malicious_messages") for row in pairs)
        == integer(summary, "malicious_rx"),
        "summary malicious receptions differ from pair-level message truth",
    )
    require(
        sum(integer(row, "track_capacity_dropped_messages") for row in pairs)
        == integer(summary, "track_capacity_dropped_messages"),
        "summary track-capacity drops differ from pair counters",
    )


def check_network_metrics(summary: dict[str, str]) -> None:
    expected = integer(summary, "pdr_expected")
    received = integer(summary, "pdr_rx")
    require(expected > 0, "integration run has no expected receiver deliveries")
    require(0 <= received <= expected, "PDR numerator exceeds exact denominator")
    require(
        math.isclose(float(summary["pdr"]), received / expected, abs_tol=1e-12),
        "reported PDR differs from raw counts",
    )
    latency_n = integer(summary, "latency_n")
    latency_sum = float(summary["latency_sum_s"])
    require(latency_n == received, "latency and PDR must use the same deliveries")
    require(latency_sum >= 0.0, "true-time latency sum is negative")
    if latency_n:
        expected_ms = 1000.0 * latency_sum / latency_n
        require(
            math.isclose(float(summary["latency_ms"]), expected_ms, rel_tol=1e-12),
            "mean latency differs from sum/count",
        )
        require(float(summary["latency_ms"]) < 100.0, "network latency is implausibly high")

    expected_malicious_pairs = integer(summary, "malicious_expected_pairs")
    observed_expected_pairs = integer(summary, "malicious_expected_pairs_observed")
    zero_reception_pairs = integer(summary, "malicious_zero_reception_pairs")
    observed_any_range = integer(summary, "malicious_observed_pairs_any_range")
    require(
        observed_expected_pairs + zero_reception_pairs == expected_malicious_pairs,
        "malicious opportunity accounting does not partition expected pairs",
    )
    require(
        observed_any_range >= observed_expected_pairs,
        "all-range observed malicious pairs omit an expected in-range pair",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    binary_path = args.binary.resolve()
    require(binary_path.is_file(), f"binary not found: {binary_path}")

    invalid = subprocess.run(
        [str(binary_path), "--attack=not-an-attack"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    require(invalid.returncode == 2, "unknown attack must fail with status 2")

    # attackStart at or beyond simTime leaves no evaluation window; a negative
    # onset is meaningless. attackStart == warmup is now legal.
    for attack_start in ("6", "7", "-1"):
        invalid_onset = subprocess.run(
            [
                str(binary_path),
                "--simTime=6",
                "--warmup=2",
                f"--attackStart={attack_start}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        require(
            invalid_onset.returncode == 2,
            f"attackStart={attack_start} must be rejected",
        )

    # attackStart=0 is the steady-state arm and MUST be accepted: it is the
    # only way to measure detectability without an onset discontinuity.
    steady = subprocess.run(
        [
            str(binary_path),
            "--simTime=6",
            "--warmup=2",
            "--attackStart=0",
            "--nVehicles=6",
            "--attack=constoffset",
            "--attackerFraction=0.34",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    require(
        steady.returncode == 0,
        "attackStart=0 (steady-state arm) must be accepted",
    )

    with tempfile.TemporaryDirectory(prefix="v2v-integration-") as directory:
        output_dir = Path(directory)
        clean_zero, clean_pairs, _ = run_simulator(
            binary_path,
            output_dir,
            run=9811,
            attack="none",
            fraction=0.0,
            clock_sigma=0.0,
        )
        clean_skew, _, _ = run_simulator(
            binary_path,
            output_dir,
            run=9811,
            attack="none",
            fraction=0.0,
            clock_sigma=0.5,
        )
        mixed, mixed_pairs, trace_path = run_simulator(
            binary_path,
            output_dir,
            run=9812,
            attack="mixedhard",
            fraction=0.5,
            clock_sigma=0.02,
            trace=True,
        )

        check_pair_metrics(clean_zero, clean_pairs)
        check_pair_metrics(mixed, mixed_pairs)
        check_network_metrics(clean_zero)
        check_network_metrics(clean_skew)
        check_network_metrics(mixed)

        # The same RNG run draws the same mobility/channel process. Clock
        # offsets change only forgeable content, so corrected TX-registry
        # delivery and latency measurements must remain identical.
        for field in (
            "pdr_rx",
            "pdr_expected",
            "latency_n",
            "latency_sum_s",
            "latency_ms",
        ):
            require(
                clean_zero[field] == clean_skew[field],
                f"{field} incorrectly depends on sender-asserted clock time",
            )

        require(integer(mixed, "n_attackers") == 7, "mixedhard attacker count is wrong")
        require(trace_path is not None and trace_path.is_file(), "trace was not created")
        raw_trace_rows = list(csv.reader(trace_path.read_text(encoding="utf-8").splitlines()))
        require(len(raw_trace_rows) > 1, "trace has no raw data rows")
        raw_header = raw_trace_rows[0]
        precision_fields = ("rx_time", "claimed_x", "oracle_true_x")
        precision_indices = [raw_header.index(field) for field in precision_fields]

        def significant_digits(token: str) -> int:
            mantissa = token.lower().split("e", 1)[0].lstrip("+-")
            digits = mantissa.replace(".", "").lstrip("0")
            return len(digits)

        numeric_tokens = [
            row[index]
            for row in raw_trace_rows[1:]
            for index in precision_indices
        ]
        require(
            any(significant_digits(token) >= 15 for token in numeric_tokens),
            "raw trace appears truncated below double-precision replay fidelity",
        )
        require(
            all(
                float(format(float(token), ".17g")) == float(token)
                for token in numeric_tokens
            ),
            "raw trace numeric values do not survive a 17-digit round trip",
        )
        with trace_path.open(newline="", encoding="utf-8") as handle:
            trace_reader = csv.DictReader(handle)
            fields = set(trace_reader.fieldnames or ())
            required_trace = {
                "receiver_id",
                "receiver_true_x",
                "receiver_true_y",
                "observable_source_ipv4",
                "claimed_id",
                "oracle_source_id",
                "oracle_tx_seq",
                "oracle_tx_time",
                "oracle_source_is_attacker",
                "oracle_assigned_role",
                "oracle_attack_active",
                "oracle_message_is_malicious",
                "oracle_victim_id",
                "oracle_owner_is_attacker",
                "oracle_expected_receiver",
            }
            require(required_trace <= fields, "v4 trace is missing truth/observable fields")
            rows = list(trace_reader)
            require(rows, "v4 trace has no observations")

        measured = [row for row in rows if float(row["rx_time"]) >= 1.0]
        attacker_rows = [
            row for row in measured if binary(row, "oracle_source_is_attacker")
        ]
        preattack = [
            row for row in attacker_rows if float(row["oracle_tx_time"]) < 3.0
        ]
        postattack = [
            row for row in attacker_rows if float(row["oracle_tx_time"]) >= 3.0
        ]
        require(preattack, "trace has no assigned-attacker pre-onset history")
        require(postattack, "trace has no assigned-attacker post-onset observations")
        require(
            all(
                not binary(row, "oracle_attack_active")
                and not binary(row, "oracle_message_is_malicious")
                for row in preattack
            ),
            "assigned attackers are not honest before attackStart",
        )
        require(
            all(binary(row, "oracle_attack_active") for row in postattack),
            "assigned attackers are not marked active after attackStart",
        )
        malicious_rows = [
            row for row in measured if binary(row, "oracle_message_is_malicious")
        ]
        require(malicious_rows, "mixedhard trace has no malicious messages")
        require(
            all(
                binary(row, "oracle_source_is_attacker")
                and binary(row, "oracle_attack_active")
                for row in malicious_rows
            ),
            "message-level maliciousness is inconsistent with source/onset truth",
        )
        honest_rows = [
            row for row in measured if not binary(row, "oracle_source_is_attacker")
        ]
        require(
            all(
                row["oracle_assigned_role"] == "honest"
                and not binary(row, "oracle_attack_active")
                and not binary(row, "oracle_message_is_malicious")
                for row in honest_rows
            ),
            "honest sources carry active/malicious oracle labels",
        )

        window_rows = [row for row in rows if float(row["rx_time"]) >= 3.0]
        window_attacker_rows = [
            row for row in window_rows if binary(row, "oracle_source_is_attacker")
        ]
        window_malicious_rows = [
            row for row in window_rows if binary(row, "oracle_message_is_malicious")
        ]
        for field, expected in (
            ("assigned_attacker_rx", len(window_attacker_rows)),
            (
                "attack_active_rx",
                sum(binary(row, "oracle_attack_active") for row in window_rows),
            ),
            ("malicious_rx", len(window_malicious_rows)),
        ):
            require(integer(mixed, field) == expected, f"trace/summary {field} mismatch")

        unique_tx: dict[str, dict[str, float]] = {}
        for row in attacker_rows:
            role = row["oracle_assigned_role"]
            key = f"{row['oracle_source_id']}:{row['oracle_tx_seq']}"
            unique_tx.setdefault(role, {})[key] = float(row["oracle_tx_time"])
        dos_times = sorted(unique_tx.get("dos", {}).values())
        dos_pre = [time for time in dos_times if 1.0 <= time < 3.0]
        dos_post = [time for time in dos_times if 3.0 <= time < 6.0]
        require(dos_pre and dos_post, "mixedhard trace lacks both DoS timing phases")
        require(
            len(dos_post) / 3.0 > 3.0 * (len(dos_pre) / 2.0),
            "DoS sender did not switch from nominal to accelerated post-onset rate",
        )

    print("All ns-3 integration assertions passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
