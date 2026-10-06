#!/usr/bin/env python3
"""Behavioral regressions for the v4 selector and experiment plan."""

from __future__ import annotations

import csv
import hashlib
import math
import os
import re
import sys
import tempfile
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import aggregate  # noqa: E402
import baselines  # noqa: E402
import experiment_pipeline  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def require_raises(callable_, message: str) -> None:
    try:
        callable_()
    except aggregate.AnalysisError:
        return
    raise AssertionError(message)


def test_crossing_contract() -> None:
    intervals = aggregate.parse_crossing_intervals("0.2:0.4|0.7:0.9")
    require(intervals == ((0.2, 0.4), (0.7, 0.9)), "interval parser changed values")
    require(aggregate.crossing_alert(intervals, 0.2), "lower endpoint is inclusive")
    require(not aggregate.crossing_alert(intervals, 0.4), "upper endpoint is exclusive")
    require(aggregate.crossing_alert(intervals, 0.7), "second lower endpoint is inclusive")
    require(not aggregate.crossing_alert(intervals, 0.9), "last upper endpoint is exclusive")
    require_raises(
        lambda: aggregate.parse_crossing_intervals("0.2:0.4|0.4:0.8"),
        "unmerged adjacent intervals were accepted",
    )
    require_raises(
        lambda: aggregate.parse_crossing_intervals("0.8:0.2"),
        "reversed interval was accepted",
    )


def add_pair(
    data: aggregate.PairArrays,
    *,
    seed: int,
    malicious: bool,
    peak: float,
    crossings: tuple[tuple[float, float], ...] = (),
    benign: bool = False,
) -> None:
    code = data.seed_code(seed)
    data.seed_codes.append(code)
    data.truth.append(int(malicious))
    data.owner_scores.append(peak)
    data.scores.append(peak)
    data.benign_validation.append(int(benign))
    data.crossings.append(crossings)


def test_selector_runtime_equivalence() -> None:
    """The selector must replay exactly the runtime decision, for both classes."""

    data = aggregate.PairArrays()
    add_pair(
        data,
        seed=101,
        malicious=True,
        peak=0.95,
        crossings=((0.2, 0.4), (0.7, 0.9)),
    )
    add_pair(data, seed=101, malicious=False, peak=0.6)
    add_pair(data, seed=101, malicious=False, peak=0.1, benign=True)
    add_pair(
        data,
        seed=102,
        malicious=True,
        peak=0.95,
        crossings=((0.3, 0.5),),
    )
    add_pair(data, seed=102, malicious=False, peak=0.2)
    add_pair(data, seed=102, malicious=False, peak=0.1, benign=True)

    grid = aggregate.deterministic_threshold_grid(0.1)
    tp, fp, positives, clean_fpr = aggregate.threshold_count_matrices(data, grid)
    truths = np.frombuffer(data.truth, dtype=np.uint8).astype(bool)
    seed_codes = np.frombuffer(data.seed_codes, dtype=np.uint32)
    peaks = np.frombuffer(data.owner_scores, dtype=np.float64)
    for grid_index, threshold in enumerate(grid):
        expected_tp = np.zeros(2, dtype=np.int64)
        expected_fp = np.zeros(2, dtype=np.int64)
        for index, seed_code in enumerate(seed_codes):
            # v5: ONE rule, independent of the label. v4 used crossing
            # intervals for positives and peaks for negatives, which let the
            # selector's curve disagree with the endpoint it was choosing a
            # threshold for.
            predicted = peaks[index] > threshold
            if predicted and truths[index]:
                expected_tp[seed_code] += 1
            elif predicted:
                expected_fp[seed_code] += 1
        require(
            np.array_equal(tp[:, grid_index], expected_tp),
            f"selector TP differs from runtime rule at threshold {threshold}",
        )
        require(
            np.array_equal(fp[:, grid_index], expected_fp),
            f"selector FP differs from runtime rule at threshold {threshold}",
        )
    require(np.array_equal(positives, np.array([1, 1])), "positive seed counts changed")
    require(np.all(np.isfinite(clean_fpr)), "benign seed FPR is undefined")

    selected = aggregate.choose_threshold(
        data,
        grid_step=0.1,
        max_clean_fpr_upper=1.0,
        confidence=0.95,
    )
    # Under v5 both positives rank by their peak (0.95), so every threshold in
    # [0.6, 0.9] separates them perfectly from the negatives (0.6, 0.2) and the
    # documented tie-break takes the highest such grid point. Under v4 the
    # positives were scored through their crossing intervals, which is why this
    # fixture used to optimise at 0.3.
    require(
        math.isclose(float(selected["threshold"]), 0.9),
        "unexpected synthetic optimum",
    )
    require(
        math.isclose(float(selected["validation_macro_f1"]), 1.0),
        "synthetic fixture should separate perfectly",
    )


def test_seed_bound_and_plan() -> None:
    upper_299 = float(
        aggregate.seed_any_event_upper(np.array([0]), 299, confidence=0.95)[0]
    )
    upper_298 = float(
        aggregate.seed_any_event_upper(np.array([0]), 298, confidence=0.95)[0]
    )
    require(upper_299 < 0.01 <= upper_298, "full clean-seed count cannot certify 1%")

    smoke_validation = experiment_pipeline.build_plan("smoke", "validation", None)
    smoke_test = experiment_pipeline.build_plan("smoke", "test", 0.5)
    full_validation = experiment_pipeline.build_plan("full", "validation", None)
    full_test = experiment_pipeline.build_plan("full", "test", 0.5)
    require(len(smoke_validation) == 8 and len(smoke_test) == 32, "smoke grid drift")
    require(len(full_validation) == 439 and len(full_test) == 1040, "full grid drift")
    smoke_validation_attacks = [
        job for job in smoke_validation if job.arm != "validation_none"
    ]
    require(
        all(
            int(experiment_pipeline.option_map(job)["nVehicles"]) == 10
            and math.isclose(
                float(experiment_pipeline.option_map(job)["attackerFraction"]),
                0.30,
            )
            for job in smoke_validation_attacks
        ),
        "smoke validation attacks must match smoke held-out pure attacks",
    )

    def grid_rows(jobs):
        return [
            {
                "experiment_id": job.experiment_id,
                "mode": job.mode,
                "stage": job.stage,
                "family": job.family,
                "run": str(job.seed),
            }
            for job in jobs
        ]

    # The consumer must accept the exact plans the producer creates. This
    # catches stale hard-coded stage/family counts before a completed sweep is
    # rejected during aggregation.
    aggregate.validate_grid(grid_rows(smoke_validation + smoke_test))
    aggregate.validate_grid(grid_rows(full_validation + full_test))
    require_raises(
        lambda: aggregate.validate_grid(
            grid_rows((smoke_validation + smoke_test)[:-1])
        ),
        "aggregate accepted an incomplete canonical smoke plan",
    )
    benign_validation = [
        job
        for job in full_validation
        if experiment_pipeline.option_map(job)["attack"] == "none"
    ]
    require(len(benign_validation) == 299, "full plan lacks 299 benign validation seeds")
    validation_attacks = [
        job for job in full_validation if job.arm != "validation_none"
    ]
    require(
        all(
            int(experiment_pipeline.option_map(job)["nVehicles"]) == 50
            and math.isclose(
                float(experiment_pipeline.option_map(job)["attackerFraction"]),
                0.30,
            )
            for job in validation_attacks
        ),
        "validation attack ROC population must match held-out pure attacks",
    )
    require(
        all(
            int(experiment_pipeline.option_map(job)["nVehicles"]) == 70
            for job in benign_validation
        ),
        "benign validation population no longer matches held-out benign target",
    )

    for job in smoke_validation + smoke_test + full_validation[:1] + full_test[:1]:
        options = experiment_pipeline.option_map(job)
        require("attackStart" in options, "plan omitted genuine attack onset")
        require("onsetBlank" in options, "plan omitted the onset-blank knob")
        require("decayHalfLife" in options and "decay" not in options, "plan uses message decay")
        # attackStart == 0 is the steady-state arm, where attackers are
        # adversarial from their first message and no onset step exists. What
        # must hold for every arm is that the evaluation window is well formed.
        warmup = float(options["warmup"])
        attack_start = float(options["attackStart"])
        onset_blank = float(options["onsetBlank"])
        sim_time = float(options["simTime"])
        eval_start = max(warmup, attack_start + onset_blank)
        require(
            0.0 <= attack_start < sim_time
            and 0.0 <= warmup < sim_time
            and onset_blank >= 0.0
            and eval_start < sim_time,
            "plan does not enforce a well-formed evaluation window",
        )

    # The onset and steady-state arms must evaluate over the IDENTICAL window,
    # or their paired difference is not attributable to the onset step alone.
    def window(job):
        options = experiment_pipeline.option_map(job)
        return (
            max(
                float(options["warmup"]),
                float(options["attackStart"]) + float(options["onsetBlank"]),
            ),
            float(options["simTime"]),
        )

    by_arm = {}
    for job in full_test:
        by_arm.setdefault(job.arm, set()).add(window(job))
    for attack in ("constoffset", "revheading", "slydos", "falsify"):
        onset = by_arm.get(f"pure_{attack}")
        steady = by_arm.get(f"pure_{attack}_steady")
        require(
            onset is not None and steady is not None and onset == steady,
            f"paired arms for {attack} do not share an evaluation window",
        )

    validation_seeds = {job.seed for job in full_validation}
    test_seeds = {job.seed for job in full_test}
    require(not validation_seeds & test_seeds, "validation/test RNG seeds overlap")

    onset_guards = [job for job in full_test if job.family == "onset_guard"]
    require(len(onset_guards) == 90, "onset-guard grid must have 3x30 paired runs")
    require(
        {
            float(experiment_pipeline.option_map(job)["onsetBlank"])
            for job in onset_guards
        }
        == {0.25, 0.5, 1.0},
        "onset-guard options drifted",
    )
    onset_times = [job for job in full_test if job.family == "onset_time"]
    require(len(onset_times) == 60, "onset-time grid must have 2x30 paired runs")
    require(
        {
            float(experiment_pipeline.option_map(job)["attackStart"])
            for job in onset_times
        }
        == {5.0, 20.0}
        and all(
            int(experiment_pipeline.option_map(job)["nVehicles"]) == 50
            and math.isclose(
                float(experiment_pipeline.option_map(job)["attackerFraction"]),
                0.30,
            )
            for job in onset_times
        ),
        "held-out onset-time controls drifted from the focused design",
    )
    require(
        all(
            job.arm.startswith("constoffset_guard_")
            and experiment_pipeline.option_map(job)["attack"] == "constoffset"
            and experiment_pipeline.option_map(job)["nVehicles"]
            == ("50" if job.mode == "full" else "10")
            and experiment_pipeline.option_map(job)["attackerFraction"] == "0.3"
            for job in onset_guards
        ),
        "onset guards are not paired constant-offset arms",
    )
    benign_stress = [job for job in full_test if job.family == "benign_stress"]
    require(len(benign_stress) == 90, "benign stress grid must have 3x30 runs")
    require(all(experiment_pipeline.option_map(job)["attack"] == "none"
                for job in benign_stress), "benign stress contains an attack")
    clock_stress = [
        job for job in benign_stress
        if job.arm == "clock_offset_sigma_0p10"
    ]
    require(
        len(clock_stress) == 30
        and all(
            math.isclose(
                float(experiment_pipeline.option_map(job)["clockSigma"]), 0.10
            )
            for job in clock_stress
        ),
        "fixed clock-offset stress is missing or misconfigured",
    )

    validation_traces = [job for job in full_validation if experiment_pipeline.needs_trace(job)]
    test_traces = [job for job in full_test if experiment_pipeline.needs_trace(job)]
    require(len(validation_traces) == 439, "baseline validation trace grid drifted")
    require(len(test_traces) == 420, "held-out/trajectory trace grid drifted")


def test_baseline_validation_selector() -> None:
    def fit_state(seed: int, signal: float, truth: bool, owner: bool = False):
        state = baselines.State()
        state.peak_signals["weighted-sum"] = signal
        state.malicious_stream = truth
        state.owner_attacker = owner
        attack = "synthetic" if truth else "none"
        return baselines.FitState(seed, attack, f"run-{seed}-{signal}", state)

    records = [
        fit_state(1, 0.1, False),
        fit_state(1, 0.8, True),
        fit_state(2, 0.2, False),
        fit_state(2, 0.9, True),
    ]
    selected = baselines.select_signal_threshold(
        records, "weighted-sum", max_clean_seed_upper=1.0
    )
    require(selected["clean_fp"] == 0, "baseline selector violated clean constraint")
    require(
        0.2 <= float(selected["threshold"]) < 0.8,
        "baseline selector did not separate synthetic validation pairs",
    )
    bound_records = [
        fit_state(10000 + seed, 0.1, False) for seed in range(1, 300)
    ] + [fit_state(50000, 0.8, True)]
    bound = baselines.score_threshold(
        bound_records, "weighted-sum", 0.2, clean_seed_confidence=0.95
    )
    require(
        bound["benign_seed_total"] == 299
        and bound["benign_seed_events"] == 0
        and float(bound["benign_seed_upper"]) < 0.01,
        "baseline selector does not reproduce the exact 299-seed clean bound",
    )


def test_validation_trained_logistic_baseline() -> None:
    def fit_state(seed: int, rates: tuple[float, ...], truth: bool):
        state = baselines.State()
        state.window_messages = 100
        state.check_fire_counts = {
            name: round(rate * state.window_messages)
            for name, rate in zip(baselines.CHECK_FEATURES, rates)
        }
        state.malicious_stream = truth
        state.owner_attacker = truth
        return baselines.FitState(
            seed, "synthetic" if truth else "none", f"lr-{seed}-{truth}", state
        )

    clean = (0.01, 0.01, 0.00, 0.00, 0.02, 0.00, 0.01)
    hostile = (0.40, 0.25, 0.10, 0.35, 0.30, 0.08, 0.20)
    records = [
        fit_state(seed, clean, False) for seed in range(1, 5)
    ] + [
        fit_state(seed, hostile, True) for seed in range(5, 9)
    ]
    model = baselines.fit_logistic_regression(records)
    clean_score = baselines.logistic_probability(records[0].state, model)
    hostile_score = baselines.logistic_probability(records[-1].state, model)
    require(hostile_score > clean_score, "validation logistic fit inverted its labels")
    require(
        model["feature_names"] == list(baselines.CHECK_FEATURES)
        and len(model["scaling_mean"]) == 7
        and len(model["scaling_scale"]) == 7
        and len(model["coefficients"]) == 7
        and math.isfinite(float(model["intercept"])),
        "logistic artifact omits feature/scaling/coefficient provenance",
    )
    require(
        math.isclose(
            baselines.rank_auc([clean_score, hostile_score], [False, True]),
            1.0,
        )
        and math.isclose(
            baselines.average_precision(
                [clean_score, hostile_score], [False, True]
            ),
            1.0,
        ),
        "baseline ROC/PR evidence helpers changed",
    )


def test_baseline_replay_history_is_monotone() -> None:
    import argparse

    args = argparse.Namespace(
        prior=0.05,
        warmup=0.0,
        baseline_parameters=baselines.provisional_parameters(0.5),
        logistic_model=baselines.provisional_logistic_model(),
        max_age=0.5,
        min_ref_dt=0.5,
        detector_gps_sigma=2.0,
        vmax=60.0,
        speed_tolerance=15.0,
        speed_sigma=0.5,
        rate_window=1.0,
        rate_limit=20.0,
        road_length=5000.0,
        road_width=30.0,
        heading_cos_min=0.0,
        decay_half_life=-1.0,
        score_clamp=8.0,
        score_model="reference",
        replay_memory=500,
        score_threshold=0.5,
    )

    def observation(now: float, tx: float, seq: int) -> baselines.Observation:
        return baselines.Observation(
            rx=1,
            now=now,
            claimed=7,
            source=7,
            source_attacker=False,
            owner_attacker=False,
            attack_active=False,
            message_malicious=False,
            seq=seq,
            tx=tx,
            x=25.0 * tx,
            y=0.0,
            vx=25.0,
            vy=0.0,
            rx_x=0.0,
            rx_y=0.0,
            observable_source="10.0.0.7",
        )

    state = baselines.State()
    state.score = math.log(args.prior / (1.0 - args.prior))
    state.owner_attacker = False
    baselines.update_state(state, observation(1.0, 1.0, 1), args, 0.0, args.warmup)
    baselines.update_state(state, observation(1.1, 0.5, 2), args, 0.0, args.warmup)
    require(
        math.isclose(state.last_tx, 1.0),
        "offline replay rolled its monotone timestamp baseline backward",
    )

    # A hostile message and first appearance before W remain detector history,
    # but neither may define W truth nor be re-labelled as a sudden appearance
    # merely because the evaluation window opened.
    pre_window = observation(4.0, 4.0, 3)
    pre_window = baselines.Observation(
        **{
            **pre_window.__dict__,
            "message_malicious": True,
            "attack_active": True,
            "x": 10.0,
        }
    )
    window_honest = observation(5.0, 5.0, 4)
    window_honest = baselines.Observation(
        **{**window_honest.__dict__, "x": 10.0}
    )
    guarded = baselines.State()
    guarded.score = math.log(args.prior / (1.0 - args.prior))
    guarded.owner_attacker = False
    baselines.update_state(guarded, pre_window, args, 5.0, args.warmup)
    baselines.update_state(guarded, window_honest, args, 5.0, args.warmup)
    require(
        not guarded.malicious_stream
        and guarded.first_malicious_time is None
        and guarded.window_messages == 1,
        "baseline truth leaked a malicious message received only before W",
    )
    require(
        guarded.peak_signals["sudden-appearance"] == -math.inf,
        "sender present before W was re-labelled as newly appearing at W",
    )

    first_inside = baselines.State()
    first_inside.score = math.log(args.prior / (1.0 - args.prior))
    first_inside.owner_attacker = False
    baselines.update_state(first_inside, window_honest, args, 5.0, args.warmup)
    require(
        math.isclose(first_inside.peak_signals["sudden-appearance"], -10.0),
        "genuine first appearance inside W lost its sudden-appearance signal",
    )

    records = [
        baselines.MetricRecord(1, "constoffset", "a", "pure_attack", "pure", "claimed", "range", {}),
        baselines.MetricRecord(1, "constoffset", "b", "onset_guard", "guard", "claimed", "range", {}),
    ]
    selected = baselines.select_records(
        records, "claimed", "range", None, baselines.HEADLINE_FAMILIES
    )
    require(
        [record.run_id for record in selected] == ["a"],
        "headline baseline population admitted a secondary onset control",
    )


def test_dread_and_coverage_sources_match_cpp() -> None:
    source = (ROOT / "v2v_cybersecurity_v2.cc").read_text(encoding="utf-8")
    matches = re.findall(
        r"/\*\s*(Spoofing|Tampering|Repudiation|InfoDisclosure|DenialOfService|Elevation)\s*\*/\s*"
        r"\{([0-9.]+),\s*([0-9.]+),\s*([0-9.]+),\s*([0-9.]+),\s*"
        r"([0-9.]+),\s*(\d+),\s*([0-9.]+)\}",
        source,
    )
    require(len(matches) == 6, "could not parse all g_dread rows from C++")
    cpp_names = {
        "Spoofing": "S_SPOOFING",
        "Tampering": "S_TAMPERING",
        "Repudiation": "S_REPUDIATION",
        "InfoDisclosure": "S_INFO_DISCLOSURE",
        "DenialOfService": "S_DOS",
        "Elevation": "S_ELEVATION",
    }
    cpp = {
        cpp_names[name]: {
            "damage": float(damage),
            "reproducibility": float(reproducibility),
            "exploitability": float(exploitability),
            "affected_users": float(affected),
            "discoverability": float(discoverability),
            "n_scenarios": int(scenarios),
            "normalised_impact": float(normalised),
        }
        for name, damage, reproducibility, exploitability, affected,
        discoverability, scenarios, normalised in matches
    }
    with (ROOT.parent / "data/stride_dread_table.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    require({row["stride_class"] for row in rows} == set(cpp), "DREAD class set drifted")
    for row in rows:
        expected = cpp[row["stride_class"]]
        require(int(row["n_scenarios"]) == expected["n_scenarios"],
                f"scenario count drift for {row['stride_class']}")
        if row["n_scenarios"] != "0":
            for field in (
                "damage", "reproducibility", "exploitability",
                "affected_users", "discoverability",
            ):
                require(math.isclose(float(row[field]), expected[field]),
                        f"DREAD {field} drift for {row['stride_class']}")
            require(math.isclose(float(row["normalised_impact"]),
                                 expected["normalised_impact"]),
                    f"impact drift for {row['stride_class']}")

    with (ROOT.parent / "data/detector_coverage.csv").open(newline="") as handle:
        coverage = {row["attack_type"]: row for row in csv.DictReader(handle)}
    reversed_heading = coverage["Reversed Heading"]
    require(
        reversed_heading["stride_class"] == "S_TAMPERING"
        and reversed_heading["detector_check"] == "CHK_HEADING"
        and reversed_heading["is_gap"] == "0",
        "Reversed Heading coverage no longer matches the implemented check",
    )
    require(
        "constexpr uint64_t TRACK_FIXED_BYTES = 100;" in source
        and "track.seenSeq.size() * 8" in source
        and "track.rxTimes.size() * 8" in source,
        "deployable state estimate omits track-local history payload",
    )


def test_source_snapshot_verification() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "workflow.py"
        source.write_text("print('frozen')\n", encoding="utf-8")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        (root / "SHA256SUMS").write_text(
            f"{digest}  workflow.py\n", encoding="utf-8"
        )
        _, files = experiment_pipeline.verify_source_snapshot(root)
        require(files["workflow.py"]["sha256"] == digest,
                "valid source snapshot was not described exactly")
        source.write_text("print('tampered')\n", encoding="utf-8")
        try:
            experiment_pipeline.verify_source_snapshot(root)
        except experiment_pipeline.PipelineError:
            pass
        else:
            raise AssertionError("tampered source snapshot was accepted")


def test_build_provenance_verification() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        local = root / "reviewed.cc"
        scratch = root / "scratch.cc"
        binary = root / "simulator"
        local.write_text("int main() { return 0; }\n", encoding="utf-8")
        scratch.write_text(local.read_text(encoding="utf-8"), encoding="utf-8")
        binary.write_bytes(b"built-binary")
        os.utime(scratch, ns=(1_000_000_000, 1_000_000_000))
        os.utime(binary, ns=(2_000_000_000, 2_000_000_000))
        provenance = experiment_pipeline.verify_build_provenance(
            local, scratch, binary
        )
        require(
            provenance["verified"]
            and provenance["source_byte_identical"]
            and provenance["binary_not_older_than_source"],
            "valid source/build correspondence was not certified",
        )

        scratch.write_text("int changed;\n", encoding="utf-8")
        try:
            experiment_pipeline.verify_build_provenance(local, scratch, binary)
        except experiment_pipeline.PipelineError:
            pass
        else:
            raise AssertionError("source mismatch passed strict build preflight")
        override = experiment_pipeline.verify_build_provenance(
            local, scratch, binary, allow_unverified=True
        )
        require(
            override["verification_mode"] == "override"
            and not override["verified"],
            "explicit unverified-build override was not recorded honestly",
        )


def test_config_signature_covers_plan_axes() -> None:
    """Every simulator argument the plan varies must be in aggregate's signature.

    The onset_guard arms vary only --onsetBlank and reuse the pure_constoffset
    seeds. When onset_blank_s was missing from config_fields, aggregate rejected
    all 90 of them as duplicate configurations, which is how this was found.
    """
    ep = experiment_pipeline

    source = (ROOT / "aggregate.py").read_text()
    block = re.search(r"config_fields = \((.*?)\)", source, re.S)
    require(block is not None, "aggregate.py no longer defines config_fields")
    fields = set(re.findall(r'"([a-z0-9_]+)"', block.group(1)))

    # simulator arg name -> summary column, for the axes the plan actually varies
    arg_to_column = {
        "nVehicles": "n", "attackerFraction": "frac", "attack": "attack",
        "simTime": "sim_time", "warmup": "warmup", "attackStart": "attack_start_s",
        "onsetBlank": "onset_blank_s", "interval": "interval",
        "detector": "detector", "scoreModel": "score_model",
        "decayHalfLife": "decay_half_life_s", "commRange": "comm_range",
        "gpsSigma": "gps_sigma", "detectorGpsSigma": "detector_gps_sigma",
        "mobility": "mobility", "spdSigma": "spd_sigma",
        "clockSigma": "clock_sigma", "bsmBytes": "bsm_bytes", "prior": "prior",
    }
    varying: dict[str, set[str]] = {}
    for job in ep.build_plan("full", "test", 0.5):
        for arg in job.args:
            if "=" in arg:
                name, value = arg.lstrip("-").split("=", 1)
                varying.setdefault(name, set()).add(value)

    for name, values in sorted(varying.items()):
        if len(values) < 2:
            continue
        column = arg_to_column.get(name)
        if column is None:
            continue
        require(
            column in fields,
            f"--{name} varies across the test plan ({sorted(values)[:3]}...) but "
            f"its column {column!r} is absent from aggregate.py config_fields; "
            f"runs differing only in it would be rejected as duplicates",
        )



def test_veremi_roundtrip_is_lossless() -> None:
    """A trace converted out to VeReMi shape and back must survive intact.

    The VeReMi adapter cannot be checked against VeReMi itself -- there is no
    reference answer there. Round-tripping a trace whose correct content is
    already known is the check that exists. It is what caught the adapter
    folding GPS noise into ground truth, which had labelled every message in a
    run malicious.

    Three things are deliberately NOT required to survive, and each is a
    documented property of the mapping rather than a defect:
      * absolute coordinates, because the adapter rebases to a local origin;
        only the rigid translation is allowed, any residual is a distortion;
      * observable_source_ipv4, which VeReMi has no counterpart for and which
        the adapter fills with a constant sentinel on purpose;
      * sequence numbers, because VeReMi message ids are global and ours are
        per-sender -- different namespaces, not lost information.
    """
    import statistics
    import subprocess

    src = ROOT / "results" / "v9" / "full" / "runs" / "test"
    # Must be an ATTACK-BEARING run. The first run alphabetically is the
    # attacker-free arm, on which every malicious-label assertion below is
    # vacuously true and the check silently proves nothing.
    runs = sorted(src.glob("*pure_attack*/trace.csv")) if src.is_dir() else []
    if not runs:
        print("SKIP  veremi round-trip (no frozen v9 attack traces present)")
        return
    trace = runs[0]
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for stage in (
            ["--emit-veremi", str(trace), "--clean", str(tmp / "c"), "--attack", str(tmp / "a")],
            ["--clean", str(tmp / "c"), "--attack", str(tmp / "a"), "--output", str(tmp / "back")],
        ):
            r = subprocess.run([sys.executable, str(ROOT / "veremi_adapter.py"), *stage],
                               capture_output=True, text=True)
            require(r.returncode == 0, f"veremi_adapter failed: {r.stderr[-300:]}")

        csv.field_size_limit(10 ** 8)
        with trace.open(newline="") as fh:
            before = list(csv.DictReader(fh))
        with (tmp / "back" / "trace.csv").open(newline="") as fh:
            after = list(csv.DictReader(fh))
        require(len(before) == len(after),
                f"round trip changed the reception count: {len(before)} -> {len(after)}")
        n_mal = sum(1 for r in before if r["oracle_message_is_malicious"] == "1")
        require(n_mal > 0,
                f"{trace} carries no malicious messages, so this check would "
                f"pass regardless of the mapping; pick an attack-bearing run")

        order = lambda r: (float(r["rx_time"]), int(r["receiver_id"]), int(r["oracle_source_id"]))
        before.sort(key=order)
        after.sort(key=order)

        labels = ("oracle_message_is_malicious", "oracle_source_is_attacker",
                  "oracle_attack_active", "oracle_owner_is_attacker")
        bad = sum(1 for x, y in zip(before, after)
                  if any(x[f] != y[f] for f in labels))
        require(bad == 0, f"{bad} rows changed truth label across the round trip")

        dx = [float(x["claimed_x"]) - float(y["claimed_x"]) for x, y in zip(before, after)]
        dy = [float(x["claimed_y"]) - float(y["claimed_y"]) for x, y in zip(before, after)]
        require(statistics.pstdev(dx) < 1e-5 and statistics.pstdev(dy) < 1e-5,
                "coordinate difference is not a rigid translation, so the "
                "round trip distorted geometry rather than merely rebasing it")
        ox, oy = statistics.mean(dx), statistics.mean(dy)
        worst = 0.0
        for x, y in zip(before, after):
            for f in ("claimed_x", "oracle_true_x", "receiver_true_x"):
                worst = max(worst, abs(float(x[f]) - float(y[f]) - ox))
            for f in ("claimed_y", "oracle_true_y", "receiver_true_y"):
                worst = max(worst, abs(float(x[f]) - float(y[f]) - oy))
            for f in ("claimed_vx", "claimed_vy", "oracle_true_vx", "oracle_true_vy"):
                worst = max(worst, abs(float(x[f]) - float(y[f])))
        require(worst < 1e-4,
                f"round trip lost {worst:.2e} of positional/velocity precision")


def main() -> int:
    test_config_signature_covers_plan_axes()
    test_veremi_roundtrip_is_lossless()
    test_crossing_contract()
    test_selector_runtime_equivalence()
    test_seed_bound_and_plan()
    test_baseline_validation_selector()
    test_validation_trained_logistic_baseline()
    test_baseline_replay_history_is_monotone()
    test_dread_and_coverage_sources_match_cpp()
    test_source_snapshot_verification()
    test_build_provenance_verification()
    print("All v6 analysis/plan assertions passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
