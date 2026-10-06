#!/usr/bin/env python3
"""Per-message detector timing on whatever machine you run it on.

The manuscript reports timings from an x86 laptop and says so. A reviewer in a
vehicular venue will ask what the detector costs on on-board-unit-class
hardware. This script answers that on any machine: copy the repository and one
trace to the target board, run it, and paste the numbers back.

It drives ``baselines.update_state``, the Python reference implementation of
the same detector. That is **not** the code Table 14 times: those numbers come
from the C++ detector inside ns-3, and on the same x86 host this script reports
roughly 46 us per message against the C++ figure of 2.7 us. Read the two as
different implementations of one algorithm, not as one number measured twice.

What this script gives you is a portable, like-for-like ratio: run it on the
x86 host and on the target board, and the ratio between the two is the
architecture penalty you can apply to the C++ figure. Quoting the Python
absolute number as an on-board-unit cost would overstate it by more than an
order of magnitude.

    python3 obu_timing.py --trace path/to/trace.csv \\
        --threshold-json results/v9/full/analysis/selected_threshold.json \\
        --baseline-parameters results/v9/full/analysis/baseline_parameters.json \\
        --out obu_timing.json

Report alongside: ``cat /proc/cpuinfo | grep -m1 'model name'`` (or
``Hardware``/``Model`` on a Pi), ``uname -srm``, and ``python3 -V``.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics as st
import sys
import time
from collections import defaultdict
from pathlib import Path

import baselines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", type=Path, required=True)
    ap.add_argument("--threshold-json", type=Path, required=True)
    ap.add_argument("--baseline-parameters", type=Path, required=True)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N receptions (0 = whole trace)")
    known, rest = ap.parse_known_args()
    sys.argv = [sys.argv[0], "--traces", str(known.trace.parent),
                "--score-model", "reference",
                "--threshold-json", str(known.threshold_json),
                "--baseline-parameters", str(known.baseline_parameters), *rest]
    args = baselines.parse_args()

    schema = baselines.read_schema(known.trace)
    meta = baselines.run_metadata(known.trace)
    eval_start, warmup = baselines.verify_replay_config(meta, args, meta.partition)

    states: dict[tuple[int, int], baselines.State] = defaultdict(baselines.State)
    samples: list[float] = []
    clock = time.perf_counter_ns
    for n, obs in enumerate(baselines.observations(known.trace, schema)):
        if known.limit and n >= known.limit:
            break
        state = states[(obs.rx, obs.claimed)]
        start = clock()
        baselines.update_state(state, obs, args, eval_start, warmup)
        samples.append((clock() - start) / 1000.0)      # microseconds

    if not samples:
        raise SystemExit(f"{known.trace}: no receptions")
    samples.sort()

    def pct(p):
        return samples[min(len(samples) - 1, int(p * len(samples)))]

    peak_keys = len(states)
    report = {
        "machine": platform.processor() or platform.machine(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "trace": str(known.trace),
        "receptions": len(samples),
        "mean_us": st.fmean(samples),
        "p50_us": pct(0.50),
        "p95_us": pct(0.95),
        "p99_us": pct(0.99),
        "max_us": samples[-1],
        "throughput_calls_per_s": 1e6 / st.fmean(samples),
        "distinct_keys": peak_keys,
    }
    if known.out:
        known.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"{report['platform']}  python {report['python']}")
    print(f"receptions           {report['receptions']}")
    print(f"mean                 {report['mean_us']:.3f} us")
    print(f"p50 / p95 / p99      {report['p50_us']:.3f} / {report['p95_us']:.3f}"
          f" / {report['p99_us']:.3f} us")
    print(f"max                  {report['max_us']:.3f} us")
    print(f"throughput           {report['throughput_calls_per_s']:.3g} calls/s")
    print(f"distinct state keys  {report['distinct_keys']}")
    print("\nThis is the Python reference implementation, not the C++ detector\n"
          "timed in the manuscript. Run it on the x86 host too and report the\n"
          "ratio; the ratio is what transfers to the C++ figure.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
