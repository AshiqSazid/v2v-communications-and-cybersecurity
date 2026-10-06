#!/usr/bin/env python3
"""Extract the ns-3-free detector and metric code into a unit-test header.

The unit test must exercise the implementation in
``v2v_cybersecurity_v2.cc``, not a hand-maintained transcription.  This script
therefore slices complete C++ blocks from the production source and wraps only
``Assess`` in a tiny receiver class.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def find_line(lines: list[str], marker: str, start: int = 0) -> int:
    for index in range(start, len(lines)):
        if marker in lines[index]:
            return index
    raise ValueError(f"marker not found: {marker!r}")


def brace_block(lines: list[str], marker: str, start: int = 0) -> tuple[str, int]:
    """Return a complete C/C++ brace-delimited declaration or function."""
    first = find_line(lines, marker, start)
    depth = 0
    opened = False
    for index in range(first, len(lines)):
        for char in lines[index]:
            if char == "{":
                depth += 1
                opened = True
            elif char == "}":
                depth -= 1
                if opened and depth == 0:
                    return "\n".join(lines[first : index + 1]), index
    raise ValueError(f"unterminated brace block beginning at {marker!r}")


def through_line(
    lines: list[str], first_marker: str, last_marker: str, start: int = 0
) -> tuple[str, int]:
    first = find_line(lines, first_marker, start)
    last = find_line(lines, last_marker, first)
    return "\n".join(lines[first : last + 1]), last


def before_section(lines: list[str], first_marker: str, section_marker: str) -> str:
    first = find_line(lines, first_marker)
    marker = find_line(lines, section_marker, first)
    section_start = marker
    while section_start > first and not lines[section_start].startswith("/*"):
        section_start -= 1
    return "\n".join(lines[first:section_start])


def build_header(source: Path) -> str:
    lines = source.read_text(encoding="utf-8").splitlines()

    bsm, _ = through_line(lines, "#pragma pack(push, 1)", "#pragma pack(pop)")
    checks, _ = through_line(
        lines,
        "enum Check",
        "static const CheckModel* g_check = g_checkReference;",
    )
    stride_attribution, _ = brace_block(lines, "struct StrideAttribution")
    attribute_stride, _ = brace_block(lines, "static StrideAttribution AttributeStrideFrame")
    priority_index, _ = brace_block(lines, "static double PriorityIndex")
    constants = before_section(
        lines, "// Physical plausibility constants", " * 3. Evaluation harness"
    )
    pair_record, pair_end = brace_block(lines, "struct PairRecord")
    pair_vector = lines[find_line(lines, "static std::vector<PairRecord>", pair_end)]
    track, _ = brace_block(lines, "struct Track")
    track_consts = "\n".join(
        line
        for line in lines
        if line.startswith("static const double TRACK_GATE_SIGMA")
        or line.startswith("static const uint32_t TRACK_MAX")
        or line.startswith("static const double TRACK_EXPIRY")
    )
    evaluate_track_checks, _ = brace_block(
        lines, "static void EvaluateTrackChecks"
    )
    neighbor, _ = brace_block(lines, "struct NeighborState")
    observe_window_truth, _ = brace_block(
        lines, "static bool ObserveWindowTruth"
    )
    observe_stream_exceed, _ = brace_block(
        lines, "static void ObserveStreamWindowExceed"
    )
    reset_track, _ = brace_block(lines, "static void ResetTrackMeasurement")
    reset_measurement, _ = brace_block(lines, "static void ResetMeasurementState")
    archive_track, _ = brace_block(lines, "static void ArchiveAndReleaseTrack")
    expire_tracks, _ = brace_block(lines, "static void ExpireTracks")
    allocate_track, _ = brace_block(lines, "static int AllocateTrackSlot")
    crossing, _ = brace_block(lines, "static bool CrossingInterval")
    merge_crossings, _ = brace_block(lines, "static std::vector<std::pair<double, double>> MergeCrossingIntervals")
    time_decay, _ = brace_block(lines, "static double TimeDecayFactor")
    assess, _ = brace_block(
        lines,
        "double Assess(const Bsm& b, double now, int64_t& evaluationOnlyNanos)",
    )
    metrics = before_section(lines, "static const double UNDEF", " * 7. Main")

    return f"""// GENERATED from {source.name}; do not edit.
#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

{bsm}

{checks}

{stride_attribution}

{attribute_stride}

{priority_index}

{constants}

{pair_record}
{pair_vector}

static double g_warmup = 5.0;
static double g_evalStart = 5.0;
static double g_detectorGpsSigma = 2.0;
static double g_spdSigma = 0.5;
static bool g_naiveThresh = false;

{track}

{track_consts}

{evaluate_track_checks}

{neighbor}

{observe_window_truth}

{observe_stream_exceed}

{reset_track}

{reset_measurement}

{archive_track}

{expire_tracks}

{allocate_track}

{crossing}

{merge_crossings}

{time_decay}

struct Receiver
{{
    double m_decayHalfLife;
    bool m_nullEvidence;
    double m_initialLogEvidence;
    std::map<uint32_t, NeighborState> m_neighbors;

    Receiver(double initialScore, double decayHalfLife, bool nullEvidence)
        : m_decayHalfLife(decayHalfLife),
          m_nullEvidence(nullEvidence),
          m_initialLogEvidence(
              std::log(initialScore / (1.0 - initialScore)))
    {{
    }}

{assess}

    double Assess(const Bsm& b, double now)
    {{
        int64_t evaluationOnlyNanos = 0;
        return Assess(b, now, evaluationOnlyNanos);
    }}
}};

{metrics}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    header = build_header(args.source)
    args.output.write_text(header, encoding="utf-8")
    print(f"extracted detector core to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
