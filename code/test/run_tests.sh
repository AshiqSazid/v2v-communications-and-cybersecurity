#!/usr/bin/env bash
# Assertion-based unit and integration checks for the v4 artifact.
set -euo pipefail
IFS=$'\n\t'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$TEST_DIR/.." && pwd)"
NS3_ROOT="${NS3_ROOT:-/home/moodifai/ns-allinone-3.40/ns-3.40}"
NS3_BIN="${NS3_BIN:-$NS3_ROOT/build/scratch/ns3.40-v2v_cybersecurity_v2-default}"
BUILD_DIR="$(mktemp -d)"

python3 "$TEST_DIR/mkharness.py" \
    "$ROOT/v2v_cybersecurity_v2.cc" \
    "$BUILD_DIR/core.inc"
g++ -O2 -std=c++17 -Wall -Wextra -Werror \
    -I "$BUILD_DIR" \
    -o "$BUILD_DIR/test_detector" \
    "$TEST_DIR/test_detector.cc"
"$BUILD_DIR/test_detector"

python3 -m py_compile \
    "$ROOT/aggregate.py" \
    "$ROOT/baselines.py" \
    "$ROOT/calibrate_llr.py" \
    "$ROOT/experiment_pipeline.py" \
    "$TEST_DIR/mkharness.py" \
    "$TEST_DIR/test_analysis.py" \
    "$TEST_DIR/test_extended_onset_analysis.py" \
    "$TEST_DIR/test_distance_analysis.py" \
    "$TEST_DIR/test_integration.py"

python3 "$TEST_DIR/test_analysis.py"
python3 "$TEST_DIR/test_extended_onset_analysis.py"
python3 "$TEST_DIR/test_distance_analysis.py"

if [[ -x "$NS3_BIN" ]]; then
    python3 "$TEST_DIR/test_integration.py" --binary "$NS3_BIN"
else
    echo "SKIP  ns-3 integration binary not found: $NS3_BIN"
    if [[ "${REQUIRE_NS3:-0}" == "1" ]]; then
        exit 1
    fi
fi

echo "All available tests passed."
