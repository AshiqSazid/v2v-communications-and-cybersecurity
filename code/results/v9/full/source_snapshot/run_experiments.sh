#!/usr/bin/env bash
# Strict, two-stage v4 experiment workflow.
#
# Publication run (1479 simulations; archives an earlier full run):
#   bash run_experiments.sh full --fresh \
#       --ns3-root /home/user/ns-allinone-3.40/ns-3.40 --jobs 7
#
# Fast end-to-end pipeline check (40 short simulations):
#   bash run_experiments.sh smoke --fresh --jobs 4
#
# Resume only already-validated per-run artifacts:
#   bash run_experiments.sh full --resume --jobs 7
#
# Validation seeds are simulated first.  aggregate.py selects one threshold
# using only those data (macro-F1 subject to an exact seed-level clean-FP
# upper bound <= 1%). The test
# plan is then generated with that frozen threshold.  Every simulator process
# writes to a private directory; no workers append to a shared CSV.
set -euo pipefail
IFS=$'\n\t'

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
HELPER="$HERE/experiment_pipeline.py"
AGGREGATE="$HERE/aggregate.py"
BASELINES="$HERE/baselines.py"

usage() {
    sed -n '2,17{s/^# \\{0,1\\}//;p}' "$0" >&2
    cat >&2 <<'EOF'
Options:
  --ns3-root PATH   ns-3 source/build root
  --binary PATH     built simulator executable
  --allow-unverified-build
                    explicitly bypass source/build correspondence checks;
                    manifest records the run as unverified
  --jobs N          parallel non-timing workers (default: 7)
  --output PATH     artifact directory (default: results/v9/MODE)
  --fresh           archive an existing output directory and start clean
  --resume          verify and reuse complete runs; rerun partial/invalid ones
  --help            show this message

Exactly one of --fresh or --resume is required when the output already exists.
The serial timing arm always runs one process at a time regardless of --jobs.
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi
MODE="${1:-}"
if [[ "$MODE" != "smoke" && "$MODE" != "full" ]]; then
    usage
    exit 2
fi
shift

NS3_ROOT="${NS3_ROOT:-/home/moodifai/ns-allinone-3.40/ns-3.40}"
JOBS="${JOBS:-7}"
OUTPUT=""
BINARY=""
FRESH=0
RESUME=0
ALLOW_UNVERIFIED_BUILD=0
ORIGINAL_INVOCATION="$(printf '%q ' "$0" "$MODE" "$@")"

while (($#)); do
    case "$1" in
        --ns3-root)
            (($# >= 2)) || { echo "ERROR: --ns3-root requires a path" >&2; exit 2; }
            NS3_ROOT="$2"
            shift 2
            ;;
        --binary)
            (($# >= 2)) || { echo "ERROR: --binary requires a path" >&2; exit 2; }
            BINARY="$2"
            shift 2
            ;;
        --jobs)
            (($# >= 2)) || { echo "ERROR: --jobs requires an integer" >&2; exit 2; }
            JOBS="$2"
            shift 2
            ;;
        --output)
            (($# >= 2)) || { echo "ERROR: --output requires a path" >&2; exit 2; }
            OUTPUT="$2"
            shift 2
            ;;
        --fresh)
            FRESH=1
            shift
            ;;
        --resume)
            RESUME=1
            shift
            ;;
        --allow-unverified-build)
            ALLOW_UNVERIFIED_BUILD=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown option: $1" >&2
            usage
            exit 2
            ;;
    esac
done

[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || {
    echo "ERROR: --jobs must be a positive integer" >&2
    exit 2
}
if ((FRESH && RESUME)); then
    echo "ERROR: --fresh and --resume are mutually exclusive" >&2
    exit 2
fi

if [[ -z "$OUTPUT" ]]; then
    OUTPUT="$HERE/results/v9/$MODE"
fi
if [[ -z "$BINARY" ]]; then
    BINARY="$NS3_ROOT/build/scratch/ns3.40-v2v_cybersecurity_v2-default"
fi

NS3_ROOT="$(realpath -m "$NS3_ROOT")"
BINARY="$(realpath -m "$BINARY")"
OUTPUT="$(realpath -m "$OUTPUT")"
RESULTS_ROOT="$(realpath -m "$HERE/results")"
SCRATCH_SOURCE="$NS3_ROOT/scratch/v2v_cybersecurity_v2.cc"

[[ -x "$BINARY" ]] || {
    echo "ERROR: simulator binary is not executable: $BINARY" >&2
    echo "Build it first from ns-3 with: ./ns3 build v2v_cybersecurity_v2" >&2
    exit 2
}
[[ -f "$HELPER" && -f "$AGGREGATE" ]] || {
    echo "ERROR: workflow helper or aggregator is missing" >&2
    exit 2
}
BUILD_VERIFY_ARGS=(
    check-build
    --local-source "$HERE/v2v_cybersecurity_v2.cc"
    --scratch-source "$SCRATCH_SOURCE"
    --binary "$BINARY"
)
if ((ALLOW_UNVERIFIED_BUILD)); then
    BUILD_VERIFY_ARGS+=(--allow-unverified-build)
    echo "WARNING: source/build correspondence checks explicitly bypassed" >&2
fi
"$PYTHON" "$HELPER" "${BUILD_VERIFY_ARGS[@]}"
if [[ -e "$OUTPUT" && ! -d "$OUTPUT" ]]; then
    echo "ERROR: output path exists but is not a directory: $OUTPUT" >&2
    exit 2
fi

# A clean run is recoverable: archive the exact target instead of deleting it.
if [[ -e "$OUTPUT" && -n "$(find "$OUTPUT" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
    if ((FRESH)); then
        case "$OUTPUT" in
            /|"$HERE"|"$RESULTS_ROOT")
                echo "ERROR: refusing to archive unsafe broad path: $OUTPUT" >&2
                exit 2
                ;;
        esac
        STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
        ARCHIVE_PARENT="$(dirname "$OUTPUT")/archive"
        mkdir -p "$ARCHIVE_PARENT"
        ARCHIVE_TARGET="$ARCHIVE_PARENT/$(basename "$OUTPUT")_$STAMP"
        [[ ! -e "$ARCHIVE_TARGET" ]] || {
            echo "ERROR: archive target already exists: $ARCHIVE_TARGET" >&2
            exit 2
        }
        mv -- "$OUTPUT" "$ARCHIVE_TARGET"
        echo "Archived previous artifacts to $ARCHIVE_TARGET"
    elif ((RESUME)); then
        :
    else
        echo "ERROR: output exists: $OUTPUT" >&2
        echo "Use --resume to verify/reuse it or --fresh to archive it." >&2
        exit 2
    fi
fi

mkdir -p "$OUTPUT/plans" "$OUTPUT/runs" "$OUTPUT/analysis"
SOURCE_SNAPSHOT="$OUTPUT/source_snapshot"
SOURCE_FILES=(
    v2v_cybersecurity_v2.cc
    run_experiments.sh
    experiment_pipeline.py
    aggregate.py
    baselines.py
    calibrate_llr.py
    requirements.txt
)
if ((RESUME)); then
    [[ -d "$SOURCE_SNAPSHOT" && -f "$SOURCE_SNAPSHOT/SHA256SUMS" ]] || {
        echo "ERROR: resume requires an existing source_snapshot/SHA256SUMS" >&2
        exit 2
    }
    (
        cd "$SOURCE_SNAPSHOT"
        sha256sum --check --strict SHA256SUMS
    )
    for source_name in "${SOURCE_FILES[@]}"; do
        cmp -s -- "$HERE/$source_name" "$SOURCE_SNAPSHOT/$source_name" || {
            echo "ERROR: current $source_name differs from frozen source snapshot" >&2
            exit 2
        }
    done
else
    mkdir -p "$SOURCE_SNAPSHOT"
    for source_name in "${SOURCE_FILES[@]}"; do
        [[ -f "$HERE/$source_name" ]] || {
            echo "ERROR: snapshot source is missing: $HERE/$source_name" >&2
            exit 2
        }
        cp -- "$HERE/$source_name" "$SOURCE_SNAPSHOT/$source_name"
    done
    (
        cd "$SOURCE_SNAPSHOT"
        sha256sum "${SOURCE_FILES[@]}" > SHA256SUMS
    )
fi
SCHEMA="$OUTPUT/summary_schema_v4.csv"
VALIDATION_PLAN="$OUTPUT/plans/validation.tsv"
TEST_PLAN="$OUTPUT/plans/test.tsv"
VALIDATION_SUMMARY="$OUTPUT/validation_summary_v4.csv"
VALIDATION_PAIRS="$OUTPUT/validation_pairs_v4.csv"
SUMMARY="$OUTPUT/summary_v4.csv"
PAIRS="$OUTPUT/pairs_v4.csv"
THRESHOLD_JSON="$OUTPUT/analysis/selected_threshold.json"
BASELINE_PARAMETERS="$OUTPUT/analysis/baseline_parameters.json"
BASELINE_REPORT="$OUTPUT/analysis/baseline_report.txt"
BASELINE_METRICS="$OUTPUT/analysis/baseline_metrics.json"

# The schema is discovered from the exact binary being executed.  It is then
# checked for the semantic fields required by v4 rather than assumed by column
# position.
# Line 1 is the run-summary schema, line 2 the per-pair schema. Both are
# emitted so downstream field lists are generated from the binary rather than
# maintained by hand.
SCHEMA_OUTPUT="$("$BINARY" --csvHeader=true)"
mapfile -t SCHEMA_LINES < <(printf '%s\n' "$SCHEMA_OUTPUT" | sed '/^[[:space:]]*$/d')
if ((${#SCHEMA_LINES[@]} != 2)); then
    echo "ERROR: --csvHeader=true must emit exactly two non-empty lines" \
         "(summary schema, then pair schema); got ${#SCHEMA_LINES[@]}" >&2
    exit 2
fi
printf '%s\n' "${SCHEMA_LINES[0]}" > "$SCHEMA"
printf '%s\n' "${SCHEMA_LINES[1]}" > "$OUTPUT/pair_schema_v4.csv"
"$PYTHON" "$HELPER" check-schema --schema "$SCHEMA"

"$PYTHON" "$HELPER" plan \
    --mode "$MODE" \
    --phase validation \
    --output "$VALIDATION_PLAN"

RESUME_ARGS=()
if ((RESUME)); then
    RESUME_ARGS+=(--resume)
fi

run_plan() {
    local plan="$1"
    local serial="$2"
    local workers="$JOBS"
    local label="parallel"
    if [[ "$serial" == "1" ]]; then
        workers=1
        label="serial"
    fi

    mapfile -t ids < <(
        "$PYTHON" "$HELPER" list-ids --plan "$plan" --serial "$serial"
    )
    if ((${#ids[@]} == 0)); then
        return
    fi
    echo "Running ${#ids[@]} $label jobs from $(basename "$plan")"
    printf '%s\0' "${ids[@]}" |
        xargs -0 -r -P "$workers" -n 1 \
            "$PYTHON" "$HELPER" run-one \
                --plan "$plan" \
                --binary "$BINARY" \
                --runs-dir "$OUTPUT/runs" \
                --schema "$SCHEMA" \
                "${RESUME_ARGS[@]}" \
                --experiment-id
}

run_plan "$VALIDATION_PLAN" 0
run_plan "$VALIDATION_PLAN" 1

"$PYTHON" "$HELPER" merge \
    --plan "$VALIDATION_PLAN" \
    --runs-dir "$OUTPUT/runs" \
    --schema "$SCHEMA" \
    --summary-out "$VALIDATION_SUMMARY" \
    --pairs-out "$VALIDATION_PAIRS"

MAX_CLEAN_FP_UPPER="0.01"
RMST_HORIZON="20"
if [[ "$MODE" == "smoke" ]]; then
    # A one-seed smoke run cannot support a 1% confidence claim. This relaxed
    # bound tests plumbing only and is recorded in selected_threshold.json.
    MAX_CLEAN_FP_UPPER="1.0"
    RMST_HORIZON="4"
fi

"$PYTHON" "$AGGREGATE" select-threshold \
    --summary "$VALIDATION_SUMMARY" \
    --pairs "$VALIDATION_PAIRS" \
    --output "$THRESHOLD_JSON" \
    --grid-step 0.001 \
    --max-clean-fpr-upper "$MAX_CLEAN_FP_UPPER" \
    --clean-fpr-confidence 0.95
FROZEN_THRESHOLD="$("$PYTHON" "$AGGREGATE" show-threshold --input "$THRESHOLD_JSON")"
echo "Frozen validation-only threshold: $FROZEN_THRESHOLD"

BASELINE_COMMON=(
    --score-model reference
    --threshold-json "$THRESHOLD_JSON"
)
if [[ "$MODE" == "smoke" ]]; then
    BASELINE_COMMON+=(--warmup 2 --bootstrap 0 --max-clean-seed-upper 1.0)
fi
"$PYTHON" "$BASELINES" \
    --traces "$OUTPUT/runs/validation" \
    --pattern '**/trace.csv' \
    "${BASELINE_COMMON[@]}" \
    --fit-output "$BASELINE_PARAMETERS"

"$PYTHON" "$HELPER" plan \
    --mode "$MODE" \
    --phase test \
    --threshold "$FROZEN_THRESHOLD" \
    --output "$TEST_PLAN"

run_plan "$TEST_PLAN" 0
run_plan "$TEST_PLAN" 1

"$PYTHON" "$HELPER" merge \
    --plan "$VALIDATION_PLAN" \
    --plan "$TEST_PLAN" \
    --runs-dir "$OUTPUT/runs" \
    --schema "$SCHEMA" \
    --summary-out "$SUMMARY" \
    --pairs-out "$PAIRS"

"$PYTHON" "$AGGREGATE" report \
    --summary "$SUMMARY" \
    --pairs "$PAIRS" \
    --threshold-json "$THRESHOLD_JSON" \
    --output-dir "$OUTPUT/analysis" \
    --bootstrap-replicates 5000 \
    --bootstrap-seed 20260731 \
    --rmst-horizon "$RMST_HORIZON"

"$PYTHON" "$BASELINES" \
    --traces "$OUTPUT/runs/test" \
    --pattern '**/trace.csv' \
    "${BASELINE_COMMON[@]}" \
    --baseline-parameters "$BASELINE_PARAMETERS" \
    --metrics-output "$BASELINE_METRICS" \
    > "$BASELINE_REPORT"

MANIFEST_BUILD_ARGS=(--scratch-source "$SCRATCH_SOURCE")
if ((ALLOW_UNVERIFIED_BUILD)); then
    MANIFEST_BUILD_ARGS+=(--allow-unverified-build)
fi

"$PYTHON" "$HELPER" manifest \
    --plan "$VALIDATION_PLAN" \
    --plan "$TEST_PLAN" \
    --runs-dir "$OUTPUT/runs" \
    --binary "$BINARY" \
    --ns3-root "$NS3_ROOT" \
    --schema "$SCHEMA" \
    --threshold-json "$THRESHOLD_JSON" \
    --source-snapshot "$SOURCE_SNAPSHOT" \
    "${MANIFEST_BUILD_ARGS[@]}" \
    --artifact "$VALIDATION_SUMMARY" \
    --artifact "$VALIDATION_PAIRS" \
    --artifact "$THRESHOLD_JSON" \
    --artifact "$SUMMARY" \
    --artifact "$PAIRS" \
    --artifact "$OUTPUT/analysis/metrics_v4.csv" \
    --artifact "$OUTPUT/analysis/paired_differences_v4.csv" \
    --artifact "$OUTPUT/analysis/peak_score_discrimination_v4.csv" \
    --artifact "$OUTPUT/analysis/survival_v4.csv" \
    --artifact "$OUTPUT/analysis/report_v4.md" \
    --artifact "$BASELINE_PARAMETERS" \
    --artifact "$BASELINE_REPORT" \
    --artifact "$BASELINE_METRICS" \
    --invocation "$ORIGINAL_INVOCATION" \
    --output "$OUTPUT/manifest_v4.json"

echo
echo "Completed strict v4 $MODE workflow."
echo "  summaries : $SUMMARY"
echo "  pair data : $PAIRS"
echo "  analysis  : $OUTPUT/analysis"
echo "  manifest  : $OUTPUT/manifest_v4.json"
if [[ "$MODE" == "smoke" ]]; then
    echo "  WARNING   : smoke outputs are pipeline checks, not publication results."
fi
