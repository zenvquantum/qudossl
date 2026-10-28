#!/bin/bash
# Run all ML-KEM fuzzing harnesses
#
# Usage:
#   cd qudo-mlkem
#   bash fuzz/run_fuzz.sh [duration_seconds] [build_dir]
#
# Examples:
#   bash fuzz/run_fuzz.sh              # 60s per target, build dir = build
#   bash fuzz/run_fuzz.sh 120          # 120s per target
#   bash fuzz/run_fuzz.sh 60 build-fuzz  # custom build directory
#
# Prerequisites:
#   - Clang compiler with libFuzzer support
#   - Build with: cmake -DBUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang -B build && cmake --build build

set -e

DURATION=${1:-60}
BUILD_DIR="${2:-build-fuzz}"
FUZZ_DIR="${BUILD_DIR}/fuzz"

if [ ! -d "$FUZZ_DIR" ]; then
    echo "ERROR: Fuzz binaries not found. Build with -DBUILD_FUZZ=ON first."
    echo "  cmake -DBUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang -B build"
    echo "  cmake --build build"
    exit 1
fi

echo "================================================================"
echo "  ML-KEM Fuzzing (${DURATION}s per target)"
echo "================================================================"

# Create corpus directories
mkdir -p fuzz/corpus_der fuzz/corpus_pem fuzz/corpus_kem

FAILED=0

for target in fuzz_mlkem_der_import fuzz_mlkem_pem_import fuzz_mlkem_kem_ops; do
    if [ ! -f "${FUZZ_DIR}/${target}" ]; then
        echo "SKIP: ${target} (not built)"
        continue
    fi

    corpus_name=$(echo $target | sed 's/fuzz_mlkem_/corpus_/' | sed 's/_import//' | sed 's/_ops//')
    mkdir -p "fuzz/${corpus_name}"

    # Use seed corpus if available (provides valid inputs for better coverage)
    seed_dir="fuzz/seed_${corpus_name}"
    SEED_ARG=""
    if [ -d "$seed_dir" ] && [ "$(ls -A "$seed_dir" 2>/dev/null)" ]; then
        SEED_ARG="$seed_dir"
        echo "  Using seed corpus from: $seed_dir ($(ls "$seed_dir" | wc -l) files)"
    fi

    echo ""
    echo "--- Running ${target} for ${DURATION}s ---"
    if "${FUZZ_DIR}/${target}" "fuzz/${corpus_name}" ${SEED_ARG} \
        -max_len=8192 \
        -max_total_time=${DURATION} \
        -print_final_stats=1 2>&1; then
        echo "PASS: ${target}"
    else
        echo "FAIL: ${target} (found crash)"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "================================================================"
if [ $FAILED -eq 0 ]; then
    echo "  All fuzz targets completed without crashes"
else
    echo "  WARNING: ${FAILED} target(s) found crashes"
fi
echo "================================================================"

exit $FAILED
