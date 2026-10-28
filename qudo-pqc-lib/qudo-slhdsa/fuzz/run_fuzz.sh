#!/bin/bash
# Run all SLH-DSA fuzzing harnesses
#
# Usage:
#   cd qudo-slhdsa
#   bash fuzz/run_fuzz.sh [duration_seconds] [build_dir]
#
# Examples:
#   bash fuzz/run_fuzz.sh              # 60s per target, build dir = build-fuzz
#   bash fuzz/run_fuzz.sh 120          # 120s per target
#
# Prerequisites:
#   - Clang compiler with libFuzzer support
#   - Build with: cmake -DBUILD_FUZZ=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_COMPILER=clang -B build-fuzz && cmake --build build-fuzz

set -e

DURATION=${1:-60}
BUILD_DIR="${2:-build-fuzz}"
FUZZ_DIR="${BUILD_DIR}/fuzz"

if [ ! -d "$FUZZ_DIR" ]; then
    echo "ERROR: Fuzz binaries not found. Build with -DBUILD_FUZZ=ON first."
    echo "  cmake -DBUILD_FUZZ=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_COMPILER=clang -B build-fuzz"
    echo "  cmake --build build-fuzz"
    exit 1
fi

echo "================================================================"
echo "  SLH-DSA Fuzzing (${DURATION}s per target)"
echo "================================================================"

# Create corpus directories
mkdir -p fuzz/corpus_der fuzz/corpus_pem fuzz/corpus_sig

FAILED=0

for target in fuzz_slhdsa_der_import fuzz_slhdsa_pem_import fuzz_slhdsa_sig_ops \
              fuzz_slhdsa_key_import fuzz_slhdsa_sig_verify; do
    if [ ! -f "${FUZZ_DIR}/${target}" ]; then
        echo "SKIP: ${target} (not built)"
        continue
    fi

    corpus_name=$(echo $target | sed 's/fuzz_slhdsa_/corpus_/' | sed 's/_import//' | sed 's/_ops//')
    mkdir -p "fuzz/${corpus_name}"

    # Use seed corpus if available
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
