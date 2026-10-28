#!/bin/bash
#
# Run all ACVP tests against NIST test vectors.
#
# Downloads vectors from usnistgov/ACVP-Server GitHub on first run,
# caches them locally in .acvp-data/.
#
# Usage:
#   bash run_acvp.sh                      # Auto-detect build directory
#   bash run_acvp.sh --build-dir PATH     # Specify build directory
#   bash run_acvp.sh --version v1.1.0.41  # Use specific ACVP version
#   bash run_acvp.sh --skip-slhdsa        # Skip SLH-DSA (slow)
#
# Environment:
#   LD_LIBRARY_PATH  — Set automatically to include libqudo-pqc.so
#   EXEC_WRAPPER     — Optional wrapper for cross-compilation (e.g., qemu-arm)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PQC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse arguments
BUILD_DIR=""
VERSION=""
SKIP_SLHDSA=0
EXTRA_ARGS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --build-dir)   BUILD_DIR="$2"; shift ;;
        --version)     VERSION="--version $2"; shift ;;
        --skip-slhdsa) SKIP_SLHDSA=1 ;;
        *)             EXTRA_ARGS="$EXTRA_ARGS $1" ;;
    esac
    shift
done

# Auto-detect build directory
if [ -z "$BUILD_DIR" ]; then
    if [ -d "$PQC_DIR/build-acvp/acvp" ]; then
        BUILD_DIR="$PQC_DIR/build-acvp"
    elif [ -d "$PQC_DIR/build-fips/acvp" ]; then
        BUILD_DIR="$PQC_DIR/build-fips"
    elif [ -d "$PQC_DIR/build/acvp" ]; then
        BUILD_DIR="$PQC_DIR/build"
    else
        echo "ERROR: No build directory found. Build with: ./build.sh --acvp"
        exit 1
    fi
fi

ACVP_BIN_DIR="$BUILD_DIR/acvp"
LIB_DIR="$BUILD_DIR/lib"

# Verify binaries exist
for bin in qudo_acvp_mlkem qudo_acvp_mldsa qudo_acvp_slhdsa; do
    if [ ! -x "$ACVP_BIN_DIR/$bin" ]; then
        echo "ERROR: $bin not found in $ACVP_BIN_DIR"
        echo "Build with: ./build.sh --acvp"
        exit 1
    fi
done

# Set library path
export LD_LIBRARY_PATH="$LIB_DIR:${LD_LIBRARY_PATH:-}"

echo "======================================"
echo "  QUDO PQC — ACVP Test Runner"
echo "  Build: $BUILD_DIR"
echo "======================================"
echo ""

OVERALL_RC=0

# ML-KEM
echo ">>> Running ML-KEM ACVP tests..."
python3 "$SCRIPT_DIR/acvp_client_mlkem.py" \
    --binary "$ACVP_BIN_DIR/qudo_acvp_mlkem" \
    $VERSION $EXTRA_ARGS || OVERALL_RC=1
echo ""

# ML-DSA
echo ">>> Running ML-DSA ACVP tests..."
python3 "$SCRIPT_DIR/acvp_client_mldsa.py" \
    --binary "$ACVP_BIN_DIR/qudo_acvp_mldsa" \
    $VERSION $EXTRA_ARGS || OVERALL_RC=1
echo ""

# SLH-DSA
if [ $SKIP_SLHDSA -eq 0 ]; then
    echo ">>> Running SLH-DSA ACVP tests (this may take a while)..."
    python3 "$SCRIPT_DIR/acvp_client_slhdsa.py" \
        --binary "$ACVP_BIN_DIR/qudo_acvp_slhdsa" \
        $VERSION $EXTRA_ARGS || OVERALL_RC=1
else
    echo ">>> SLH-DSA ACVP tests: SKIPPED (--skip-slhdsa)"
fi

echo ""
echo "======================================"
if [ $OVERALL_RC -eq 0 ]; then
    echo "  ALL ACVP TESTS PASSED"
else
    echo "  SOME ACVP TESTS FAILED"
fi
echo "======================================"

exit $OVERALL_RC
