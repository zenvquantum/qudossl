#!/bin/bash

# QUDO PQC Coverage Report Generator
# Builds with coverage instrumentation, runs tests, and generates HTML report.
#
# Usage:
#   ./coverage.sh                      - Generate coverage report
#   ./coverage.sh -o report/           - Output to custom directory
#   ./coverage.sh -f                   - Force clean rebuild
#   ./coverage.sh --fips               - FIPS mode coverage
#   ./coverage.sh -h                   - Show help

set -e

# Resolve script directory (works from any cwd)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ========================================================================== #
# Defaults                                                                    #
# ========================================================================== #

OUTPUT_DIR="coverage-report"
FORCE_CLEAN=0
FIPS_MODE=0

# ========================================================================== #
# Parse arguments                                                             #
# ========================================================================== #

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output)
            if [ -z "$2" ] || [[ "$2" == -* ]]; then
                echo "ERROR: --output requires a directory argument"
                exit 1
            fi
            OUTPUT_DIR="$2"
            shift
            ;;
        -f|--force)
            FORCE_CLEAN=1
            ;;
        --fips)
            FIPS_MODE=1
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Build with coverage instrumentation, run tests, generate HTML report."
            echo ""
            echo "Options:"
            echo "  -o, --output DIR   Output directory for HTML report (default: coverage-report/)"
            echo "  -f, --force        Force clean rebuild before generating coverage"
            echo "  --fips             Build and test in FIPS mode"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Prerequisites:"
            echo "  lcov               Install via: apt-get install lcov (Debian/Ubuntu)"
            echo "                                  yum install lcov (RHEL/Fedora)"
            echo "                                  brew install lcov (macOS)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-o DIR] [-f] [--fips] [-h]"
            exit 1
            ;;
    esac
    shift
done

# ========================================================================== #
# Check prerequisites                                                         #
# ========================================================================== #

if ! command -v lcov &> /dev/null; then
    echo "ERROR: lcov is not installed."
    echo ""
    echo "Install lcov:"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "  brew install lcov"
    elif command -v apt-get &> /dev/null; then
        echo "  sudo apt-get install lcov"
    elif command -v yum &> /dev/null; then
        echo "  sudo yum install lcov"
    elif command -v pacman &> /dev/null; then
        echo "  sudo pacman -S lcov"
    else
        echo "  Please install lcov for your platform."
    fi
    exit 1
fi

if ! command -v genhtml &> /dev/null; then
    echo "ERROR: genhtml is not installed (usually part of lcov package)."
    exit 1
fi

if ! command -v cmake &> /dev/null; then
    echo "ERROR: cmake is not installed."
    exit 1
fi

# ========================================================================== #
# Build configuration                                                         #
# ========================================================================== #

echo "======================================"
echo "  QUDO PQC — Coverage Report"
if [ $FIPS_MODE -eq 1 ]; then
    echo "  Mode: FIPS 140-3"
fi
echo "  Output: $OUTPUT_DIR/"
echo "======================================"
echo ""

# Select build directory
if [ $FIPS_MODE -eq 1 ]; then
    BUILD_DIR="build-fips"
else
    BUILD_DIR="build-coverage"
fi

# Clean rebuild if requested
if [ $FORCE_CLEAN -eq 1 ]; then
    echo "Cleaning $BUILD_DIR..."
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"

# ========================================================================== #
# Step 1: Build with coverage flags                                           #
# ========================================================================== #

echo "Step 1: Building with coverage instrumentation..."
echo ""

BUILD_ARGS="--coverage -t --acvp"
if [ $FIPS_MODE -eq 1 ]; then
    BUILD_ARGS="$BUILD_ARGS --fips"
fi
if [ $FORCE_CLEAN -eq 1 ]; then
    BUILD_ARGS="$BUILD_ARGS -f"
fi

./build.sh $BUILD_ARGS

echo ""

# ========================================================================== #
# Step 2: Reset coverage counters                                             #
# ========================================================================== #

echo "Step 2: Resetting coverage counters..."
lcov --zerocounters --directory "$BUILD_DIR"
echo ""

# ========================================================================== #
# Step 3: Run tests                                                           #
# ========================================================================== #

echo "Step 3: Running tests..."
cd "$BUILD_DIR"
ctest --output-on-failure || true
cd "$SCRIPT_DIR"
echo ""

# Step 3b: Run ACVP harnesses (NIST test vectors) when built, to cover
# algorithm internals not reached by ctest.
if [ -x "$BUILD_DIR/acvp/qudo_acvp_mlkem" ]; then
    echo "Step 3b: Running ACVP harnesses (NIST vectors)..."
    bash "$SCRIPT_DIR/acvp/run_acvp.sh" --build-dir "$BUILD_DIR" || true
    echo ""
fi

# ========================================================================== #
# Step 4: Capture coverage data                                               #
# ========================================================================== #

echo "Step 4: Capturing coverage data..."

# Non-FIPS build only: exclude self-test infrastructure whose entry points are
# active only in FIPS builds.
NONFIPS_EXCLUDES=""
if [ $FIPS_MODE -eq 0 ]; then
    NONFIPS_EXCLUDES="
        --exclude ${SCRIPT_DIR}/src/qudo_pqc_post.c
        --exclude ${SCRIPT_DIR}/src/qudo_pqc_pct.c
        --exclude ${SCRIPT_DIR}/src/qudo_pqc_indicator.c
        --exclude ${SCRIPT_DIR}/src/qudo_pqc_security.c
        --exclude ${SCRIPT_DIR}/src/qudo_pqc_selftest.h
        --exclude ${SCRIPT_DIR}/include/qudo_pqc_indicator.h"
fi

lcov --capture \
     --directory "$BUILD_DIR" \
     --base-directory "$SCRIPT_DIR" \
     --exclude "${SCRIPT_DIR}/tests/*" \
     --exclude "${SCRIPT_DIR}/qudo-mlkem/tests/*" \
     --exclude "${SCRIPT_DIR}/qudo-mldsa/tests/*" \
     --exclude "${SCRIPT_DIR}/qudo-slhdsa/tests/*" \
     --exclude "${SCRIPT_DIR}/acvp/*" \
     --exclude "${SCRIPT_DIR}/tools/*" \
     --exclude "${SCRIPT_DIR}/qudo-mldsa/mldsa-native/*" \
     --exclude "${SCRIPT_DIR}/qudo-mlkem/mlkem-native/*" \
     --exclude "${SCRIPT_DIR}/qudo-slhdsa/slhdsa-native/*" \
     --exclude "${SCRIPT_DIR}/src/qudo_fips_boundary_start.c" \
     --exclude "${SCRIPT_DIR}/src/qudo_fips_boundary_end.c" \
     --exclude "${SCRIPT_DIR}/src/fips/qudo_fips_aes_ct.c" \
     --exclude "${SCRIPT_DIR}/qudo-slhdsa/src/slhdsa_rand.c" \
     $NONFIPS_EXCLUDES \
     --exclude "/usr/include/*" \
     --exclude "/usr/lib/*" \
     --no-external \
     --ignore-errors mismatch,source,negative,unused,inconsistent,gcov,format \
     --branch-coverage \
     --output-file "$BUILD_DIR/coverage.info"
echo ""

# ========================================================================== #
# Step 5: Generate HTML report                                                #
# ========================================================================== #

echo "Step 5: Generating HTML report..."
rm -rf "$OUTPUT_DIR"
genhtml "$BUILD_DIR/coverage.info" \
    --output-directory "$OUTPUT_DIR" \
    --title "QUDO PQC Coverage Report" \
    --prefix "$SCRIPT_DIR" \
    --legend \
    --show-details \
    --highlight \
    --branch-coverage \
    --ignore-errors source,inconsistent,category
echo ""

# ========================================================================== #
# Print summary                                                               #
# ========================================================================== #

echo "======================================"
echo "  Coverage Summary"
echo "======================================"
lcov --summary --rc branch_coverage=1 "$BUILD_DIR/coverage.info"
echo ""
echo "HTML report: $OUTPUT_DIR/index.html"
echo ""

# Extract and display final line/function percentages
SUMMARY=$(lcov --summary --rc branch_coverage=1 "$BUILD_DIR/coverage.info" 2>&1)
LINES_PCT=$(echo "$SUMMARY" | grep "lines" | grep -oP '[\d.]+%' | head -1 || echo "N/A")
FUNCTIONS_PCT=$(echo "$SUMMARY" | grep "functions" | grep -oP '[\d.]+%' | head -1 || echo "N/A")
BRANCHES_PCT=$(echo "$SUMMARY" | grep "branches" | grep -oP '[\d.]+%' | head -1 || echo "N/A")

echo "  Lines:     $LINES_PCT"
echo "  Functions: $FUNCTIONS_PCT"
echo "  Branches:  $BRANCHES_PCT"
echo "======================================"
echo ""
echo "Done."
