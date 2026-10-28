#!/bin/bash

# QUDO PQC Clang Static Analyzer (scan-build) Runner
# Runs the Clang Static Analyzer over the qudo-authored shipping sources and
# generates an HTML report. Vendored native code (mlkem/mldsa/slhdsa-native,
# formally verified upstream), tests, examples and ACVP harnesses are excluded
# so findings reflect only the code that ships in libqudo-pqc.so.
#
# Complements clang-tidy and cppcheck with path-sensitive checks (null-deref,
# use-after-free, leaks, dead stores).
#
# Usage:
#   ./scan-build.sh                    - Analyze, write report to scan-report/
#   ./scan-build.sh -o report/         - Output to custom directory
#   ./scan-build.sh -f                 - Force clean rebuild
#   ./scan-build.sh --fips             - Analyze the FIPS-module build
#   ./scan-build.sh -h                 - Show help

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ========================================================================== #
# Defaults                                                                    #
# ========================================================================== #

OUTPUT_DIR="scan-report"
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
            echo "Run the Clang Static Analyzer over qudo shipping sources, generate HTML report."
            echo ""
            echo "Options:"
            echo "  -o, --output DIR   Output directory for HTML report (default: scan-report/)"
            echo "  -f, --force        Force clean rebuild before analysis"
            echo "  --fips             Analyze the FIPS-module build (-DQUDO_FIPS_MODULE=ON)"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Prerequisites:"
            echo "  scan-build         Install via: apt-get install clang-tools (Debian/Ubuntu)"
            echo "                                  brew install llvm (macOS)"
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
# Resolve scan-build / clang (prefer unversioned, fall back to newest -NN)    #
# ========================================================================== #

SCAN_BUILD="$(command -v scan-build || true)"
if [ -z "$SCAN_BUILD" ]; then
    SCAN_BUILD="$(ls /usr/bin/scan-build-* /usr/lib/llvm-*/bin/scan-build 2>/dev/null | sort -V | tail -1 || true)"
fi
if [ -z "$SCAN_BUILD" ]; then
    echo "ERROR: scan-build is not installed."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "  brew install llvm     (scan-build ships with the LLVM toolchain)"
    else
        echo "  sudo apt-get install clang-tools"
    fi
    exit 1
fi

CC_BIN="${CC:-clang}"
if ! command -v "$CC_BIN" &> /dev/null; then
    CC_BIN="$(ls /usr/bin/clang-* 2>/dev/null | grep -E 'clang-[0-9]+$' | sort -V | tail -1 || true)"
fi
if [ -z "$CC_BIN" ]; then
    echo "ERROR: clang is not installed (required by the static analyzer)."
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
echo "  QUDO PQC — Static Analysis (scan-build)"
if [ $FIPS_MODE -eq 1 ]; then
    echo "  Mode: FIPS 140-3"
fi
echo "  Analyzer: $SCAN_BUILD"
echo "  Output: $OUTPUT_DIR/"
echo "======================================"
echo ""

BUILD_DIR="build-scan"

if [ $FORCE_CLEAN -eq 1 ]; then
    echo "Cleaning $BUILD_DIR..."
    rm -rf "$BUILD_DIR"
fi
rm -rf "$OUTPUT_DIR"

CMAKE_ARGS=(-S . -B "$BUILD_DIR" -G Ninja
    -DCMAKE_BUILD_TYPE=Debug
    -DQUDO_PQC_BUILD_TESTS=ON)
if [ $FIPS_MODE -eq 1 ]; then
    CMAKE_ARGS+=(-DQUDO_FIPS_MODULE=ON)
fi

# Vendored / non-shipping paths excluded from analysis so findings reflect only
# qudo-authored code compiled into libqudo-pqc.so.
EXCLUDES=(
    --exclude "${SCRIPT_DIR}/qudo-mlkem/mlkem-native"
    --exclude "${SCRIPT_DIR}/qudo-mldsa/mldsa-native"
    --exclude "${SCRIPT_DIR}/qudo-slhdsa/slhdsa-native"
    --exclude "${SCRIPT_DIR}/tests"
    --exclude "${SCRIPT_DIR}/qudo-mlkem/tests"
    --exclude "${SCRIPT_DIR}/qudo-mldsa/tests"
    --exclude "${SCRIPT_DIR}/qudo-slhdsa/tests"
    --exclude "${SCRIPT_DIR}/examples"
    --exclude "${SCRIPT_DIR}/qudo-mlkem/examples"
    --exclude "${SCRIPT_DIR}/qudo-mldsa/examples"
    --exclude "${SCRIPT_DIR}/qudo-slhdsa/examples"
    --exclude "${SCRIPT_DIR}/acvp"
)

# ========================================================================== #
# Step 1: Configure under scan-build                                          #
# ========================================================================== #

echo "Step 1: Configuring under scan-build..."
"$SCAN_BUILD" --use-cc="$CC_BIN" cmake "${CMAKE_ARGS[@]}"
echo ""

# ========================================================================== #
# Step 2: Analyze (build under scan-build)                                    #
# ========================================================================== #

echo "Step 2: Analyzing shipping sources..."
set +e
"$SCAN_BUILD" --use-cc="$CC_BIN" --status-bugs "${EXCLUDES[@]}" \
    -o "$OUTPUT_DIR" cmake --build "$BUILD_DIR" --parallel
RC=$?
set -e
echo ""

# ========================================================================== #
# Print summary                                                               #
# ========================================================================== #

echo "======================================"
echo "  Static Analysis Summary"
echo "======================================"
if [ $RC -eq 0 ]; then
    echo "  Result: CLEAN — no findings in shipping sources"
else
    NBUGS=$(find "$OUTPUT_DIR" -name 'report-*.html' 2>/dev/null | wc -l | tr -d ' ')
    echo "  Result: $NBUGS finding(s) in shipping sources"
    echo ""
    echo "  Findings by file:"
    grep -rhoE '<!-- BUGFILE [^ ]+ -->' "$OUTPUT_DIR" 2>/dev/null \
        | sed -E "s#<!-- BUGFILE (.*) -->#\1#; s#${SCRIPT_DIR}/##" \
        | sort | uniq -c | sort -rn | sed 's/^/    /'
    echo ""
    echo "  HTML report: $OUTPUT_DIR/index.html  (open in a browser, or: scan-view $OUTPUT_DIR)"
fi
echo "======================================"
echo ""
echo "Done."
exit $RC
