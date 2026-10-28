#!/bin/bash

# QUDO PQC — Comprehensive Test Runner
# Runs all available test suites: unit tests, sanitizers, valgrind, static analysis
#
# Usage:
#   ./run_all_tests.sh              - Run all tests (standard + FIPS)
#   ./run_all_tests.sh --quick      - Standard tests only (fastest)
#   ./run_all_tests.sh --sanitizers - Unit tests + ASan/UBSan
#   ./run_all_tests.sh --full       - Everything including valgrind + static analysis
#   ./run_all_tests.sh --help       - Show this help

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' NC=''
fi

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RESULTS=()

log_pass() { PASS_COUNT=$((PASS_COUNT + 1)); RESULTS+=("${GREEN}PASS${NC} $1"); echo -e "  ${GREEN}PASS${NC} $1"; }
log_fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); RESULTS+=("${RED}FAIL${NC} $1"); echo -e "  ${RED}FAIL${NC} $1"; }
log_skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); RESULTS+=("${YELLOW}SKIP${NC} $1"); echo -e "  ${YELLOW}SKIP${NC} $1"; }

# Parse arguments
MODE="standard"
while [ $# -gt 0 ]; do
    case "$1" in
        --quick)      MODE="quick" ;;
        --sanitizers) MODE="sanitizers" ;;
        --full)       MODE="full" ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick       Standard unit tests only (fastest)"
            echo "  --sanitizers  Standard + ASan/UBSan tests"
            echo "  --full        Everything: standard, FIPS, ASan, valgrind, static analysis"
            echo "  -h, --help    Show this help"
            echo ""
            echo "Default (no args): standard + FIPS tests"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

echo ""
echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}  QUDO PQC — Comprehensive Test Suite${NC}"
echo -e "${CYAN}  Mode: ${MODE}${NC}"
echo -e "${CYAN}=====================================================${NC}"
echo ""

# ========================================================================== #
# 1. Standard Build + Unit Tests                                              #
# ========================================================================== #

echo -e "${CYAN}[1/7] Standard Build + Unit Tests${NC}"
./build.sh --clean > /dev/null 2>&1 || true
if ./build.sh -t 2>&1 | tee /tmp/qudo_test_standard.log | tail -5; then
    log_pass "Standard unit tests"
else
    log_fail "Standard unit tests"
fi
echo ""

# ========================================================================== #
# 2. FIPS Build + Tests                                                       #
# ========================================================================== #

if [ "$MODE" != "quick" ]; then
    echo -e "${CYAN}[2/7] FIPS 140-3 Build + Tests${NC}"
    if ./build.sh --fips -t 2>&1 | tee /tmp/qudo_test_fips.log | tail -5; then
        log_pass "FIPS 140-3 tests (POST, PCT, integrity, CAST, indicators)"
    else
        log_fail "FIPS 140-3 tests"
    fi
    echo ""
else
    log_skip "FIPS tests (--quick mode)"
fi

# ========================================================================== #
# 3. ASan + UBSan                                                             #
# ========================================================================== #

if [ "$MODE" = "sanitizers" ] || [ "$MODE" = "full" ]; then
    echo -e "${CYAN}[3/7] AddressSanitizer + UBSan Build + Tests${NC}"
    if ./build.sh -s -t 2>&1 | tee /tmp/qudo_test_asan.log | tail -5; then
        log_pass "ASan + UBSan (no memory errors, no undefined behavior)"
    else
        log_fail "ASan + UBSan"
    fi
    echo ""
else
    log_skip "ASan + UBSan (use --sanitizers or --full)"
fi

# ========================================================================== #
# 4. Valgrind Memory Check                                                    #
# ========================================================================== #

if [ "$MODE" = "full" ]; then
    echo -e "${CYAN}[4/7] Valgrind Memory Check${NC}"
    if command -v valgrind &> /dev/null; then
        # Valgrind runs against the standard (non-sanitizer) build in build/.
        if [ ! -d "build" ]; then
            ./build.sh -t 2>&1 > /dev/null
        fi
        VALGRIND_FAIL=0
        for test_bin in build/tests/test_pqc_*; do
            if [ -x "$test_bin" ]; then
                TEST_NAME=$(basename "$test_bin")
                if valgrind --leak-check=full --error-exitcode=1 --quiet "$test_bin" 2>&1 > /dev/null; then
                    :  # pass silently
                else
                    echo "    Valgrind failure: $TEST_NAME"
                    VALGRIND_FAIL=1
                fi
            fi
        done
        if [ $VALGRIND_FAIL -eq 0 ]; then
            log_pass "Valgrind (no leaks, no invalid accesses)"
        else
            log_fail "Valgrind (memory errors detected)"
        fi
    else
        log_skip "Valgrind (not installed)"
    fi
    echo ""
else
    log_skip "Valgrind (use --full)"
fi

# ========================================================================== #
# 5. cppcheck Static Analysis                                                 #
# ========================================================================== #

if [ "$MODE" = "full" ]; then
    echo -e "${CYAN}[5/7] cppcheck Static Analysis${NC}"
    if command -v cppcheck &> /dev/null; then
        if cppcheck --enable=warning,performance,portability \
            --std=c99 \
            --suppress=missingIncludeSystem \
            --suppress=unusedFunction \
            --error-exitcode=1 \
            -I include/ -I src/ -I src/fips/ \
            src/ 2>&1 | tee /tmp/qudo_cppcheck.log | tail -5; then
            log_pass "cppcheck (no warnings)"
        else
            log_fail "cppcheck (warnings found — see /tmp/qudo_cppcheck.log)"
        fi
    else
        log_skip "cppcheck (not installed — sudo apt install cppcheck)"
    fi
    echo ""
else
    log_skip "cppcheck (use --full)"
fi

# ========================================================================== #
# 6. clang-tidy                                                               #
# ========================================================================== #

if [ "$MODE" = "full" ]; then
    echo -e "${CYAN}[6/7] clang-tidy Static Analysis${NC}"
    if command -v clang-tidy &> /dev/null; then
        # Need compile_commands.json
        if [ ! -f "build/compile_commands.json" ]; then
            cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . -B build 2>&1 > /dev/null
        fi
        TIDY_ERRORS=0
        for src_file in src/*.c; do
            if ! clang-tidy -p build "$src_file" 2>&1 | grep -q "error:"; then
                :
            else
                echo "    clang-tidy error in: $src_file"
                TIDY_ERRORS=1
            fi
        done
        if [ $TIDY_ERRORS -eq 0 ]; then
            log_pass "clang-tidy (no errors)"
        else
            log_fail "clang-tidy (errors found)"
        fi
    else
        log_skip "clang-tidy (not installed — sudo apt install clang-tidy)"
    fi
    echo ""
else
    log_skip "clang-tidy (use --full)"
fi

# ========================================================================== #
# 7. clang-format Check                                                       #
# ========================================================================== #

if [ "$MODE" = "full" ]; then
    echo -e "${CYAN}[7/7] clang-format Style Check${NC}"
    if command -v clang-format &> /dev/null; then
        FORMAT_ISSUES=0
        for src_file in src/*.c include/*.h; do
            if [ -f "$src_file" ]; then
                if ! clang-format --dry-run --Werror "$src_file" 2>/dev/null; then
                    FORMAT_ISSUES=1
                fi
            fi
        done
        if [ $FORMAT_ISSUES -eq 0 ]; then
            log_pass "clang-format (code style consistent)"
        else
            log_fail "clang-format (style issues — run: clang-format -i src/*.c include/*.h)"
        fi
    else
        log_skip "clang-format (not installed — sudo apt install clang-format)"
    fi
    echo ""
else
    log_skip "clang-format (use --full)"
fi

# ========================================================================== #
# Summary                                                                      #
# ========================================================================== #

echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}  Test Summary${NC}"
echo -e "${CYAN}=====================================================${NC}"
echo ""
for result in "${RESULTS[@]}"; do
    echo -e "  $result"
done
echo ""
echo -e "  Total: ${GREEN}${PASS_COUNT} passed${NC}, ${RED}${FAIL_COUNT} failed${NC}, ${YELLOW}${SKIP_COUNT} skipped${NC}"
echo ""

if [ $FAIL_COUNT -gt 0 ]; then
    echo -e "  ${RED}SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "  ${GREEN}ALL TESTS PASSED${NC}"
    exit 0
fi
