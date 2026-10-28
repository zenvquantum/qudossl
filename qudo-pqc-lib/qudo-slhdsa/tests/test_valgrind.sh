#!/bin/bash
# Valgrind Memory Leak Testing Script for QUDO SLH-DSA
# Tests all executables for memory leaks using Valgrind

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --vex-guest-max-insns caps VEX basic-block size to avoid "VEX temporary storage exhausted" on large AVX2 basic blocks
VALGRIND_OPTS="--vex-guest-max-insns=40 --leak-check=full --show-leak-kinds=definite,possible --track-origins=yes --error-exitcode=1 --errors-for-leak-kinds=definite,possible"

echo -e "${BLUE}QUDO SLH-DSA Valgrind Memory Leak Test Suite${NC}"
echo ""

if ! command -v valgrind &> /dev/null; then
    echo -e "${RED}ERROR: Valgrind is not installed${NC}"
    echo "Install with: sudo apt-get install valgrind"
    exit 1
fi

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

run_valgrind_test() {
    local test_name="$1"
    shift
    local test_cmd="$@"

    echo -e "${YELLOW}Testing: ${test_name}${NC}"
    echo "Command: $test_cmd"

    TESTS_RUN=$((TESTS_RUN + 1))

    if valgrind $VALGRIND_OPTS $test_cmd &> /tmp/valgrind_slhdsa_$TESTS_RUN.log; then
        if grep -q "All heap blocks were freed" /tmp/valgrind_slhdsa_$TESTS_RUN.log || \
           (grep -q "definitely lost: 0 bytes" /tmp/valgrind_slhdsa_$TESTS_RUN.log && \
            grep -q "possibly lost: 0 bytes" /tmp/valgrind_slhdsa_$TESTS_RUN.log); then
            echo -e "${GREEN}PASS: No memory leaks detected${NC}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "${RED}FAIL: Memory leaks detected${NC}"
            grep "LEAK SUMMARY" -A 10 /tmp/valgrind_slhdsa_$TESTS_RUN.log
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        echo -e "${RED}FAIL: Valgrind reported errors${NC}"
        tail -50 /tmp/valgrind_slhdsa_$TESTS_RUN.log
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo ""
}

# Find test directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(dirname "$SCRIPT_DIR")/build/tests"

if [ -d "$BUILD_DIR" ]; then
    cd "$BUILD_DIR"
elif [ -f "test_slhdsa" ]; then
    : # already in correct dir
else
    echo -e "${RED}ERROR: Cannot find test executables${NC}"
    exit 1
fi

echo "-----------------------------------------------------------"
echo "Basic Tests"
echo "-----------------------------------------------------------"
echo ""

run_valgrind_test "Basic Functionality Test" ./test_slhdsa
run_valgrind_test "DER/PEM Serialization Test" ./test_der_pem

echo "-----------------------------------------------------------"
echo "Summary"
echo "-----------------------------------------------------------"
echo ""
echo "Total tests run: $TESTS_RUN"
echo -e "${GREEN}Tests passed:    $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Tests failed:    $TESTS_FAILED${NC}"
else
    echo -e "${GREEN}Tests failed:    $TESTS_FAILED${NC}"
fi

rm -f /tmp/valgrind_slhdsa_*.log

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}ALL MEMORY LEAK TESTS PASSED${NC}"
    exit 0
else
    echo -e "\n${RED}SOME MEMORY LEAK TESTS FAILED${NC}"
    exit 1
fi
