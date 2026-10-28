#!/bin/bash
# Valgrind Memory Leak Testing Script for QUDO ML-DSA
# Tests all executables for memory leaks using Valgrind

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Valgrind options
# --vex-guest-max-insns caps VEX basic-block size to avoid "VEX temporary storage exhausted" on the large AVX2 chknorm block
VALGRIND_OPTS="--vex-guest-max-insns=40 --leak-check=full --show-leak-kinds=definite,possible --track-origins=yes --error-exitcode=1 --errors-for-leak-kinds=definite,possible"

# Use a unique temp directory to avoid collisions with concurrent runs
VALGRIND_TMPDIR=$(mktemp -d /tmp/qudo_mldsa_valgrind.XXXXXX)
trap 'rm -rf "$VALGRIND_TMPDIR"' EXIT

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       QUDO ML-DSA Valgrind Memory Leak Test Suite          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if valgrind is installed
if ! command -v valgrind &> /dev/null; then
    echo -e "${RED}ERROR: Valgrind is not installed${NC}"
    echo "Install with: sudo apt-get install valgrind"
    exit 1
fi

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run test under Valgrind
run_valgrind_test() {
    local test_name="$1"
    shift
    local test_cmd="$@"
    
    echo -e "${YELLOW}Testing: ${test_name}${NC}"
    echo "Command: $test_cmd"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    if valgrind $VALGRIND_OPTS $test_cmd &> $VALGRIND_TMPDIR/valgrind_$TESTS_RUN.log; then
        # Check for no leaks (either "All heap blocks were freed" or "0 bytes" lost)
        if grep -q "All heap blocks were freed" $VALGRIND_TMPDIR/valgrind_$TESTS_RUN.log || \
           (grep -q "definitely lost: 0 bytes" $VALGRIND_TMPDIR/valgrind_$TESTS_RUN.log && \
            grep -q "possibly lost: 0 bytes" $VALGRIND_TMPDIR/valgrind_$TESTS_RUN.log); then
            echo -e "${GREEN}✅ PASS: No memory leaks detected${NC}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "${RED}❌ FAIL: Memory leaks detected${NC}"
            grep "LEAK SUMMARY" -A 10 $VALGRIND_TMPDIR/valgrind_$TESTS_RUN.log
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        echo -e "${RED}❌ FAIL: Valgrind reported errors${NC}"
        tail -50 $VALGRIND_TMPDIR/valgrind_$TESTS_RUN.log
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo ""
}

# Get test directory
if [ -d "tests" ]; then
    TEST_DIR="tests"
elif [ -f "test_mldsa" ]; then
    TEST_DIR="."
else
    echo -e "${RED}ERROR: Cannot find test directory${NC}"
    exit 1
fi

cd $TEST_DIR

echo "═══════════════════════════════════════════════════════════════"
echo "Basic Tests"
echo "═══════════════════════════════════════════════════════════════"
echo ""

run_valgrind_test "Basic Functionality Test" ./test_mldsa

echo "═══════════════════════════════════════════════════════════════"
echo "Known Answer Tests (KAT)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

run_valgrind_test "KAT Functional Test" ./test_kat

echo "═══════════════════════════════════════════════════════════════"
echo "NIST KAT Tests"
echo "═══════════════════════════════════════════════════════════════"
echo ""

run_valgrind_test "NIST KAT ML-DSA-44" ./test_kat_nist ML-DSA-44 1
run_valgrind_test "NIST KAT ML-DSA-65" ./test_kat_nist ML-DSA-65 1
run_valgrind_test "NIST KAT ML-DSA-87" ./test_kat_nist ML-DSA-87 1

echo "═══════════════════════════════════════════════════════════════"
echo "Summary"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Total tests run: $TESTS_RUN"
echo -e "${GREEN}Tests passed:    $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Tests failed:    $TESTS_FAILED${NC}"
else
    echo -e "${GREEN}Tests failed:    $TESTS_FAILED${NC}"
fi
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           ALL MEMORY LEAK TESTS PASSED ✅                   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║           SOME MEMORY LEAK TESTS FAILED ❌                  ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
