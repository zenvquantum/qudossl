#!/bin/bash
# QUDO_KEM Build Configuration Helper
# This script helps users discover and set build options

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  QUDO_KEM Build Configuration Helper${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
}

print_help() {
    print_header
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo -e "${GREEN}Available Build Options:${NC}"
    echo ""
    echo -e "${YELLOW}Library Type:${NC}"
    echo "  --shared           Build shared library (.so/.dylib/.dll) [DEFAULT]"
    echo "  --static           Build static library (.a/.lib)"
    echo ""
    echo -e "${YELLOW}Build Components:${NC}"
    echo "  --with-examples    Build example programs [DEFAULT]"
    echo "  --no-examples      Skip building examples"
    echo "  --with-tests       Build test programs [DEFAULT]"
    echo "  --no-tests         Skip building tests"
    echo "  --lib-only         Build only library (no tests/examples)"
    echo ""
    echo -e "${YELLOW}Platform Optimizations:${NC}"
    echo "  --with-avx2        Enable AVX2 optimizations (x86_64) [DEFAULT]"
    echo "  --no-avx2          Disable AVX2 (use generic C code)"
    echo "  --with-neon        Enable NEON optimizations (ARM64) [DEFAULT]"
    echo "  --no-neon          Disable NEON optimizations"
    echo "  --with-rvv         Enable RISC-V Vector extensions [DEFAULT]"
    echo "  --no-rvv           Disable RISC-V Vector extensions"
    echo ""
    echo -e "${YELLOW}Special Builds:${NC}"
    echo "  --embedded         Build for embedded systems (minimal stdlib)"
    echo "  --no-openssl       Don't use OpenSSL (use built-in crypto)"
    echo "  --strict           Enable strict compiler warnings"
    echo ""
    echo -e "${YELLOW}Build Type:${NC}"
    echo "  --debug            Build with debug symbols"
    echo "  --release          Build optimized release [DEFAULT]"
    echo ""
    echo -e "${YELLOW}Advanced:${NC}"
    echo "  --list             List all available CMake options"
    echo "  --clean            Remove build directory before configuring"
    echo "  --help, -h         Show this help message"
    echo ""
    echo -e "${GREEN}Examples:${NC}"
    echo "  $0 --shared --release              # Default build"
    echo "  $0 --static --no-tests             # Static library, no tests"
    echo "  $0 --embedded --no-openssl         # Embedded build"
    echo "  $0 --no-avx2                       # Generic x86_64 (no AVX2)"
    echo "  $0 --clean --static --release      # Clean rebuild as static"
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
}

list_options() {
    print_header
    echo ""
    if [ -d "$PROJECT_ROOT/build" ]; then
        echo -e "${GREEN}Current CMake Configuration:${NC}"
        echo ""
        cmake -LA "$PROJECT_ROOT/build" 2>/dev/null | grep -E "^(BUILD_|ENABLE_|MLKEM_|CMAKE_BUILD_TYPE)" || true
    else
        echo -e "${YELLOW}No build directory found. Run configuration first.${NC}"
        echo ""
        echo -e "${GREEN}Available Options (defaults):${NC}"
        echo ""
        echo "BUILD_SHARED_LIBS:BOOL=ON"
        echo "BUILD_EXAMPLES:BOOL=ON"
        echo "BUILD_TESTS:BOOL=ON"
        echo "ENABLE_AVX2:BOOL=ON"
        echo "ENABLE_NEON:BOOL=ON"
        echo "ENABLE_RVV:BOOL=ON"
        echo "MLKEM_BUILD_ONLY_LIB:BOOL=OFF"
        echo "MLKEM_EMBEDDED_BUILD:BOOL=OFF"
        echo "MLKEM_USE_OPENSSL:BOOL=ON"
        echo "MLKEM_STRICT_WARNINGS:BOOL=OFF"
        echo "CMAKE_BUILD_TYPE:STRING=Release"
    fi
    echo ""
}

# Parse command line arguments
CMAKE_ARGS=""
BUILD_TYPE="Release"
CLEAN_BUILD=0

if [ $# -eq 0 ]; then
    print_help
    exit 0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --help|-h)
            print_help
            exit 0
            ;;
        --list)
            list_options
            exit 0
            ;;
        --shared)
            CMAKE_ARGS="$CMAKE_ARGS -DBUILD_SHARED_LIBS=ON"
            ;;
        --static)
            CMAKE_ARGS="$CMAKE_ARGS -DBUILD_SHARED_LIBS=OFF"
            ;;
        --with-examples)
            CMAKE_ARGS="$CMAKE_ARGS -DBUILD_EXAMPLES=ON"
            ;;
        --no-examples)
            CMAKE_ARGS="$CMAKE_ARGS -DBUILD_EXAMPLES=OFF"
            ;;
        --with-tests)
            CMAKE_ARGS="$CMAKE_ARGS -DBUILD_TESTS=ON"
            ;;
        --no-tests)
            CMAKE_ARGS="$CMAKE_ARGS -DBUILD_TESTS=OFF"
            ;;
        --lib-only)
            CMAKE_ARGS="$CMAKE_ARGS -DMLKEM_BUILD_ONLY_LIB=ON"
            ;;
        --with-avx2)
            CMAKE_ARGS="$CMAKE_ARGS -DENABLE_AVX2=ON"
            ;;
        --no-avx2)
            CMAKE_ARGS="$CMAKE_ARGS -DENABLE_AVX2=OFF"
            ;;
        --with-neon)
            CMAKE_ARGS="$CMAKE_ARGS -DENABLE_NEON=ON"
            ;;
        --no-neon)
            CMAKE_ARGS="$CMAKE_ARGS -DENABLE_NEON=OFF"
            ;;
        --with-rvv)
            CMAKE_ARGS="$CMAKE_ARGS -DENABLE_RVV=ON"
            ;;
        --no-rvv)
            CMAKE_ARGS="$CMAKE_ARGS -DENABLE_RVV=OFF"
            ;;
        --embedded)
            CMAKE_ARGS="$CMAKE_ARGS -DMLKEM_EMBEDDED_BUILD=ON"
            ;;
        --no-openssl)
            CMAKE_ARGS="$CMAKE_ARGS -DMLKEM_USE_OPENSSL=OFF"
            ;;
        --strict)
            CMAKE_ARGS="$CMAKE_ARGS -DMLKEM_STRICT_WARNINGS=ON"
            ;;
        --debug)
            BUILD_TYPE="Debug"
            ;;
        --release)
            BUILD_TYPE="Release"
            ;;
        --clean)
            CLEAN_BUILD=1
            ;;
        *)
            echo -e "${YELLOW}Warning: Unknown option '$1'${NC}"
            echo "Run '$0 --help' for usage information"
            exit 1
            ;;
    esac
    shift
done

# Clean build if requested
if [ $CLEAN_BUILD -eq 1 ]; then
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "$PROJECT_ROOT/build"
fi

# Create build directory
mkdir -p "$PROJECT_ROOT/build"
cd "$PROJECT_ROOT/build"

# Run CMake configuration
print_header
echo ""
echo -e "${GREEN}Configuring QUDO_KEM with:${NC}"
echo -e "  Build Type: ${YELLOW}$BUILD_TYPE${NC}"
echo -e "  Options: ${YELLOW}$CMAKE_ARGS${NC}"
echo ""

cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" $CMAKE_ARGS ..

echo ""
echo -e "${GREEN}✓ Configuration complete!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  cd build"
echo "  make -j\$(nproc)"
echo "  make test          # (if tests enabled)"
echo "  sudo make install"
echo ""
